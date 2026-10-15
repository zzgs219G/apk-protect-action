/*
 * sig_guard2.c — 签名校验第二独立线(2026-10)
 *
 * 【为什么存在】
 *   第一线 sig_check.c 的所有失败路径最终汇聚到单个 delayed_kill()。
 *   实测(2026-10):把该函数入口 4 字节改成 ret,整条杀链即失效,重签名包
 *   可正常运行。单点 = 改一处全废。
 *   本模块提供【完全独立】的第二线:独立取指纹来源、独立派生公式、独立
 *   标准答案(sig_guard2.h)、独立处置路径。攻击者改掉第一线,本线照跑。
 *
 * 【与 sig_check.c 的关系】
 *   - 零代码共享:不复用其函数、不 include sig_hash.h
 *     (共享标准答案 = 单点:改一处两线同废)
 *   - 同源指纹:两份答案都由 make-sig-hash.sh 从同一 APK 生成
 *   - 各自挂 constructor,互不感知
 *
 * 【派生公式(与第一线不同,与 make-sig-hash.sh 生成侧逐字节一致)】
 *   t2       = SHA256(b"G2" || fp)                    轮1:域分隔
 *   stored[i]= t2[i] ^ salt2[(i*7)%16] ^ ((i*0x5B+0x3D)&0xFF)
 *
 * 【处置:两条路径,互不依赖】
 *   路径 A(明杀):syscall(__NR_tgkill, SIGKILL) —— SIGKILL 不可捕获
 *   路径 B(反制):校验失败后起 watchdog;若 N 秒后进程仍活着,说明杀路径
 *                 被 patch 了 —— 再走一条完全不同的路径(exit_group)
 *
 * 【误报兜底】任一步 I/O/解析异常 → 视为"未检出",绝不误伤。
 *   全零标准答案 = 调试模式(流水线未注入) → 跳过。
 *
 * 【性能】构造期一次解析 + SHA-256;watchdog 线程睡眠不耗 CPU。
 *   正常运行路径零开销。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <dlfcn.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "sig_guard2.h"

/* ── 日志:纯 logcat,零文件 I/O(与第一线解耦,也不受其哨兵开关影响) ── */
#ifdef __ANDROID__
#include <android/log.h>
#define G2LOG(...) __android_log_print(ANDROID_LOG_INFO, "nc", __VA_ARGS__)
#else
#define G2LOG(...) do { } while (0)
#endif

/* ═══════════════════════ SHA-256(公共域精简实现,自包含) ═══════════════════════ */
typedef struct {
    unsigned int state[8];
    unsigned long long bitlen;
    unsigned char data[64];
    unsigned int datalen;
} g2_sha_ctx;

static const unsigned int g2_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
#define G2_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define G2_CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define G2_MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define G2_EP0(x) (G2_ROTR(x,2) ^ G2_ROTR(x,13) ^ G2_ROTR(x,22))
#define G2_EP1(x) (G2_ROTR(x,6) ^ G2_ROTR(x,11) ^ G2_ROTR(x,25))
#define G2_SG0(x) (G2_ROTR(x,7) ^ G2_ROTR(x,18) ^ ((x) >> 3))
#define G2_SG1(x) (G2_ROTR(x,17) ^ G2_ROTR(x,19) ^ ((x) >> 10))

static void g2_transform(g2_sha_ctx *c, const unsigned char d[64]) {
    unsigned int m[64], a,b,cc,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        m[i] = ((unsigned int)d[i*4] << 24) | ((unsigned int)d[i*4+1] << 16) |
               ((unsigned int)d[i*4+2] << 8) | (unsigned int)d[i*4+3];
    for (i = 16; i < 64; i++)
        m[i] = G2_SG1(m[i-2]) + m[i-7] + G2_SG0(m[i-15]) + m[i-16];
    a=c->state[0]; b=c->state[1]; cc=c->state[2]; e=c->state[3];
    f=c->state[4]; g=c->state[5]; h=c->state[6]; /* state[7] 暂存 */
    {
        unsigned int dd = c->state[3];
        unsigned int ee = c->state[4], ff = c->state[5], gg = c->state[6], hh = c->state[7];
        unsigned int aa = c->state[0], bb = c->state[1], ccc = c->state[2];
        for (i = 0; i < 64; i++) {
            t1 = hh + G2_EP1(ee) + G2_CH(ee,ff,gg) + g2_k[i] + m[i];
            t2 = G2_EP0(aa) + G2_MAJ(aa,bb,ccc);
            hh=gg; gg=ff; ff=ee; ee=dd+t1; dd=ccc; ccc=bb; bb=aa; aa=t1+t2;
        }
        c->state[0]+=aa; c->state[1]+=bb; c->state[2]+=ccc; c->state[3]+=dd;
        c->state[4]+=ee; c->state[5]+=ff; c->state[6]+=gg; c->state[7]+=hh;
    }
    (void)a;(void)b;(void)cc;(void)e;(void)f;(void)g;(void)h;
}

static void g2_sha_init(g2_sha_ctx *c) {
    c->datalen = 0; c->bitlen = 0;
    c->state[0]=0x6a09e667; c->state[1]=0xbb67ae85;
    c->state[2]=0x3c6ef372; c->state[3]=0xa54ff53a;
    c->state[4]=0x510e527f; c->state[5]=0x9b05688c;
    c->state[6]=0x1f83d9ab; c->state[7]=0x5be0cd19;
}

static void g2_sha_update(g2_sha_ctx *c, const unsigned char *d, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        c->data[c->datalen++] = d[i];
        if (c->datalen == 64) { g2_transform(c, c->data); c->bitlen += 512; c->datalen = 0; }
    }
}

static void g2_sha_final(g2_sha_ctx *c, unsigned char out[32]) {
    unsigned int i = c->datalen;
    int j;
    c->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) c->data[i++] = 0;
        g2_transform(c, c->data);
        i = 0;
    }
    while (i < 56) c->data[i++] = 0;
    c->bitlen += (unsigned long long)c->datalen * 8;
    for (j = 7; j >= 0; j--) c->data[56 + (7 - j)] = (unsigned char)(c->bitlen >> (j * 8));
    g2_transform(c, c->data);
    for (i = 0; i < 8; i++) {
        out[i*4]   = (unsigned char)(c->state[i] >> 24);
        out[i*4+1] = (unsigned char)(c->state[i] >> 16);
        out[i*4+2] = (unsigned char)(c->state[i] >> 8);
        out[i*4+3] = (unsigned char)(c->state[i]);
    }
}

/* ═══════════════════════ 基础 I/O 工具 ═══════════════════════ */
static int g2_read_at(int fd, void *buf, size_t len, off_t off) {
    ssize_t n;
    while (len > 0) {
        n = pread(fd, buf, len, off);
        if (n <= 0) return -1;
        buf = (char *)buf + n; len -= (size_t)n; off += n;
    }
    return 0;
}

static unsigned int g2_rd32le(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned long long g2_rd64le(const unsigned char *p) {
    return (unsigned long long)g2_rd32le(p) | ((unsigned long long)g2_rd32le(p + 4) << 32);
}

/* ═══════════════════════ APK 定位(精简版) ═══════════════════════
 * 与第一线的 179 行实现相比,本版只保留两条足够可靠的路径:
 *   ① /proc/self/maps 里出现 "base.apk" 的行 → 截尾部空格后的纯路径
 *   ② 由本 so 自身路径反推安装目录(/proc/<pid>/root 前缀,绕 SELinux)
 * 取舍理由:兜底扫 /data/app 在 Android 11+ 必失败(SELinux),留着只是噪声。
 * 任一路径 access(R_OK) 通过即采用;全失败 → 未检出(不误伤)。 */
static int g2_find_apk(char *out, size_t outlen) {
    FILE *fp;
    char line[1024];

#ifdef SIGGUARD2_HOST_TEST
    {
        const char *t = getenv("SIGGUARD2_TEST_APK");
        if (t && *t) { snprintf(out, outlen, "%s", t); return 0; }
    }
#endif

    /* 路径 ①:maps 里的 base.apk */
    fp = fopen("/proc/self/maps", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            char *p = strstr(line, "base.apk");
            if (p) {
                char *sp;
                p += 8;
                *p = '\0';
                sp = strrchr(line, ' ');
                if (sp) {
                    snprintf(out, outlen, "%s", sp + 1);
                    if (access(out, R_OK) == 0) { fclose(fp); return 0; }
                }
            }
        }
        fclose(fp);
    }

    /* 路径 ②:由本 so 路径反推(extractNativeLibs=true 场景) */
    {
        Dl_info info;
        if (dladdr((const void *)&g2_find_apk, &info) != 0 && info.dli_fname) {
            const char *p = strstr(info.dli_fname, "/lib/");
            if (p) {
                size_t n = (size_t)(p - info.dli_fname);
                if (n + 64 < outlen) {
                    int i;
                    memcpy(out, info.dli_fname, n);
                    /* /proc/<pid>/root 前缀,获得 SELinux 可读的真实路径 */
                    snprintf(out + n, outlen - n, "/base.apk");
                    if (out[0] == '/') {
                        char real[1024];
                        snprintf(real, sizeof(real), "/proc/%d/root%s", (int)getpid(), out);
                        if (access(real, R_OK) == 0) {
                            snprintf(out, outlen, "%s", real);
                            return 0;
                        }
                    }
                    /* 直接试原路径 */
                    if (access(out, R_OK) == 0) return 0;
                    /* 逐级回退找根目录 */
                    for (i = (int)n - 1; i > 0; i--) {
                        if (out[i] == '/') {
                            char cand[1024];
                            out[i] = '\0';
                            snprintf(cand, sizeof(cand), "%s/base.apk", out);
                            if (access(cand, R_OK) == 0) {
                                snprintf(out, outlen, "%s", cand);
                                return 0;
                            }
                            out[i] = '/';
                        }
                    }
                }
            }
        }
    }
    return -1;
}

/* ═══════════════════════ APK Signing Block 解析 ═══════════════════════
 * 与第一线同布局(AOSP v2/v3),但独立实现。找出证书 DER。 */
#define G2_BLOCK_MAGIC "APK Sig Block 42"
#define G2_V2_ID 0x7109871aULL
#define G2_V3_ID 0xf05368c0ULL

static int g2_extract_cert(int fd, unsigned char **out_der, size_t *out_len) {
    off_t fsize, pos, search_start;
    unsigned char eocd[22], magic[16], sz8[8], header[12];
    unsigned long long cd_off, block_size, pair_len, block_id;
    off_t block_start, pair_pos;
    unsigned char *value = NULL;
    int found = -1;

    fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 22) return -1;

    search_start = (fsize > 65557) ? (fsize - 65557) : 0;
    for (pos = fsize - 22; pos >= search_start; pos--) {
        if (g2_read_at(fd, eocd, 22, pos) != 0) return -1;
        if (eocd[0]==0x50 && eocd[1]==0x4b && eocd[2]==0x05 && eocd[3]==0x06) break;
    }
    if (pos < search_start) return -1;

    cd_off = g2_rd32le(eocd + 16);
    if (cd_off == 0 || cd_off == 0xffffffffULL) return -1;
    if ((off_t)cd_off < 32) return -1;
    if (g2_read_at(fd, magic, 16, (off_t)cd_off - 16) != 0) return -1;
    if (memcmp(magic, G2_BLOCK_MAGIC, 16) != 0) return -1;
    if (g2_read_at(fd, sz8, 8, (off_t)cd_off - 24) != 0) return -1;
    block_size = g2_rd64le(sz8);
    if ((off_t)(block_size + 8) > cd_off) return -1;
    block_start = (off_t)cd_off - 8 - (off_t)block_size;

    pair_pos = block_start + 8;
    while (pair_pos + 12 <= (off_t)cd_off - 24) {
        if (g2_read_at(fd, header, 12, pair_pos) != 0) break;
        pair_len = g2_rd64le(header);
        block_id = (unsigned long long)g2_rd32le(header + 8);
        if (pair_len < 4 || pair_len > block_size) break;
        if (block_id == G2_V2_ID || block_id == G2_V3_ID) {
            unsigned long long vlen = pair_len - 4;
            value = (unsigned char *)malloc(vlen);
            if (!value) return -1;
            if (g2_read_at(fd, value, vlen, pair_pos + 12) != 0) { free(value); return -1; }
            found = (int)vlen;
            break;
        }
        pair_pos += 8 + (off_t)pair_len;
    }
    if (found < 0) return -1;

    {
        const unsigned char *p = value, *end = value + found;
        unsigned int signer_len, sd_len, digests_len, certs_len, cert_len;
        const unsigned char *signer, *sd, *certs;

        if (p + 4 > end) goto fail;
        p += 4;
        if (p + 4 > end) goto fail;
        signer_len = g2_rd32le(p); p += 4;
        if (p + signer_len > end) goto fail;
        signer = p;

        if (signer + 4 > end) goto fail;
        sd_len = g2_rd32le(signer); signer += 4;
        sd = signer;
        if (sd + sd_len > end) goto fail;

        if (sd + 4 > sd + sd_len) goto fail;
        digests_len = g2_rd32le(sd); sd += 4;
        if (sd + digests_len + 4 > sd + sd_len) goto fail;
        sd += digests_len;
        certs_len = g2_rd32le(sd); sd += 4;
        certs = sd;

        if (certs + 4 > end) goto fail;
        cert_len = g2_rd32le(certs); certs += 4;
        if (cert_len == 0 || certs + cert_len > end) goto fail;

        *out_der = (unsigned char *)malloc(cert_len);
        if (!*out_der) goto fail;
        memcpy(*out_der, certs, cert_len);
        *out_len = cert_len;
        free(value);
        return 0;
    }
fail:
    free(value);
    return -1;
}

/* ═══════════════════════ 处置 ═══════════════════════ */

/* 路径 A:SIGKILL 直投(SIGKILL 不可捕获、不可忽略) */
static void g2_kill_hard(void) {
#ifdef __NR_tgkill
    syscall(__NR_tgkill, (long)getpid(), (long)syscall(__NR_gettid), SIGKILL);
#endif
    /* 兜底:raise(SIGKILL) 与 _exit */
    raise(SIGKILL);
    _exit(127);
}

/* 路径 B:反制"杀路径被 patch"
 * 校验失败 → 记录时间戳 → 起 watchdog
 * watchdog 每 3 秒检查:若"应该已死"却还活着 → 换另一条路径(exit_group)
 * 意义:攻击者 patch 掉 g2_kill_hard 后,进程仍会死于此路径。 */
static volatile long g2_fail_ts = 0;

static void *g2_watchdog(void *arg) {
    (void)arg;
    for (;;) {
        sleep(3);
        if (g2_fail_ts != 0 && (time(NULL) - g2_fail_ts) >= 12) {
            /* 校验已失败 12 秒,进程还活着 → 前一条杀路径必已被改 */
#ifdef __NR_exit_group
            syscall(__NR_exit_group, 3);
#endif
            _exit(3);
        }
    }
    return NULL;
}

static void g2_fail(void) {
    pthread_t t;
    pthread_attr_t attr;
    /* 先记录失败时刻,watchdog 据此判定"本该已死" */
    g2_fail_ts = (long)time(NULL);

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, g2_watchdog, NULL) != 0) {
        pthread_attr_destroy(&attr);
        g2_kill_hard();
        return;
    }
    pthread_attr_destroy(&attr);

    /* 路径 A 立即执行 */
    g2_kill_hard();
}

/* ═══════════════════════ 校验主逻辑 ═══════════════════════ */

/* 独立派生(与 make-sig-hash.sh 生成侧逐字节一致):
 *   t2 = SHA256(b"G2" || fp)
 *   expected[i] = t2[i] ^ salt2[(i*7)%16] ^ ((i*0x5B+0x3D)&0xFF)  */
static void g2_derive(const unsigned char fp[32], unsigned char out[32]) {
    g2_sha_ctx c;
    unsigned char t2[32];
    int i;
    g2_sha_init(&c);
    g2_sha_update(&c, (const unsigned char *)"G2", 2);
    g2_sha_update(&c, fp, 32);
    g2_sha_final(&c, t2);
    for (i = 0; i < 32; i++) {
        out[i] = (unsigned char)(t2[i] ^ SG2_SALT[(i * 7) % 16]
                                 ^ (unsigned char)((i * 0x5B + 0x3D) & 0xFF));
    }
}

static void g2_verify(void) {
    char apk[1024];
    int fd;
    unsigned char *der = NULL;
    size_t der_len = 0;
    unsigned char fp[32], expected[32];
    g2_sha_ctx c;
    int i, mismatch = 0, slot_configured = 0;

    /* 调试模式:标准答案全零(流水线未注入) → 跳过,不误伤 */
    for (i = 0; i < SG2_HASH_LEN; i++) {
        if (SG2_STORED[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured) return;

    if (g2_find_apk(apk, sizeof(apk)) != 0) return;   /* 定位失败 → 未检出 */
    fd = open(apk, O_RDONLY);
    if (fd < 0) return;
    if (g2_extract_cert(fd, &der, &der_len) != 0) { close(fd); return; }
    close(fd);

    g2_sha_init(&c);
    g2_sha_update(&c, der, der_len);
    g2_sha_final(&c, fp);
    free(der);

    g2_derive(fp, expected);
    for (i = 0; i < 32; i++) mismatch |= expected[i] ^ SG2_STORED[i];

    if (mismatch != 0) g2_fail();
}

/* so 加载即检(与第一线的 constructor 并存,顺序无关、互不依赖) */
__attribute__((constructor))
static void g2_entry(void) {
    g2_verify();
}
