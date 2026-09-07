/*
 * sig_check.c — 纯 Native 签名校验（第四版方案核心）
 *
 * 设计要点：
 *   1. 入口使用 __attribute__((constructor))，在 so 被 dlopen 时、
 *      甚至早于 JNI_OnLoad 执行，早于一切 Java 业务代码与入口重定向。
 *      （dcc 工具链的 libnc.so 已占用 JNI_OnLoad，故不与其冲突）
 *   2. 完全不经过 Java 层 API（不调 PackageManager / FileInputStream），
 *      直接 open/read /data/app/.../base.apk，手工解析 APK Signing Block
 *      (v2: 0x7109871a / v3: 0xf05368c0)，提取证书 DER 后计算 SHA-256，
 *      与编译期注入的期望指纹（sig_hash.h 中的 SIG_HASH）比对。
 *   3. 校验失败不直接 exit(0)：起分离线程延时随机 abort，
 *      让"hook exit/abort 即绕过"的通用脚本失效（二期继续增强为隐蔽破坏）。
 *   4. SIG_HASH 全零 = 调试模式（流水线未注入指纹时跳过校验，便于本地测试）。
 *
 * 编译：由流水线把本文件与 dcc 生成的 C 代码一起放进 ndk 工程编译，
 *      最终产物与业务逻辑同在 libnc.so，防剥离。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <android/log.h>

#include "sig_hash.h"

#define LOG_TAG "nc"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* APK Signing Block magic：'APK Sig Block 42' */
static const unsigned char SIG_BLOCK_MAGIC[16] = {
    'A','P','K',' ','S','i','g',' ','B','l','o','c','k',' ','4','2'
};
#define V2_BLOCK_ID  0x7109871au
#define V3_BLOCK_ID  0xf05368c0au

/* ─────────────────────────── SHA-256（精简公共域实现） ─────────────────────────── */

typedef struct {
    unsigned int state[8];
    unsigned long long bitlen;
    unsigned char data[64];
    unsigned int datalen;
} sha256_ctx;

static const unsigned int k256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x)  (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define EP1(x)  (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define SIG0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx *ctx, const unsigned char data[64]) {
    unsigned int m[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        m[i] = ((unsigned int)data[i*4] << 24) | ((unsigned int)data[i*4+1] << 16) |
               ((unsigned int)data[i*4+2] << 8) | (unsigned int)data[i*4+3];
    for (i = 16; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + k256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

static void sha256_update(sha256_ctx *ctx, const unsigned char *data, size_t len) {
    unsigned int i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

/* 单入口：对 data 计算 SHA-256，输出 32 字节 hash。
   实现说明：sha256_update 只消化完整 64 字节块；残留字节 + padding + 8 字节
   长度在此手工组块后直接 transform，不经 update（避免计数干扰）。 */
static void sha256(const unsigned char *data, size_t len, unsigned char hash[32]) {
    sha256_ctx ctx;
    unsigned long long bits = (unsigned long long)len * 8;
    unsigned char tail[128];
    unsigned int padlen;
    int j;

    sha256_init(&ctx);
    sha256_update(&ctx, data, len);

    /* 组尾块：残留数据 + 0x80 + 零填充 + 64 位总长度（大端） */
    padlen = (ctx.datalen < 56) ? (56 - ctx.datalen) : (120 - ctx.datalen);
    memset(tail, 0, sizeof(tail));
    memcpy(tail, ctx.data, ctx.datalen);
    tail[ctx.datalen] = 0x80;
    for (j = 0; j < 8; j++)
        tail[ctx.datalen + padlen + j] = (unsigned char)(bits >> (56 - j*8));

    if (ctx.datalen + padlen + 8 == 64) {
        sha256_transform(&ctx, tail);
    } else {
        /* 跨两块：先消化补满的第一个块，再消化长度所在的第二块 */
        sha256_transform(&ctx, tail);
        sha256_transform(&ctx, tail + 64);
    }

    for (j = 0; j < 4; j++) {
        hash[j]    = (unsigned char)(ctx.state[0] >> (24 - j*8));
        hash[4+j]  = (unsigned char)(ctx.state[1] >> (24 - j*8));
        hash[8+j]  = (unsigned char)(ctx.state[2] >> (24 - j*8));
        hash[12+j] = (unsigned char)(ctx.state[3] >> (24 - j*8));
        hash[16+j] = (unsigned char)(ctx.state[4] >> (24 - j*8));
        hash[20+j] = (unsigned char)(ctx.state[5] >> (24 - j*8));
        hash[24+j] = (unsigned char)(ctx.state[6] >> (24 - j*8));
        hash[28+j] = (unsigned char)(ctx.state[7] >> (24 - j*8));
    }
}
/* ─────────────────────────── 文件读取工具 ─────────────────────────── */

static int read_full(int fd, void *buf, size_t len) {
    size_t got = 0;
    while (got < len) {
        ssize_t n = read(fd, (char*)buf + got, len - got);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) return -1; /* EOF，长度不符 */
        got += (size_t)n;
    }
    return 0;
}

static int read_at(int fd, void *buf, size_t len, off_t off) {
    if (lseek(fd, off, SEEK_SET) == (off_t)-1) return -1;
    return read_full(fd, buf, len);
}

static unsigned int rd32le(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned long long rd64le(const unsigned char *p) {
    return (unsigned long long)rd32le(p) | ((unsigned long long)rd32le(p+4) << 32);
}

/* ─────────────────────────── 定位 base.apk ─────────────────────────── */

/* 从 /proc/self/cmdline 读取当前进程包名 */
static int get_pkg_name(char *out, size_t outlen) {
    int fd = open("/proc/self/cmdline", O_RDONLY);
    ssize_t n;
    if (fd < 0) return -1;
    n = read(fd, out, outlen - 1);
    close(fd);
    if (n <= 0) return -1;
    out[n] = '\0'; /* cmdline 以 \0 分隔 argv，第一个即包名 */
    return 0;
}

/*
 * 定位当前 APK：
 *   1. 先扫 /proc/self/maps，若 extractNativeLibs=false，so 直接映射自
 *      base.apk（行内含 "base.apk"），截取路径即可；
 *   2. 否则按包名遍历 /data/app/ 的两层目录找 <pkg>* /base.apk。
 */
static int find_apk_path(char *out, size_t outlen) {
    FILE *fp;
    char line[512];
    char *p;

#ifdef SIGCHECK_HOST_TEST
    /* 宿主测试：直接用环境变量指定的路径 */
    {
        const char *t = getenv("SIGCHECK_TEST_APK");
        if (t && *t) {
            snprintf(out, outlen, "%s", t);
            LOGI("apk path from test env: %s", out);
            return 0;
        }
    }
#endif

    fp = fopen("/proc/self/maps", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            p = strstr(line, "base.apk");
            if (p && strstr(line, ".so")) {
                *p = '\0';
                snprintf(out, outlen, "%s", line);
                fclose(fp);
                LOGI("apk path from maps: %s", out);
                return 0;
            }
        }
        fclose(fp);
    }

    {
        char pkg[256];
        DIR *d1, *d2;
        struct dirent *e1, *e2;
        if (get_pkg_name(pkg, sizeof(pkg)) != 0) return -1;

        d1 = opendir("/data/app");
        if (!d1) return -1;
        while ((e1 = readdir(d1))) {
            char p1[512];
            if (e1->d_name[0] == '.') continue;
            snprintf(p1, sizeof(p1), "/data/app/%s", e1->d_name);
            d2 = opendir(p1);
            if (!d2) continue;
            while ((e2 = readdir(d2))) {
                char candidate[640];
                if (strncmp(e2->d_name, pkg, strlen(pkg)) != 0) continue;
                snprintf(candidate, sizeof(candidate), "%s/%s/base.apk", p1, e2->d_name);
                if (access(candidate, R_OK) == 0) {
                    snprintf(out, outlen, "%s", candidate);
                    closedir(d2);
                    closedir(d1);
                    LOGI("apk path from data/app: %s", out);
                    return 0;
                }
            }
            closedir(d2);
        }
        closedir(d1);
    }
    return -1;
}

/* ─────────────────────────── APK Signing Block 解析 ─────────────────────────── */

/*
 * 从 APK 文件中提取 v2/v3 签名块里第一张证书的 DER 字节。
 * 成功返回 malloc 的缓冲区（调用者 free）与长度。
 */
static int extract_cert_der(int fd, unsigned char **out_der, size_t *out_len) {
    off_t fsize;
    unsigned char eocd[22];
    off_t search_start, pos;
    unsigned long long cd_off;
    unsigned char magic[16];
    unsigned long long block_size;
    off_t block_start, pair_pos;
    unsigned char header[12];
    unsigned long long block_id = 0;
    unsigned char *value = NULL;
    int found = -1;

    fsize = lseek(fd, 0, SEEK_END);
    if (fsize < 22) return -1;

    /* 1. 从尾部 64KB+22 范围内找 EOCD（PK\x05\x06） */
    search_start = (fsize > 65557) ? (fsize - 65557) : 0;
    for (pos = fsize - 22; pos >= search_start; pos--) {
        if (read_at(fd, eocd, 22, pos) != 0) return -1;
        if (eocd[0] == 0x50 && eocd[1] == 0x4b && eocd[2] == 0x05 && eocd[3] == 0x06) break;
    }
    if (pos < search_start) return -1;

    cd_off = rd32le(eocd + 16);
    if (cd_off == 0 || cd_off == 0xffffffffULL) return -1; /* 空/zip64 不支持 */

    /* 2. CD 前应紧邻 Signing Block 尾部：magic 在 cd_off-16。
     * AOSP 布局: [size-payload(8)][pairs...][size-total(8)][magic(16)]
     * 尾部 size-total = pairs + 尾部 24 字节，整块 = size-total + 头部 8 字节，
     * 块起点 = cd_off - size_total - 8。（实测部分签名工具头尾两字段写相同值，
     * 故不校验头部 size-payload，定位以尾部字段为准） */
    if ((off_t)cd_off < 32) return -1;
    if (read_at(fd, magic, 16, (off_t)cd_off - 16) != 0) return -1;
    if (memcmp(magic, SIG_BLOCK_MAGIC, 16) != 0) return -1; /* 无 v2/v3 签名 */

    {
        unsigned char sz8[8];
        if (read_at(fd, sz8, 8, (off_t)cd_off - 24) != 0) return -1;
        block_size = rd64le(sz8);
    }
    if ((off_t)(block_size + 8) > cd_off) return -1;
    block_start = (off_t)cd_off - 8 - (off_t)block_size;

    /* 3. 遍历 ID-value pairs，找 v2/v3 块 */
    pair_pos = block_start + 8;
    while (pair_pos + 12 <= (off_t)cd_off - 24) {
        unsigned long long pair_len;
        if (read_at(fd, header, 12, pair_pos) != 0) break;
        pair_len = rd64le(header);            /* 长度含 id(4)+value */
        block_id = (unsigned long long)rd32le(header + 8);
        if (pair_len < 4 || pair_len > block_size) break;
        if (block_id == V2_BLOCK_ID || block_id == V3_BLOCK_ID) {
            unsigned long long vlen = pair_len - 4;
            value = (unsigned char *)malloc(vlen);
            if (!value) return -1;
            if (read_at(fd, value, vlen, pair_pos + 12) != 0) { free(value); return -1; }
            found = (int)vlen;
            break;
        }
        pair_pos += 8 + (off_t)pair_len;
    }
    if (found < 0) return -1;

    /*
     * 4. 解析 signer 结构（所有长度均为 uint32 LE 前缀）：
     *    value = [len signers][signer...]
     *    signer = [len][signed_data][len signatures][len public_key]
     *    signed_data = [len digests][len certificates][len additional]
     *    certificates = [len cert1][...]
     */
    {
        const unsigned char *p = value;
        const unsigned char *end = value + found;
        unsigned int signer_len, sd_len, digests_len, certs_len, cert_len;
        const unsigned char *signer, *sd, *certs;

        p += 4;                                     /* signers 区总长（无需使用） */
        if (p + 4 > end) goto fail;
        signer_len = rd32le(p); p += 4;             /* 第一个 signer 的长度 */
        if (p + signer_len > end) goto fail;
        signer = p;

        /* signer 内部：signed_data */
        if (signer + 4 > signer + signer_len) goto fail;
        sd_len = rd32le(signer); signer += 4;
        if (signer + sd_len > signer - 4 + signer_len + 0) { /* 长度自洽性检查放在下面 */
        }
        sd = signer;
        if (sd + sd_len > end) goto fail;

        /* signed_data 内部：跳过 digests，取 certificates */
        if (sd + 4 > sd + sd_len) goto fail;
        digests_len = rd32le(sd); sd += 4;
        if (sd + digests_len + 4 > sd + sd_len) goto fail;
        sd += digests_len;
        certs_len = rd32le(sd); sd += 4;            /* certificates 区总长 */
        certs = sd;

        if (certs + 4 > certs + certs_len) goto fail;
        cert_len = rd32le(certs); certs += 4;       /* 第一张证书 DER */
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

/* ─────────────────────────── 校验主逻辑 ─────────────────────────── */

static void *delayed_kill(void *arg) {
    /* 失败后延时随机 90~270 秒再 abort，攻击者难以关联崩溃原因；
       二期升级为污染数据等更隐蔽的破坏策略 */
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    int delay = 90 + (int)(rand_r(&seed) % 180);
    LOGD("v");
    sleep(delay);
    abort();
    return NULL;
}

static void sig_verify(void) {
    char apk_path[1024];
    int fd;
    unsigned char *der = NULL;
    size_t der_len = 0;
    unsigned char actual[32];
    int i, mismatch = 0;
    int slot_configured = 0;

    /* 调试模式：槽位全零（流水线未注入）则跳过 */
    for (i = 0; i < 32; i++) {
        if (SIG_HASH[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured) {
        LOGI("sig hash slot empty, skip verify");
        return;
    }

    if (find_apk_path(apk_path, sizeof(apk_path)) != 0) {
        LOGE("apk not found");
        goto fail;
    }

    fd = open(apk_path, O_RDONLY);
    if (fd < 0) {
        LOGE("open apk failed");
        goto fail;
    }

    if (extract_cert_der(fd, &der, &der_len) != 0) {
        close(fd);
        LOGE("no v2/v3 signing block or parse failed");
        goto fail;
    }

    sha256(der, der_len, actual);
    free(der);
    close(fd);

    /* 恒定时间比较，避免计时侧信道 */
    for (i = 0; i < 32; i++) mismatch |= actual[i] ^ SIG_HASH[i];

    if (mismatch == 0) {
        LOGI("signature verify ok");
        return;
    }
    LOGE("signature mismatch");

fail:
    {
        pthread_t t;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&t, &attr, delayed_kill, NULL) != 0) {
            abort(); /* 起线程失败则直接崩，不能放行 */
        }
        pthread_attr_destroy(&attr);
    }
}

/* dlopen 后最先执行的入口（早于 JNI_OnLoad 与一切 Java 代码） */
__attribute__((constructor)) static void sig_check_entry(void) {
    sig_verify();
}

/* ── 宿主端测试钩子（仅 SIGCHECK_HOST_TEST 编译时启用，Android 构建不受影响）── */
#ifdef SIGCHECK_HOST_TEST
#include <stdlib.h>
/* 测试时用环境变量 SIGCHECK_TEST_APK 覆盖 find_apk_path 的结果 */
const char *sigcheck_test_apk_path(void);
void sig_verify_test(void) { sig_verify(); }
#endif
