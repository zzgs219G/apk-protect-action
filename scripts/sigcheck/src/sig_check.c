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
 *      经双轮派生(derive_expected,2026-10 追加)后与 sig_hash.h 中的
 *      SIG_HASH_STORED 比对——明文指纹不再落盘(防搜索替换攻击)。
 *   3. 校验失败不直接 exit(0)：起分离线程延时随机 abort，
 *      让"hook exit/abort 即绕过"的通用脚本失效（二期继续增强为隐蔽破坏）。
 *      当前延时 1~3 秒(调试)，改法见 delayed_kill 函数上方注释。
 *   4. SIG_HASH_STORED 全零 = 调试模式（流水线未注入派生槽位时跳过校验，便于本地测试）。
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

/* ─────────────────────────── 文件日志(追加能力,用户 2026-09-08 需求) ───────────────────────────
 * 背景:logcat 在无 adb 的真机排障场景拿不到,"签名一致仍闪退"无法定位。
 * 方案:LOGD/LOGI/LOGE 在原 logcat 输出之外,同步追加写入应用外部目录文件。
 *
 * 开关(哨兵文件,运行时生效,无需重编译/重装):
 *   /storage/emulated/0/xixin_debug   存在 → 写文件日志
 *   (2026-xx 用户要求统一改名:原 sigcheck_debug → xixin_debug,与 jian_box
 *    普通 App 的崩溃日志开关共用同一文件名,用户只记一个开关)
 *   (放 sdcard 根而非 Android/data:MT 管理器等工具在 Android 11+ 也能直接建)
 * 日志输出:
 *   /storage/emulated/0/Android/data/<包名>/files/sigcheck_log.txt
 *
 * 安全性:所有文件 I/O 失败一律静默忽略(constructor 早期 FUSE 可能未就绪),
 * 不影响校验主流程;日志内容只有路径/指纹哈希/分支结论,无密钥无用户数据。 */

#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <dlfcn.h>     /* 报错十四: dladdr/dlsym 定位本 so 真实路径 */

#define SIGLOG_SENTINEL "/storage/emulated/0/xixin_debug"

static char siglog_path[512];   /* 日志文件完整路径,'' = 未探测 */
static int  siglog_ready = -1;  /* -1 未探测, 0 开关关/不可用, 1 可写 */

/* 前向声明:get_pkg_name 定义在本文件后部(§定位 base.apk),此处先用 */
static int get_pkg_name(char *out, size_t outlen);

static void siglog_detect(void) {
    char pkg[256];
    const char *env;
    if (siglog_ready >= 0) return;
    siglog_ready = 0;
#ifdef SIGCHECK_HOST_TEST
    /* 宿主测试:不碰 sdcard,开关用环境变量控制 */
    env = getenv("SIGCHECK_TEST_LOG");
    if (!env || !*env) return;
    snprintf(siglog_path, sizeof(siglog_path), "%s", env);
    siglog_ready = 1;
    return;
#endif
    if (access(SIGLOG_SENTINEL, F_OK) != 0) return;   /* 哨兵不存在 → 关 */
    if (get_pkg_name(pkg, sizeof(pkg)) != 0) return;
    snprintf(siglog_path, sizeof(siglog_path),
             "/storage/emulated/0/Android/data/%s/files/sigcheck_log.txt", pkg);
    siglog_ready = 1;   /* 真正可写性由 siglog 打开时判定,失败静默 */
}

static void siglog(const char *prio, const char *fmt, ...) {
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    va_list ap;
    if (siglog_ready != 1) return;
    fp = fopen(siglog_path, "a");
    if (!fp) { siglog_ready = 0; return; }   /* 不可写 → 本次进程内放弃,不重试 */
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000UL);
    fprintf(fp, "[%lu][%s][pid %d] ", ms, prio, (int)getpid());
    va_start(ap, fmt);
    vfprintf(fp, fmt, ap);
    va_end(ap);
    fputc('\n', fp);
    fclose(fp);
}

/* 重定义三个日志宏为"logcat + 文件"双写;所有调用点零改动(纯追加原则) */
#undef LOGD
#undef LOGI
#undef LOGE
#define LOGD(...) do { __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__); \
                       siglog("D", __VA_ARGS__); } while (0)
#define LOGI(...) do { __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__); \
                       siglog("I", __VA_ARGS__); } while (0)
#define LOGE(...) do { __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__); \
                       siglog("E", __VA_ARGS__); } while (0)

/* ─────────────────────────── 中文流程日志(用户 2026-11 需求) ───────────────────────────
 * 需求:日志每行能让用户(非英文读者)一眼看出"这行在干什么、是成功还是报错"。
 * 方案:文案明文只写在调用点的 LSG 标记注释里(形如 斜杠星LSG:NAME|文案星斜杠,
 *       源码可读,注释即真相);scripts/sig-log/make-sig-log.py 构建期扫描标记
 *       生成 sig_log_data.h(XOR 密文数组,与源文件同目录编译);运行时解码。
 * so 里只有密文 → strings 不泄功能语义(不回退 2026-10 加固,同一威胁模型)。
 * 三级前缀约定(用户约定,勿改):
 *   【流程】= 正常走到某一步  【成功】【通过】= 该步/校验正常
 *   【失败】= 出错,走 fail 链  【数据】= 关键中间值(路径/指纹) */
#include "sig_log_data.h"

static void siglog_c(int prio, lsg_id_t id, const char *detail) {
    char msg[512];
    if (lsg_decode(id, msg, sizeof(msg)) < 0) return;
    /* detail: 可选的运行时数据(路径/errno 说明),拼在中文文案后 */
    if (detail && *detail) {
        __android_log_print(prio, LOG_TAG, "%s (%s)", msg, detail);
        {
            char line[640];
            snprintf(line, sizeof(line), "%s (%s)", msg, detail);
            siglog(prio == ANDROID_LOG_DEBUG ? "D" : prio == ANDROID_LOG_ERROR ? "E" : "I", "%s", line);
        }
    } else {
        __android_log_print(prio, LOG_TAG, "%s", msg);
        siglog(prio == ANDROID_LOG_DEBUG ? "D" : prio == ANDROID_LOG_ERROR ? "E" : "I", "%s", msg);
    }
}

#define LSGD(id, ...) do { char d_[256]; snprintf(d_, sizeof(d_), __VA_ARGS__); \
                           siglog_c(ANDROID_LOG_DEBUG, id, d_); } while (0)
#define LSGI(id, ...) do { char d_[256]; snprintf(d_, sizeof(d_), __VA_ARGS__); \
                           siglog_c(ANDROID_LOG_INFO, id, d_); } while (0)
#define LSGE(id, ...) do { char d_[256]; snprintf(d_, sizeof(d_), __VA_ARGS__); \
                           siglog_c(ANDROID_LOG_ERROR, id, d_); } while (0)
#define LSGI0(id)   siglog_c(ANDROID_LOG_INFO, id, NULL)
#define LSGE0(id)   siglog_c(ANDROID_LOG_ERROR, id, NULL)

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
 *   2. 报错十四：extractNativeLibs=true 时 so 是从 lib/<abi>/libnc.so
 *      加载的，由 so 自身路径反推同安装目录下的 base.apk
 *      （/proc/<pid>/root 前缀是为了获得 SELinux 可读的真实路径）；
 *   3. 最后兜底遍历 /data/app/（Android 11+ 因 SELinux 大概率 EACCES，
 *      保留兼容旧机型）。
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
            /* 报错十二修复:p 必须停在 "base.apk" 【之后】,旧代码 *p='\0'
             * 把文件名本身截掉,得到 ".../" 目录 → open 必失败 → 延时 abort
             * (与签名无关,同 keystore 重签也必闪退) */
            /* 报错十七修复(两处叠加,真机日志 com.sdmnfowa.soad.p1):
             * ① 命中条件去掉 ".so":extractNativeLibs=false 时 so 映射自
             *   base.apk,maps 行路径是 ".../base.apk",行内根本不含 ".so"
             *   字样——旧条件 strstr(".so") 在真实布局下永不正确命中,唯一
             *   命中途径是路径其他部分恰好含 ".so"(实例: 包名 com.sdmnfowa.
             *   soad.p1 含 ".so" 子串,dex 映射 base.apk 行被误判命中 →
             *   误入本分支)。这也解释了为何只有特定包名闪退、其他包正常。
             *   凡 maps 出现 base.apk 行即指向 APK 本体,取路径 access
             *   确认即可,确认失败继续扫行走原有 fallback。
             * ② 命中后只截尾不截头:maps 行首是 "addr perms offset dev
             *   inode",旧代码 *p='\0' 后 out 从行首开始 → out 是带元数据
             *   的整行前缀(真机日志实锤),open 必 errno=2 → 签名一致也
             *   延时 abort。现向前回溯到最后一个空格取纯路径。 */
            p = strstr(line, "base.apk");
            if (p) {
                char *sp;
                p += 8; /* strlen("base.apk") */
                *p = '\0';
                sp = strrchr(line, ' ');  /* 行首元数据与路径的分隔空格 */
                if (sp) {
                    snprintf(out, outlen, "%s", sp + 1);
                    if (access(out, R_OK) == 0) {
                        fclose(fp);
                        LOGI("apk path from maps: %s", out);
                        /*LSG:MAPS_OK|【成功】maps 直接定位到 APK*/
                        LSGI(LSG_MAPS_OK, "%s", out);
                        return 0;
                    }
                    LOGE("maps candidate not accessible: %s errno=%d", out, errno);
                    /*LSG:MAPS_NG|【流程】maps 候选路径不可读,继续扫 maps 后续行*/
                    LSGE(LSG_MAPS_NG, "%s errno=%d", out, errno);
                }
                /* 取不到纯路径或不可读:继续扫后续行,走原有 fallback */
            }
        }
        fclose(fp);
        LOGI("maps has no base.apk!/...so line, try lib-path fallback");
        /*LSG:MAPS_MISS|【流程】maps 无 base.apk 行,改由 libnc.so 路径反推*/
        LSGI0(LSG_MAPS_MISS);
    } else {
        LOGE("fopen /proc/self/maps failed: errno=%d", errno);
        /*LSG:MAPS_OPEN_ERR|【失败】无法打开 /proc/self/maps*/
        LSGE(LSG_MAPS_OPEN_ERR, "errno=%d", errno);
    }

    /* ── 报错十四修复：由 so 自身路径反推 base.apk ────────────────────
     * 现象(2026-09-08 真机日志, com.xixin.box): extractNativeLibs=true
     * (本流水线强制)时 so 从 lib/<abi>/libnc.so 加载, maps 无 base.apk 行;
     * 兜底 opendir("/data/app") 在 Android 11+ 被 SELinux 拒 → errno=13
     * → "apk not found" → 签名一致也延时 abort。
     * 修法: dladdr 取本 so 真实路径(/proc/<pid>/root 前缀)或直接扫 maps
     * 里本 so 的映射行, 截掉 "/lib/<abi>/libnc.so" 得安装根目录,
     * 拼上 base.apk 后 access(R_OK) 确认。 */
    {
        Dl_info info;
        char root[1024];
        size_t r;
        /* 直接对本文件的 static 函数指针做 dladdr 即可(dlsym 查不到 static
         * 符号;dladdr 按"地址落在哪个 so"反查,static 函数一样有效) */
        if (dladdr((void *)&find_apk_path, &info) && info.dli_fname) {
            snprintf(root, sizeof(root), "%s", info.dli_fname);
        } else {
            FILE *mfp = fopen("/proc/self/maps", "r");
            root[0] = '\0';
            if (mfp) {
                while (fgets(line, sizeof(line), mfp)) {
                    char *q = strstr(line, "/libnc.so");
                    if (q) { *q = '\0'; snprintf(root, sizeof(root), "%s", line); break; }
                }
                fclose(mfp);
            }
        }
        r = strlen(root);
        if (r > 0) {
            const char *sfx = "/lib/";
            char *cut = NULL;
            char *s = strstr(root, sfx);
            /* 只认“安装根目录/lib/”结构，且截点在路径中后段，防止包名含 /lib/ 误截 */
            if (s && (size_t)(s - root) > 6) cut = s;
            if (cut) {
                char candidate[1100];
                *cut = '\0';
                snprintf(candidate, sizeof(candidate), "/proc/self/root%s/base.apk", root);
                if (access(candidate, R_OK) == 0) {
                    snprintf(out, outlen, "%s", candidate);
                    LOGI("apk path from so dir: %s", out);
                    /*LSG:SODIR_OK|【成功】由 libnc.so 路径反推出 APK*/
                    LSGI(LSG_SODIR_OK, "%s", out);
                    return 0;
                }
                LOGE("so-dir candidate not accessible: %s errno=%d", candidate, errno);
                /*LSG:SODIR_NG|【流程】so 路径反推的候选不可读*/
                LSGE(LSG_SODIR_NG, "%s errno=%d", candidate, errno);
            } else {
                LOGE("so path not in expected layout: %s", root);
                /*LSG:SODIR_LAYOUT|【流程】so 路径不是预期安装布局,反推失败*/
                LSGE(LSG_SODIR_LAYOUT, "%s", root);
            }
        } else {
            LOGE("cannot resolve self so path (dladdr+maps both empty)");
            /*LSG:SODIR_NOSELF|【流程】无法取得本 so 自身路径*/
            LSGE0(LSG_SODIR_NOSELF);
        }
    }

    {
        char pkg[256];
        DIR *d1, *d2;
        struct dirent *e1, *e2;
        if (get_pkg_name(pkg, sizeof(pkg)) != 0) {
            LOGE("read /proc/self/cmdline failed: errno=%d", errno);
            return -1;
        }
        LOGI("pkg from cmdline: %s", pkg);

        d1 = opendir("/data/app");
        if (!d1) {
            LOGE("opendir /data/app failed: errno=%d", errno);
            return -1;
        }
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
                    /*LSG:DATA_OK|【成功】遍历 /data/app 定位到 APK*/
                    LSGI(LSG_DATA_OK, "%s", out);
                    return 0;
                }
            }
            closedir(d2);
        }
        closedir(d1);
        LOGE("data/app scan exhausted: no <pkg>*/base.apk accessible");
        /*LSG:DATA_MISS|【失败】/data/app 扫描完毕,无可读 base.apk*/
        LSGE0(LSG_DATA_MISS);
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

    /*LSG:BLK_START|【流程】开始解析 APK Signing Block(找 EOCD)*/
    LSGD(LSG_BLK_START, "fsize=%ld", (long)fsize);

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

    /*LSG:BLK_MAGIC_OK|【成功】找到 APK Signing Block magic*/
    LSGI0(LSG_BLK_MAGIC_OK);

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
            /*LSG:BLK_ID_OK|【成功】命中 v2/v3 签名块,读取 signer 数据*/
            LSGI(LSG_BLK_ID_OK, "id=0x%llx len=%d", (unsigned long long)block_id, found);
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
        /*LSG:CERT_OK|【成功】证书 DER 提取成功*/
        LSGI(LSG_CERT_OK, "der_len=%zu", *out_len);
        return 0;
    }
fail:
    free(value);
    return -1;
}

/* ─────────────────────────── 校验主逻辑 ─────────────────────────── */

/* [2026-10 追加] 双轮派生:期望值存储形态还原(与 make-sig-hash.sh 生成侧逐字节一致)。
 * 背景:明文指纹 SIG_HASH 在 so 里可被十六进制搜索替换(攻击者拿公开证书指纹
 * 原地覆盖期望值即绕过)。改为存 SIG_SALT/SIG_HASH_STORED:
 *   生成侧: salt=os.urandom(16); t1=SHA256(fp); stored[i]=t1[i]^salt[i%16]^(i*0x9E&0xFF)
 *   校验侧(本函数): 对运行时提取的实际指纹 actual 做同样变换,再与 stored 比对。
 * 明文指纹从二进制中消失;攻击者无法脱离本函数的派生逻辑构造替换目标。
 * ⚠️ 两侧实现必须逐字节一致,否则正确签名也闪退(显性失败,联调即暴露)。 */
static void derive_expected(const unsigned char actual[32], unsigned char out[32]) {
    unsigned char t1[32];
    int i;
    sha256(actual, 32, t1);   /* 复用文件内已有 sha256,零新增依赖 */
    for (i = 0; i < 32; i++)
        out[i] = (unsigned char)(t1[i] ^ SIG_SALT[i % SIG_SALT_LEN]
                                 ^ (unsigned char)((i * 0x9E) & 0xFF));
}

/* 失败后延时随机 abort，攻击者难以关联崩溃原因。
 * 二期升级为污染数据等更隐蔽的破坏策略。
 *
 * 【改延时看这里】直接改下面 delay 一行:
 *   delay = 1 + rand_r(&seed) % 3   →  随机 1~3 秒(当前,方便调试肉眼确认)
 *   想改回正式发布的 90~270 秒,把那行换成:
 *   delay = 90 + rand_r(&seed) % 180
 *   (通用格式: 下限 + rand_r(&seed) % 跨度, 跨度=上限-下限+1)
 * ⚠️ 发布前记得改回大延时,否则 hook 绕过成本大幅下降。 */
static void *delayed_kill(void *arg) {
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    int delay = 1 + (int)(rand_r(&seed) % 3);   /* 随机 1~3 秒(调试用) */
    LOGD("v");
    /*LSG:KILL|【流程】延时退出线程启动:随机延时后 abort(校验失败后的反应)*/
    LSGD(LSG_KILL, "%s", "delay=1~3s");
    /* [so加固 2026-10 追加] 延时堆破坏:校验失败除延时 abort 外,先在后台
     * 以随机间隔持续 malloc/free 不同尺寸的块(不写入,不崩溃),使攻击者
     * 即便 hook 掉 abort()/sleep() 让本线程失效,进程堆布局也已碎片化,
     * 后续任意时点的崩溃/异常都难以归因到本校验。纯 malloc/free,不触碰
     * 任何业务内存,宿主测试(SIGCHECK_HOST_TEST)同样安全。 */
    {
        int rounds = 8 + (int)(rand_r(&seed) % 16);   /* 8~23 轮,量级随机 */
        int i;
        for (i = 0; i < rounds; i++) {
            size_t sz = (size_t)(64 + (rand_r(&seed) % 4096));
            void *p = malloc(sz);
            int j;
            for (j = 0; j < 50 + (int)(rand_r(&seed) % 200); j++) {
                usleep(1000 + (rand_r(&seed) % 3000));   /* 1~4ms 抖动 */
            }
            free(p);
        }
    }
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

    siglog_detect();   /* 文件日志开关探测(只做一次,失败静默) */

    /*LSG:ENTER|【流程】so 已加载,进入签名校验 sig_verify*/
    LSGI0(LSG_ENTER);

    /* [2026-10 改] 调试模式判定改用派生后的存储槽位(全零=流水线未注入则跳过) */
    for (i = 0; i < 32; i++) {
        if (SIG_HASH_STORED[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured) {
        LOGI("nc: slot empty");   /* so加固2026-10: 原文 "sig hash slot empty, skip verify" 含路标词,改中性 */
        /*LSG:SLOT_EMPTY|【通过】指纹槽全零:流水线未注入,跳过校验(调试模式)*/
        LSGI0(LSG_SLOT_EMPTY);
        return;
    }

    /*LSG:FIND_START|【流程】开始定位 APK 文件 find_apk_path*/
    LSGI0(LSG_FIND_START);

    if (find_apk_path(apk_path, sizeof(apk_path)) != 0) {
        LOGE("apk not found (maps+data/app both failed), pkg from cmdline see above");
        /*LSG:NOT_FOUND|【失败】三条定位路径(maps/so反推/data/app)全部失败*/
        LSGE0(LSG_NOT_FOUND);
        goto fail;
    }

    fd = open(apk_path, O_RDONLY);
    if (fd < 0) {
        LOGE("open apk failed: %s errno=%d(%s)", apk_path, errno, strerror(errno));
        /*LSG:OPEN_ERR|【失败】打开 APK 失败 open()*/
        LSGE(LSG_OPEN_ERR, "%s errno=%d", apk_path, errno);
        goto fail;
    }
    /*LSG:OPEN_OK|【成功】APK 已打开*/
    LSGI(LSG_OPEN_OK, "%s", apk_path);

    if (extract_cert_der(fd, &der, &der_len) != 0) {
        close(fd);
        LOGE("no v2/v3 signing block or parse failed: %s "
             "(重签工具必须启用 v2 方案: apksigner 默认开;MT 管理器需勾选 v2)",
             apk_path);
        /*LSG:BLK_FAIL|【失败】无 v2/v3 签名块或解析失败(重签工具须启用 v2)*/
        LSGE(LSG_BLK_FAIL, "%s", apk_path);
        goto fail;
    }

    sha256(der, der_len, actual);
    free(der);
    close(fd);

    {
        char hex[65];
        static const char d[] = "0123456789abcdef";
        for (i = 0; i < 32; i++) {
            hex[i*2]   = d[actual[i] >> 4];
            hex[i*2+1] = d[actual[i] & 15];
        }
        hex[64] = '\0';
        LOGI("nc: fp=%s", hex);   /* so加固2026-10: 原文 "cert fp actual=%s",改缩写,fp=指纹(排障用) */
        /*LSG:FP|【数据】实际证书指纹 actual_fp*/
        LSGI(LSG_FP, "%s", hex);
    }

    /* [2026-10 改] 恒定时间比较:对实际指纹做双轮派生后与 SIG_HASH_STORED 比对
     * (原来直接比明文 SIG_HASH;expected 含派生结果,still 恒定时间) */
    {
        unsigned char expected[32];
        derive_expected(actual, expected);
        for (i = 0; i < 32; i++) mismatch |= expected[i] ^ SIG_HASH_STORED[i];
    }

    if (mismatch == 0) {
        LOGI("nc: ok");   /* so加固2026-10: 原文 "signature verify ok",改中性 */
        /*LSG:VERIFY_OK|【通过】指纹比对一致,签名校验通过,放行*/
        LSGI0(LSG_VERIFY_OK);
        return;
    }
    LOGE("nc: mm");   /* so加固2026-10: 原文 "signature mismatch (actual vs expected...)",排障走上方 fp 行 */
    /*LSG:VERIFY_MM|【失败】指纹比对不一致 → 校验失败,延时退出已安排*/
    LSGE0(LSG_VERIFY_MM);

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

/*
 * 兼容性说明(追加的文件日志与两种构建方式):
 *   - 联合方案/sigcheck-only: Android.mk(由 scripts/lib/lib-ndk.sh 生成)
 *     的 wildcard 收 jni/ 或 jni/nc/ 下所有 .c/.cpp,本文件在其中即被编译,
 *     无需单独源文件列表。
 *   - siglog_detect 依赖 get_pkg_name(/proc/self/cmdline),而 get_pkg_name
 *     定义在本文件前部,无新增外部依赖;CLOCK_REALTIME 与 clock_gettime
 *     在 bionic(API>=21)与 glibc 均内置,无需 -lrt。
 */
