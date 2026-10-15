/*
 * env_check.c — 纯 Native 环境检测(Frida / Xposed / 调试器),2026-10 新增模块
 *
 * 设计要点:
 *   1. 与 sig_check.c 同型:__attribute__((constructor)) 入口,so 加载即检,
 *      早于一切 Java 代码。由流水线(--envcheck)并入 libnc.so,不勾选则完全不参与编译。
 *   2. 只检测、不检测 Root/Magisk(用户拍板:避免误伤正常 root 用户)。
 *      检测项:
 *        a. Frida: 默认端口 27042 可连接 / 进程内存映射含 frida 特征 / frida-server 进程名
 *        b. Xposed/LSPosed: 已加载库特征(lspd/xposed_art 等)与常见模块文件
 *        c. 调试器: /proc/self/status 的 TracerPid != 0
 *   3. 检测到 → 与 sig_check.delayed_kill 同款反应:分离线程随机延时 abort,
 *      攻击者无法关联是哪个检测触发(两个模块的延时线程天然难以区分)。
 *   4. 全部探测失败均静默:任何一步 I/O 异常都视为"未检出",绝不误伤正常用户。
 *   5. 不依赖 sig_check.c 的任何符号(模块化契约:独立脚本/源文件,零交叉引用);
 *      自带精简日志(logcat 单路,不写文件——避免与 sigcheck 日志文件相互踩)。
 *
 * 编译:流水线 --envcheck 勾选时,把本文件并入 ndk 工程(wildcard 收编),
 *      产物与业务逻辑同在 libnc.so,防剥离。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <android/log.h>
/* 2026-12 追加:内存完整性校验(CRC32/ELF 解析)与常驻复查线程所需头 */
#include <stdint.h>
#include <time.h>
#include <dlfcn.h>
#include <sys/uio.h>   /* process_vm_readv 的 iovec(d4 指令检测) */
#include <elf.h>
#include <sys/auxv.h>   /* 2026-12 追加:运行时探测 CPU CRC32 扩展(getauxval/AT_HWCAP) */
#include <sys/ptrace.h> /* 2026-10 追加:PTRACE_TRACEME 反调试抢占 */
#include <sys/prctl.h>  /* 2026-10 追加:PR_SET_DUMPABLE 禁内存 dump */
#include <sys/syscall.h> /* 2026-10 追加:探针可信化 —— syscall 直调绕开 libc hook */
#include <signal.h>      /* 2026-10 追加:方案 F —— SIGABRT 直投内核 */
#include <stdarg.h>
#if defined(__aarch64__)
#include <arm_acle.h>   /* 2026-12 追加:__crc32* 内建即硬件 CRC32(需 target("crc")) */
#endif

/* 中文流程日志(与 sig_check.c 同一套生成数据,static 定义互不冲突):
 * 文案在源码 LSG 标记注释里(可读),so 内密文(strings 不泄语义),
 * 运行时解码后写与 sig_check 同一个日志文件(哨兵开关控制)。
 * 注:env_check 自身无文件日志能力(设计要点5:零交叉引用),解码后
 * 走 sig_check.c 提供的同名 siglog 文件通道? —— 不,遵守契约:
 * 这里自带一份最小文件写入(envlog_c),路径探测复用 sig_check 已探测
 * 的结果不可行(跨模块),故独立探测哨兵/包名,逻辑与 sig_check 对称。 */
#include "sig_log_data.h"

#define LOG_TAG "nc"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

static char envlog_path[512];
static int  envlog_ready = -1;

static void envlog_detect(void) {
    char pkg[256];
    const char *env;
    FILE *fp;
    int fd;
    if (envlog_ready >= 0) return;
    envlog_ready = 0;
#ifdef SIGCHECK_HOST_TEST
    env = getenv("SIGCHECK_TEST_LOG");
    if (!env || !*env) return;
    snprintf(envlog_path, sizeof(envlog_path), "%s", env);
    envlog_ready = 1;
    return;
#endif
    /* 哨兵与 sig_check 同一个:用户只建一个开关文件(2026-xx 改名 xixin_debug) */
    if (access("/storage/emulated/0/xixin_debug", F_OK) != 0) return;
    {
        FILE *c = fopen("/proc/self/cmdline", "r");
        if (!c) return;
        {
            size_t n = fread(pkg, 1, sizeof(pkg) - 1, c);
            fclose(c);
            if (n == 0) return;
            pkg[n] = '\0';
        }
    }
    snprintf(envlog_path, sizeof(envlog_path),
             "/storage/emulated/0/Android/data/%s/files/sigcheck_log.txt", pkg);
    /* 预检可写性(以追加方式打开一次即验证),失败则本次进程内放弃 */
    fd = open(envlog_path, O_WRONLY | O_APPEND | O_CREAT, 0644);
    if (fd < 0) return;
    close(fd);
    (void)fp;
    envlog_ready = 1;
}

static void envlog(const char *prio, const char *msg) {
    FILE *fp;
    struct timespec ts;
    unsigned long ms;
    if (envlog_ready != 1) return;
    fp = fopen(envlog_path, "a");
    if (!fp) { envlog_ready = 0; return; }
    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (unsigned long)ts.tv_sec * 1000UL + (unsigned long)(ts.tv_nsec / 1000000UL);
    fprintf(fp, "[%lu][%s][pid %d] %s\n", ms, prio, (int)getpid(), msg);
    fclose(fp);
}

/* 解码 + 写文件 + logcat(prio: 0=I 1=E) */
static void envlog_c(int is_err, lsg_id_t id, const char *detail) {
    char msg[512];
    char line[640];
    const char *prio = is_err ? "E" : "I";
    if (lsg_decode(id, msg, sizeof(msg)) < 0) return;
    if (detail && *detail) {
        snprintf(line, sizeof(line), "%s (%s)", msg, detail);
        __android_log_print(is_err ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG, "%s", line);
        envlog(prio, line);
    } else {
        __android_log_print(is_err ? ANDROID_LOG_ERROR : ANDROID_LOG_INFO, LOG_TAG, "%s", msg);
        envlog(prio, msg);
    }
}

/* ─────────────────────────── 检测到危险环境后的反应 ───────────────────────────
 * 与 sig_check.c 的 delayed_kill 同款:分离线程随机延时后处置。
 * 注:两个模块各有一条延时线程,攻击者 hook 掉其一,另一条仍在——天然互为备份。
 *
 * 前向声明:safe_syscall 定义在下方 a0b 节(探针可信化),本节的处置需要提前用它。 */
static long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5);

/* * 2026-10 增强(方案 F):让处置"不直白、难 hook、难归因"
 *   ① 延时堆破坏:先以随机间隔 malloc/free 不同尺寸的块(不写入业务内存),
 *      使进程堆布局碎片化。攻击者即便 hook 掉后续的发信号/abort,进程状态
 *      也已被扰动,后续任意时点的崩溃都难以归因到本校验。
 *      纯 malloc/free,不触碰任何业务数据(通用工具不做业务耦合)。
 *   ② syscall 直调发信号:SIGABRT 用 __NR_tgkill 直投内核,不经 libc 的
 *      abort()——攻击者 LD_PRELOAD/Frida hook abort 不再有效(与方案 C
 *      探针可信化同一思路)。
 *   ③ 保留随机延时:崩溃时机不可预测,攻击者难以把崩溃与"刚触发了什么"关联。
 *
 * 失败兜底:syscall 不可用(被 seccomp 拦等)时回落 abort(),绝不静默放行。 */
static void *env_delayed_kill(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    int delay = 1 + (int)(rand_r(&seed) % 3);   /* 与 sig_check 调试延时保持一致 */

    /* ① 延时堆破坏(与 sig_check.c 的 delayed_kill 同款手法) */
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

    /* ② syscall 直调发 SIGABRT(绕开 libc 的 abort,防 hook) */
#ifdef __NR_tgkill
    if (safe_syscall(__NR_tgkill, (long)getpid(), (long)gettid(), SIGABRT, 0, 0, 0) == 0) {
        /* 信号已投递;若因屏蔽未致死,下面兜底 */
    }
#endif
    abort();   /* ③ 兜底:syscall 失败或被拦时仍要死,绝不静默放行 */
    return NULL;
}

static void env_fail(void) {
    LOGI("nc: t");   /* so加固2026-10: 原文 "env check triggered" 含路标词,改中性 */
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, env_delayed_kill, NULL) != 0) {
        abort();   /* 起线程失败则直接崩,不能放行 */
    }
    pthread_attr_destroy(&attr);
}

/* ────────────────── a0. 反调试抢占(2026-10 追加) ──────────────────
 * tracer_probe(下方 c 项)是【被动】读 /proc/self/status 查 TracerPid——
 * 攻击者 attach 后立即 detach 即可避开(探针只在构造时 + 每 20s 跑)。
 * 本函数改为【主动】向内核声明"本进程不许被调试":
 *   ptrace(PTRACE_TRACEME) —— 声明自身为被跟踪者后,内核拒绝任何外部
 *     ptrace attach(EBUSY),调试器/事后挂载在系统层面被堵死,不依赖轮询时机。
 *   prctl(PR_SET_DUMPABLE, 0) —— 同时禁掉 /proc/pid/mem 与 core dump 的可达性,
 *     抬高内存 dump 与 Frida 注入的门槛。
 *
 * 性能:仅构造期执行一次,零运行期开销。
 * 失败处理:PTRACE_TRACEME 返回 -1 且 errno==EPERM 表示"本进程已被跟踪"
 *   (真机可能被系统的其他调试设施占用,如 Android Studio 的 profileable),
 *   此时【不判失败】——交由 tracer_probe 的 TracerPid 判定,避免误伤;
 *   其他错误同样静默(宁漏勿误伤,与全文件误报兜底纪律一致)。
 * 注:已有 tracer 挂着时 PTRACE_TRACEME 会失败,这是预期行为,不算异常。 */
static void anti_debug_preempt(void) {
    (void)ptrace(PTRACE_TRACEME, 0, 0, 0);
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

/* ────────────────── a0b. 探针可信化:syscall 直调(2026-10 追加) ──────────────────
 * 背景:全文件的 /proc 探针(以及 ELF 解析)一律走 libc 的 fopen/fgets/fread。
 * 攻击者只需 LD_PRELOAD 或 Frida 挂一个假的 fopen,即可让【全部探针】读到
 * 伪造内容(maps 里藏掉 frida、status 里 TracerPid 归零、net/unix 清空),
 * 一行 hook 废掉整个环境检测模块。
 *
 * 对策:所有敏感读取改走 syscall() 直调内核,不经 libc 的 FILE* 层。
 * 攻击者要绕过就必须 hook syscall 本身(或内核级 rootkit),门槛显著抬高。
 *
 * 性能:syscall 直调比 fopen/fgets 更轻(少一层缓冲与锁),零额外开销。
 * 兼容:__NR_openat 在 arm64 与 armv7 上均为 257,无需分架构处理;
 *       read/close 的号也不分架构。不可用(seccomp 等)时返回"读失败",
 *      由调用方的"宁漏勿误伤"兜底接住,绝不误判。
 *
 * 本函数只负责【读一段文件到内存】,不做任何判定 —— 探针的判定逻辑一行不改。 */
static long safe_syscall(long n, long a0, long a1, long a2, long a3, long a4, long a5) {
    return syscall(n, a0, a1, a2, a3, a4, a5);
}

/* 读整个文件到 calloc 的缓冲(调用方 free)。成功返回长度(不含结尾 \0),失败返回 -1。
 * 注:缓冲末尾补 \0,便于按字符串处理(与 fgets 语义衔接)。 */
static long safe_read_alloc(const char *path, char **out) {
    int fd;
    char *buf = NULL;
    size_t cap = 0, len = 0;
    *out = NULL;
    fd = (int)safe_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return -1;
    cap = 65536;
    buf = (char *)malloc(cap);
    if (!buf) { safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return -1; }
    for (;;) {
        long r;
        if (len + 4096 + 1 > cap) {
            char *nb;
            size_t ncap = cap * 2;
            nb = (char *)realloc(buf, ncap);
            if (!nb) { free(buf); safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return -1; }
            buf = nb; cap = ncap;
        }
        r = safe_syscall(__NR_read, fd, (long)(buf + len), (long)(cap - len - 1), 0, 0, 0);
        if (r < 0) { free(buf); safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return -1; }
        if (r == 0) break;
        len += (size_t)r;
        if (len > (32u << 20)) break;   /* 上限守卫:防超大文件耗尽内存 */
    }
    safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    buf[len] = '\0';
    *out = buf;
    return (long)len;
}

/* ────────────────────── 行迭代器(替代 fopen+fgets 组合) ──────────────────────
 * 用法与 fgets 循环同构,便于逐处替换而不动判定逻辑:
 *   safe_lines_t it; const char *line;
 *   if (safe_lines_open(&it, path) == 0) {
 *       while ((line = safe_lines_next(&it)) != NULL) { ...原 fgets 循环体... }
 *       safe_lines_close(&it);
 *   } */
typedef struct {
    char *buf;
    size_t pos;
    long   len;
} safe_lines_t;

static int safe_lines_open(safe_lines_t *it, const char *path) {
    it->buf = NULL; it->pos = 0; it->len = -1;
    it->len = safe_read_alloc(path, &it->buf);
    if (it->len < 0 || it->buf == NULL) { it->len = -1; return -1; }
    return 0;
}

/* 返回下一行(已去尾换行),到末尾返回 NULL。行内容指向 it->buf 内部,无需释放。 */
static char *safe_lines_next(safe_lines_t *it) {
    size_t start;
    if (it->len < 0 || it->buf == NULL) return NULL;
    if (it->pos >= (size_t)it->len) return NULL;
    start = it->pos;
    while (it->pos < (size_t)it->len && it->buf[it->pos] != '\n') it->pos++;
    it->buf[it->pos] = '\0';
    if (it->pos < (size_t)it->len) it->pos++;   /* 跳过换行 */
    return it->buf + start;
}

static void safe_lines_close(safe_lines_t *it) {
    if (it->buf) { free(it->buf); it->buf = NULL; }
    it->len = -1; it->pos = 0;
}

/* ─────────────────────────── a. Frida 检测 ─────────────────────────── */

/* a1. frida 默认端口 27042 / 27043 是否有监听者(127.0.0.1 回环快扫,50ms 超时) */
static int frida_port_probe(void) {
    static const int ports[] = { 27042, 27043 };
    size_t i;
    for (i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((unsigned short)ports[i]);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        /* 非阻塞连接探测:正常机器连接立即被拒(ECONNREFUSED)= 未检出 */
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        int r = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
        int hit = 0;
        if (r == 0) {
            hit = 1;                          /* 立即连上 = 有监听 */
        } else if (errno == EINPROGRESS) {
            fd_set wset;
            struct timeval tv = { 0, 50 };    /* 50ms,足够本机回环 */
            FD_ZERO(&wset);
            FD_SET(fd, &wset);
            if (select(fd + 1, NULL, &wset, NULL, &tv) > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                hit = (err == 0);             /* 真连上才算,其他错误=未检出 */
            }
            /* 超时:视作未检出(宁漏勿误伤) */
        }
        close(fd);
        if (hit) return 1;
    }
    return 0;
}

/* ────────────────── a2. 特征串密文标记(LSGS) ──────────────────
 * 明文只活在下面的标记注释里(与 LSG 中文文案同一套机制);
 * 构建期 make-sig-log.py 扫描加密 → so 里只有密文;
 * 运行时 lsg_s() 解码到栈缓冲。改特征串 = 改这里的标记明文。
 * ⚠️ 注释里严禁出现 LSGS 标记的字面示例(嵌套注释会提前终结本注释块,
 *    编译炸"top level declarator")——写法示例只存在于 make-sig-log.py。
 * ─────────────────────────────────────────────────────────────── */
/*LSGS:FRIDA_AGENT|frida-agent*/
/*LSGS:FRIDA_GADGET|frida-gadget*/
/*LSGS:FRIDA_INJECT|frida-inject*/
/*LSGS:GADGET_FRIDA|gadget_frida*/

/* a2. /proc/self/maps 里有没有 frida 特征库(frida-gadget/frida-agent 注入痕迹)
 * 特征串不明文进 so(2026-10,借鉴 XopProtector 的 OBSC 思路,走自家 LSG 机制):
 * 探针比对用的 4 个特征串来自上方 LSGS 标记(构建期加密,运行时 lsg_s 解码)。
 * strings 扫 so 得不到任何检测特征。
 * 解码失败(NULL)按"未检出"处理,与全文件宁漏勿误伤纪律一致。
 * ⚠️ 本注释及全文件任何注释中禁止书写 LSGS 标记的字面形态(嵌套注释会
 *    提前终结注释块,编译炸 top level declarator;报错速查已留档)。 */
static int frida_maps_probe(void) {
    safe_lines_t it;
    char *line;
    char s1[24], s2[24], s3[24], s4[24];
    int hit = 0;
    const char *k1 = lsg_s(LSGS_FRIDA_AGENT, s1, sizeof(s1));
    const char *k2 = lsg_s(LSGS_FRIDA_GADGET, s2, sizeof(s2));
    const char *k3 = lsg_s(LSGS_FRIDA_INJECT, s3, sizeof(s3));
    const char *k4 = lsg_s(LSGS_GADGET_FRIDA, s4, sizeof(s4));
    if (!k1 || !k2 || !k3 || !k4) return 0;   /* 解码失败 → 未检出 */
    if (safe_lines_open(&it, "/proc/self/maps") != 0) return 0;
    /* 只认明显的 frida 命名特征,宁漏勿误伤 */
    while ((line = safe_lines_next(&it)) != NULL) {
        if (strstr(line, k1) || strstr(line, k2) ||
            strstr(line, k3) || strstr(line, k4)) {
            hit = 1;
            break;
        }
    }
    safe_lines_close(&it);
    return hit;
}

/* ────────────────── a3. TCP 端口特征标记 ────────────────── */
/*LSGS:TCP_69A2|:69A2*/
/*LSGS:TCP_69A3|:69A3*/

/* a3. /proc/net/tcp(及 tcp6) 里 27042/27043 的十六进制端口是否处于 LISTEN(0A)
 * 端口特征串( ":69A2"/":69A3" )同样走 LSGS 密文,不明文进 so。 */
static int frida_tcp_table_probe(void) {
    static const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    char p1[12], p2[12];
    const char *hexports[2];
    size_t t, p;
    hexports[0] = lsg_s(LSGS_TCP_69A2, p1, sizeof(p1));
    hexports[1] = lsg_s(LSGS_TCP_69A3, p2, sizeof(p2));
    if (!hexports[0] || !hexports[1]) return 0;
    for (t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        safe_lines_t it;
        char *line;
        if (safe_lines_open(&it, tables[t]) != 0) continue;
        while ((line = safe_lines_next(&it)) != NULL) {
            for (p = 0; p < 2; p++) {
                /* 形如 "...:69A2 00...:0000 0A ..." — 本地端口匹配 + state=0A(LISTEN) */
                if (strstr(line, hexports[p]) && strstr(line + 10, " 0A ")) {
                    safe_lines_close(&it);
                    return 1;
                }
            }
        }
        safe_lines_close(&it);
    }
    return 0;
}

/* ─────────────────────────── b. Xposed / LSPosed 检测 ─────────────────────────── */

/* ────────────────── b1/b2. Xposed 特征标记 ────────────────── */
/*LSGS:XP_LIBXPOSED|libxposed*/
/*LSGS:XP_LSPD|lspd*/
/*LSGS:XP_LSPOSED|lsposed*/
/*LSGS:XP_EDXPOSED|edxposed*/
/*LSGS:XP_LIBRIRU|libriru*/
/*LSGS:XP_LIBZYGISK|libzygisk*/
/*LSGS:XP_PATH_LSPD|/data/adb/lspd*/
/*LSGS:XP_PATH_ZYGISK_LSP|/data/adb/modules/zygisk_lsposed*/
/*LSGS:XP_PATH_RIRU_LSP|/data/adb/modules/riru_lsposed*/
/*LSGS:XP_PATH_ZYGISK_EDX|/data/adb/modules/zygisk_edxposed*/
/*LSGS:XP_PATH_XBRIDGE|/system/framework/XposedBridge.jar*/

/* b1. 已加载库特征(读 maps,比文件存在性可靠——hook 框架必然注入自身库)
 * 6 个特征串全走 LSGS 密文(不明文进 so),解码失败按"未检出"。 */
static int xposed_maps_probe(void) {
    safe_lines_t it;
    char *line;
    char s1[16], s2[8], s3[16], s4[16], s5[16], s6[16];
    int hit = 0;
    const char *k1 = lsg_s(LSGS_XP_LIBXPOSED, s1, sizeof(s1));
    const char *k2 = lsg_s(LSGS_XP_LSPD,      s2, sizeof(s2));
    const char *k3 = lsg_s(LSGS_XP_LSPOSED,   s3, sizeof(s3));
    const char *k4 = lsg_s(LSGS_XP_EDXPOSED,  s4, sizeof(s4));
    const char *k5 = lsg_s(LSGS_XP_LIBRIRU,   s5, sizeof(s5));
    const char *k6 = lsg_s(LSGS_XP_LIBZYGISK, s6, sizeof(s6));
    if (!k1 || !k2 || !k3 || !k4 || !k5 || !k6) return 0;
    if (safe_lines_open(&it, "/proc/self/maps") != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        if (strstr(line, k1) || strstr(line, k2) ||
            strstr(line, k3) || strstr(line, k4) ||
            strstr(line, k5) || strstr(line, k6)) {
            hit = 1;
            break;
        }
    }
    safe_lines_close(&it);
    return hit;
}

/* b2. 已加载类特征:Xposed 环境 Java 栈里常有 XposedBridge(读自身进程 oatatmp 不可靠,
 * 改为探测 Xposed 安装痕迹文件——仅命中高置信路径)
 * 5 个路径全走 LSGS 密文(路径本身也是检测特征,不明文进 so)。 */
static int xposed_file_probe(void) {
    char p1[48], p2[48], p3[48], p4[48], p5[48];
    const char *paths[5];
    size_t i;
    paths[0] = lsg_s(LSGS_XP_PATH_LSPD,        p1, sizeof(p1));   /* LSPosed daemon */
    paths[1] = lsg_s(LSGS_XP_PATH_ZYGISK_LSP,  p2, sizeof(p2));   /* LSPosed zygisk 模块 */
    paths[2] = lsg_s(LSGS_XP_PATH_RIRU_LSP,    p3, sizeof(p3));   /* LSPosed riru 旧版 */
    paths[3] = lsg_s(LSGS_XP_PATH_ZYGISK_EDX,  p4, sizeof(p4));   /* EdXposed */
    paths[4] = lsg_s(LSGS_XP_PATH_XBRIDGE,     p5, sizeof(p5));   /* 原版 Xposed */
    for (i = 0; i < 5; i++) {
        if (!paths[i]) continue;          /* 单条解码失败跳过该条,不影响其余 */
        if (access(paths[i], F_OK) == 0) return 1;
    }
    return 0;
}

/* ────────────────── c/e/f. 调试器与 Frida 特征标记 ────────────────── */
/*LSGS:TRACERPID|TracerPid:*/
/*LSGS:THR_GUMJS|gum-js-loop*/
/*LSGS:THR_GMAIN|gmain*/
/*LSGS:THR_GDBUS|gdbus*/
/*LSGS:THR_POOL|pool-frida*/
/*LSGS:THR_FRIDA|frida*/
/*LSGS:UNX_FRIDA|frida*/
/*LSGS:UNX_LINJECTOR|linjector*/
/*LSGS:UNX_GUMJS|gum-js*/
/*LSGS:SYM_FOPEN|fopen*/
/*LSGS:SYM_OPEN|open*/
/*LSGS:SYM_CONNECT|connect*/
/*LSGS:SYM_READ|read*/

/* ─────────────────────────── c. 调试器检测 ─────────────────────────── */

/* /proc/self/status 的 TracerPid:被 ptrace 附着(调试器/memfault 工具)时非 0
 * "TracerPid:" 前缀走 LSGS 密文(它是调试检测的最直接路标词)。 */
static int tracer_probe(void) {
    safe_lines_t it;
    char *line;
    char tp[16];
    int hit = 0;
    const char *key = lsg_s(LSGS_TRACERPID, tp, sizeof(tp));
    if (!key) return 0;
    if (safe_lines_open(&it, "/proc/self/status") != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        if (strncmp(line, key, 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) hit = 1;
            break;
        }
    }
    safe_lines_close(&it);
    return hit;
}

/* ═══════════════════════════════════════════════════════════════════════
 * 2026-12 追加:吸收 dpt-shell 优点并超越其覆盖面(只追加,不改上方已有逻辑行)
 *   d. libc .text 内存完整性校验(CRC32):抓 inline hook / 内存补丁(借鉴 dpt_risk)
 *   e. Frida 线程名检测(/proc/self/task/<tid>/comm):抓"抹掉 maps 特征"的 Frida
 *   f. Frida unix socket 检测(/proc/net/unix):多一路抓法(dpt 无,超越)
 *   g. 常驻复查线程:保留"加载即检",另周期重检,补"启动后才挂载"窗口
 *      (dpt 只有轮询;我们两者兼得)
 * 误报兜底:以下每一项探测,任何 I/O/解析异常一律视为"未检出"(宁漏勿误伤)。
 * ═══════════════════════════════════════════════════════════════════════ */

/* d1. CRC32(标准多项式 0xEDB88320,与 zlib/CRC-32 一致) */
static uint32_t env_crc32_table[256];
static int env_crc32_ready = 0;

static void env_crc32_init(void) {
    uint32_t i, j, c;
    for (i = 0; i < 256; i++) {
        c = i;
        for (j = 0; j < 8; j++) c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        env_crc32_table[i] = c;
    }
    env_crc32_ready = 1;
}

/* d1b. 硬件 CRC32 快速路径(2026-12 追加:与表驱动逐位等价,实测快约 65 倍)
 * arm64 的 CRC 扩展是"可选"能力:运行时用 getauxval(AT_HWCAP) 探测,
 * 不具备(32 位 armeabi-v7a / 老 SoC)则自动回落下面的表驱动,结果不变。 */
#ifndef HWCAP_CRC32
#define HWCAP_CRC32 (1ul << 7)
#endif

#if defined(__aarch64__)
__attribute__((target("crc")))
static uint32_t env_crc32_hw(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    while (len >= 8) {
        uint64_t v;
        memcpy(&v, buf, 8);
        buf += 8; len -= 8;
        crc = __crc32d(crc, v);
    }
    while (len--) crc = __crc32b(crc, *buf++);
    return crc ^ 0xFFFFFFFFu;
}

/* 探测只做一次:硬件能力在进程生命周期内恒定 */
static int env_hw_crc_ok(void) {
    static int cached = -1;
    if (cached < 0) cached = (getauxval(AT_HWCAP) & HWCAP_CRC32) ? 1 : 0;
    return cached;
}
#endif

static uint32_t env_crc32(const uint8_t *buf, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
#if defined(__aarch64__)
    if (env_hw_crc_ok()) return env_crc32_hw(buf, len);
#endif
    if (!env_crc32_ready) env_crc32_init();
    for (i = 0; i < len; i++)
        crc = env_crc32_table[(crc ^ buf[i]) & 0xFFu] ^ (crc >> 8);
    return crc ^ 0xFFFFFFFFu;
}

/* d2. 从 /proc/self/maps 取"含 needle 的映射"的文件路径(第一个 '/' 起) */
static int env_map_path(const char *needle, char *out, size_t outlen) {
    safe_lines_t it;
    char *line;
    if (safe_lines_open(&it, "/proc/self/maps") != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        char *slash;
        size_t n;
        if (!strstr(line, needle)) continue;
        slash = strchr(line, '/');
        if (!slash) continue;
        n = strcspn(slash, "\n");
        if (n >= outlen) n = outlen - 1;
        memcpy(out, slash, n);
        out[n] = '\0';
        safe_lines_close(&it);
        return 1;
    }
    safe_lines_close(&it);
    return 0;
}

/* d3. [addr,addr+len) 是否整体落在可读映射内(maps 解析,避免非法读崩溃) */
static int env_mem_readable(const void *addr, size_t len) {
    safe_lines_t it;
    char *line;
    uintptr_t target = (uintptr_t)addr;
    uintptr_t end = target + len;
    if (safe_lines_open(&it, "/proc/self/maps") != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        unsigned long s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) != 3) continue;
        if (perms[0] != 'r') continue;
        if (target >= (uintptr_t)s && end <= (uintptr_t)e) { safe_lines_close(&it); return 1; }
    }
    safe_lines_close(&it);
    return 0;
}

/* d4. 解析 ELF 取 .text 的 文件偏移/虚拟地址/大小(仅小端,32/64 位) */
typedef struct { uint64_t offset; uint64_t vaddr; uint64_t size; } env_text_t;

static int env_elf_text(const char *path, env_text_t *out) {
    unsigned char *file = NULL;
    long flen;
    unsigned char ident[16];
    int is64, ok = 0;
    /* 2026-10 探针可信化:ELF 也走 syscall 直调 —— 攻击者 hook fopen 后
     * 可以喂一份"原版" .text 内容,让 libc_text_crc_probe 永久通过 */
    flen = safe_read_alloc(path, (char **)&file);
    if (flen < 16 || file == NULL) { if (file) free(file); return 0; }
    memcpy(ident, file, 16);
    if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') { free(file); return 0; }
    if (ident[5] != 1) { free(file); return 0; }        /* 只处理小端 */
    is64 = (ident[4] == 2);
    if (is64) {
        Elf64_Ehdr *eh = (Elf64_Ehdr *)file;
        size_t shstr_size = 0;
        char *strtab = NULL;
        int i;
        if ((long)sizeof(Elf64_Ehdr) > flen) { free(file); return 0; }
        if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shstrndx >= eh->e_shnum) { free(file); return 0; }
        if ((long)(eh->e_shoff + (uint64_t)eh->e_shstrndx * eh->e_shentsize + sizeof(Elf64_Shdr)) > flen) { free(file); return 0; }
        {
            Elf64_Shdr *shstr = (Elf64_Shdr *)(file + eh->e_shoff + (uint64_t)eh->e_shstrndx * eh->e_shentsize);
            shstr_size = (size_t)shstr->sh_size;
            if ((long)(shstr->sh_offset + shstr_size) > flen) { free(file); return 0; }
            strtab = (char *)malloc(shstr_size + 1);
            if (!strtab) { free(file); return 0; }
            memcpy(strtab, file + shstr->sh_offset, shstr_size);
            strtab[shstr_size] = '\0';
        }
        for (i = 0; i < (int)eh->e_shnum; i++) {
            Elf64_Shdr *sh;
            if ((long)(eh->e_shoff + (uint64_t)i * eh->e_shentsize + sizeof(Elf64_Shdr)) > flen) break;
            sh = (Elf64_Shdr *)(file + eh->e_shoff + (uint64_t)i * eh->e_shentsize);
            if ((size_t)sh->sh_name >= shstr_size) continue;
            if (strcmp(strtab + sh->sh_name, ".text") == 0) {
                out->offset = sh->sh_offset; out->vaddr = sh->sh_addr; out->size = sh->sh_size;
                ok = 1; break;
            }
        }
        free(strtab); free(file);
        return ok;
    }
    {
        Elf32_Ehdr *eh = (Elf32_Ehdr *)file;
        size_t shstr_size = 0;
        char *strtab = NULL;
        int i;
        if ((long)sizeof(Elf32_Ehdr) > flen) { free(file); return 0; }
        if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shstrndx >= eh->e_shnum) { free(file); return 0; }
        if ((long)(eh->e_shoff + (uint32_t)eh->e_shstrndx * eh->e_shentsize + sizeof(Elf32_Shdr)) > flen) { free(file); return 0; }
        {
            Elf32_Shdr *shstr = (Elf32_Shdr *)(file + eh->e_shoff + (uint32_t)eh->e_shstrndx * eh->e_shentsize);
            shstr_size = (size_t)shstr->sh_size;
            if ((long)(shstr->sh_offset + shstr_size) > flen) { free(file); return 0; }
            strtab = (char *)malloc(shstr_size + 1);
            if (!strtab) { free(file); return 0; }
            memcpy(strtab, file + shstr->sh_offset, shstr_size);
            strtab[shstr_size] = '\0';
        }
        for (i = 0; i < (int)eh->e_shnum; i++) {
            Elf32_Shdr *sh;
            if ((long)(eh->e_shoff + (uint32_t)i * eh->e_shentsize + sizeof(Elf32_Shdr)) > flen) break;
            sh = (Elf32_Shdr *)(file + eh->e_shoff + (uint32_t)i * eh->e_shentsize);
            if ((size_t)sh->sh_name >= shstr_size) continue;
            if (strcmp(strtab + sh->sh_name, ".text") == 0) {
                out->offset = sh->sh_offset; out->vaddr = sh->sh_addr; out->size = sh->sh_size;
                ok = 1; break;
            }
        }
        free(strtab); free(file);
        return ok;
    }
}

/* d4. libc 导出函数入口指令检测(2026-10 借鉴 XopProtector libc_hook_score):
 * Inline hook 的本质是"把函数入口第一条指令改写成跳转/断点",所以不校验
 * 全部 .text(那是 d5 CRC 的活),只读 4 个攻击者最常 hook 的导出函数入口
 * 4 字节,判 arm64 的 B/BL/BRK —— 16 字节 vs d5 的 1-2MB,纳秒级。
 * 打分制(照抄 Xop):单个被 hook 可能是 ROM 厂商特性(MIUI 某些隐藏 hook),
 * ≥2 分才报警压误报。读内存走 process_vm_readv(内核拷贝,不经本进程页表,
 * 防 XOM 设备直接解引用 SIGSEGV;Xop safe_read_u32 同款)。
 * 4 个函数名走 LSGS 密文(不然 "fopen"/"connect" 又是明文特征)。 */
static int env_pvm_read_u32(const void *addr, uint32_t *out) {
    struct iovec local, remote;
    if (addr == NULL || out == NULL) return 0;
    local.iov_base = out;             local.iov_len = sizeof(uint32_t);
    remote.iov_base = (void *)addr;   remote.iov_len = sizeof(uint32_t);
    /* ⚠️ process_vm_readv 是 6 参调用,syscall() 变参包装必须补第 7 个 0:
     * ARM64 变参寄存器传参,缺位读到的是寄存器残留 → EINVAL(errno 22)。
     * 实测 Termux dbg5:6 参包装恒失败,补 0 后正常。 */
    return safe_syscall(__NR_process_vm_readv, (long)getpid(),
                        (long)&local, 1L, (long)&remote, 1L, 0L) == (long)sizeof(uint32_t);
}

static int libc_hook_probe(void) {
    char n1[8], n2[8], n3[12], n4[8];
    const char *names[4];
    void *fns[4];
    int score = 0, i;
    static const uint32_t masks[3] = { 0xFC000000u, 0xFC000000u, 0xFFE0001Fu };
    static const uint32_t hooks[3] = { 0x14000000u, 0x94000000u, 0xD4200000u };
    names[0] = lsg_s(LSGS_SYM_FOPEN,   n1, sizeof(n1));
    names[1] = lsg_s(LSGS_SYM_OPEN,    n2, sizeof(n2));
    names[2] = lsg_s(LSGS_SYM_CONNECT, n3, sizeof(n3));
    names[3] = lsg_s(LSGS_SYM_READ,    n4, sizeof(n4));
    if (!names[0] || !names[1] || !names[2] || !names[3]) return 0;
    for (i = 0; i < 4; i++) {
        uint32_t w = 0;
        int j, hooked = 0;
        fns[i] = dlsym(RTLD_DEFAULT, names[i]);
        if (fns[i] == NULL) continue;
        if (!env_pvm_read_u32(fns[i], &w)) continue;
        for (j = 0; j < 3; j++) {
            if ((w & masks[j]) == hooks[j]) { hooked = 1; break; }
        }
        score += hooked;
    }
    return (score >= 2) ? 1 : 0;
}

/* d5. libc .text 内存 vs 磁盘 CRC 比对;不等=内存被改写。任一步异常→放行(未检出) */
static int libc_text_crc_probe(void) {
    Dl_info info;
    char path[512];
    env_text_t ts;
    uint8_t *fb;
    uint32_t cf, cm;
    const uint8_t *mem;

    if (dladdr((const void *)&fopen, &info) == 0 || info.dli_fbase == NULL) return 0;
    path[0] = '\0';
    if (info.dli_fname != NULL) {
        if (info.dli_fname[0] == '/')
            snprintf(path, sizeof(path), "%s", info.dli_fname);
        else
            env_map_path(info.dli_fname, path, sizeof(path));
    }
    if (path[0] == '\0') env_map_path("libc.so", path, sizeof(path));
    if (path[0] == '\0') return 0;

    if (!env_elf_text(path, &ts)) return 0;
    if (ts.size == 0 || ts.size > (64u << 20)) return 0;

    mem = (const uint8_t *)info.dli_fbase + ts.vaddr;
    if (!env_mem_readable(mem, (size_t)ts.size)) return 0;

    /* 磁盘副本读取走 syscall 直调(2026-10 修复):此前 fopen/fread 走 libc,
     * 攻击者假 fread 喂一份"与内存一致的伪造 libc 内容"即可让本探针永久失明
     * —— 文件头威胁模型自述过这一攻击(623 行),实现却漏网,真·自相矛盾。
     * safe_read_alloc 一次读全文件再按 offset 取段,开销多读文件头部,
     * 但 libc .text 通常在文件前段,可接受;CRC 降频后更是每 5 轮才一次。 */
    {
        char *file = NULL;
        long flen = safe_read_alloc(path, &file);
        if (flen < 0 || file == NULL) return 0;
        if ((long)ts.offset + (long)ts.size > flen) { free(file); return 0; }
        fb = (uint8_t *)file + ts.offset;
        cf = env_crc32(fb, (size_t)ts.size);
        cm = env_crc32(mem, (size_t)ts.size);
        free(file);
        return (cf != cm) ? 1 : 0;
    }
}

/* d6. 自身 so .text 内存 vs 磁盘 CRC 比对(2026-10 方案 B)——抓运行时 so 被 patch。
 *
 * 与 d5(libc)同构,目标换成"本 so 自身":
 *   攻击者把 nc_verify_t1 / derive_expected 等校验函数 InlineHook 成恒真后,
 *   内存里的机器码与磁盘文件不再一致 → 本探针检出。
 *
 * 性能设计(用户要求"性能写好点"):
 *   ① 复用 env_crc32 —— arm64 自动走 target("crc") 硬件指令(HWCAP 探测),
 *      实测比表驱动快约 65 倍;不支持则回落表驱动,结果逐位等价。
 *   ② 只 CRC 目标段(.text),不读整个 so —— 典型 300KB,硬件 CRC 约 0.1~0.3ms。
 *   ③ 磁盘侧只读该段(openat + pread 到固定缓冲),不做整文件扫描。
 *   ④ 调用频率:构造期一次 + 看门狗每 20s 一次,平均开销可忽略。
 *
 * 误报兜底(与全文件纪律一致):任一步 I/O/解析/内存权限异常 → 视为"未检出",
 *   宁漏勿误伤。特别注意:若 .text 所在页在内存中不可读(某些加固/只读映射),
 *   直接放行而不是误判。 */
static int self_text_crc_probe(void) {
    Dl_info info;
    char path[512];
    env_text_t ts;
    int fd;
    uint8_t *fb;
    long n;
    uint32_t cf, cm;
    const uint8_t *mem;

    /* 用本探针自身地址定位自家 so(dladdr 对 static 函数同样有效) */
    if (dladdr((const void *)&self_text_crc_probe, &info) == 0 || info.dli_fbase == NULL) return 0;

    path[0] = '\0';
    if (info.dli_fname != NULL) {
        if (info.dli_fname[0] == '/')
            snprintf(path, sizeof(path), "%s", info.dli_fname);
        else
            env_map_path(info.dli_fname, path, sizeof(path));
    }
    if (path[0] == '\0') env_map_path("libnc.so", path, sizeof(path));
    if (path[0] == '\0') return 0;

    if (!env_elf_text(path, &ts)) return 0;
    /* 合理性守卫:自家 .text 不该是 0 或荒谬大(防解析到错误段) */
    if (ts.size < 4096 || ts.size > (32u << 20)) return 0;

    mem = (const uint8_t *)info.dli_fbase + ts.vaddr;
    if (!env_mem_readable(mem, (size_t)ts.size)) return 0;

    /* 磁盘侧只读目标段:syscall 直调(防 fopen hook 喂假内容,与方案 C 一致) */
    fd = (int)safe_syscall(__NR_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
    if (fd < 0) return 0;
    fb = (uint8_t *)malloc((size_t)ts.size);
    if (!fb) { safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0); return 0; }
    n = safe_syscall(__NR_pread64, fd, (long)fb, (long)ts.size, (long)ts.offset, 0, 0);
    safe_syscall(__NR_close, fd, 0, 0, 0, 0, 0);
    if (n != (long)ts.size) { free(fb); return 0; }

    cf = env_crc32(fb, (size_t)ts.size);
    cm = env_crc32(mem, (size_t)ts.size);
    free(fb);
    return (cf != cm) ? 1 : 0;
}

/* e. Frida 线程名检测(读 /proc/self/task/<tid>/comm)
 * 5 个线程名全走 LSGS 密文(线程名是最直接的 Frida 指纹之一)。
 * 注意:gum 判定改为比对解码后的 k1,不再硬编码字面量。 */
static int frida_thread_probe(void) {
    char n1[16], n2[8], n3[8], n4[16], n5[8];
    const char *names[5];
    size_t i;
    DIR *d = opendir("/proc/self/task");
    struct dirent *de;
    int hits = 0, gum = 0;
    names[0] = lsg_s(LSGS_THR_GUMJS,  n1, sizeof(n1));   /* gum-js-loop */
    names[1] = lsg_s(LSGS_THR_GMAIN,  n2, sizeof(n2));
    names[2] = lsg_s(LSGS_THR_GDBUS,  n3, sizeof(n3));
    names[3] = lsg_s(LSGS_THR_POOL,   n4, sizeof(n4));   /* pool-frida */
    names[4] = lsg_s(LSGS_THR_FRIDA,  n5, sizeof(n5));
    /* 任一解码失败 → 检测不完整,按"未检出"处理(宁漏勿误伤) */
    if (!names[0] || !names[1] || !names[2] || !names[3] || !names[4]) { if (d) closedir(d); return 0; }
    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        char p[160];
        char nm[64];
        char *fb = NULL;
        size_t L;
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        snprintf(p, sizeof(p), "/proc/self/task/%s/comm", de->d_name);
        /* 线程名同样走 syscall 直调(防 fopen hook 伪造 comm) */
        if (safe_read_alloc(p, &fb) < 0 || fb == NULL) continue;
        snprintf(nm, sizeof(nm), "%s", fb);
        free(fb);
        L = strcspn(nm, "\n");
        nm[L] = '\0';
        for (i = 0; i < 5; i++) {
            if (strcmp(nm, names[i]) == 0) {
                hits++;
                if (i == 0) gum = 1;   /* 第 0 位恒为 gum-js-loop(见上方解码顺序) */
                break;
            }
        }
    }
    closedir(d);
    /* gum-js-loop 为 Frida 最特征线程名,单命中即判;其余要求 ≥2 个,压低误报 */
    return (gum || hits >= 2) ? 1 : 0;
}

/* f. Frida unix socket 检测(读 /proc/net/unix 的路径字段) */
static int frida_unix_probe(void) {
    char s1[12], s2[16], s3[12];
    const char *sigs[3];
    size_t i;
    safe_lines_t it;
    char *line;
    sigs[0] = lsg_s(LSGS_UNX_FRIDA,     s1, sizeof(s1));   /* "frida" */
    sigs[1] = lsg_s(LSGS_UNX_LINJECTOR, s2, sizeof(s2));   /* "linjector" */
    sigs[2] = lsg_s(LSGS_UNX_GUMJS,     s3, sizeof(s3));   /* "gum-js" */
    if (!sigs[0] || !sigs[1] || !sigs[2]) return 0;
    if (safe_lines_open(&it, "/proc/net/unix") != 0) return 0;
    while ((line = safe_lines_next(&it)) != NULL) {
        for (i = 0; i < 3; i++) {
            if (strstr(line, sigs[i])) { safe_lines_close(&it); return 1; }
        }
    }
    safe_lines_close(&it);
    return 0;
}

/* g. 常驻复查线程:周期性重跑全部探测,补"启动后才挂载"的窗口。
 *    与构造时一次性检测并存(env_check_run 先跑一次,再启动本线程)。
 *
 * Java 心跳检查(2026-10 借鉴 XopProtector 双向绑定):
 *    nc_heartbeat_expired 由 nc_link.c 提供(sigcheck 勾选时在工程里);
 *    envcheck 单勾时 nc_link 不在工程 → weak 弱引用自动落空返回 0,
 *    检查静默跳过,组合自洽(见 weak 符号注释)。 */
#if defined(__GNUC__)
__attribute__((weak))
#endif
int nc_heartbeat_expired(void);

static void *env_watchdog(void *arg) {
    (void)arg;
    unsigned round = 0;   /* CRC 降频计数:指令检测每轮跑,CRC 每 5 轮跑一次 */
    for (;;) {
        int hit = 0;
        sleep(20);
        round++;
        /* d4 指令打分(纳秒级)每轮先跑;命中才轮到重的 CRC(命中通常也意味着
         * 下一轮 CRC 会确认;这里独立判定,两个探针抓的攻击面不同,见各自注释) */
        if (!hit && libc_hook_probe())       hit = 1;
        if (frida_port_probe())              hit = 1;
        if (!hit && frida_maps_probe())      hit = 1;
        if (!hit && frida_tcp_table_probe()) hit = 1;
        if (!hit && frida_thread_probe())    hit = 1;
        if (!hit && frida_unix_probe())      hit = 1;
        if (!hit && xposed_maps_probe())     hit = 1;
        if (!hit && xposed_file_probe())     hit = 1;
        if (!hit && tracer_probe())          hit = 1;
        /* CRC 全量比对降频(2026-10):Inline hook 是"装完长期驻留"型攻击,
         * 100s 检出延迟对效果无损,换来 80% 轮次的毫秒级开销归零 */
        if (!hit && (round % 5 == 0) && libc_text_crc_probe()) hit = 1;
        if (!hit && (round % 5 == 0) && self_text_crc_probe()) hit = 1;
        /* 心跳超时(Java 层被删/被绕过)——独立于上面的环境探针,
         * 不占 hit 位:env_fail 路径相同,但语义上分两条日志便于排障 */
        if (!hit && nc_heartbeat_expired())  hit = 2;
        if (hit == 1) {
            /*LSG:ENV_WATCHDOG_HIT|【失败】常驻复查线程检出危险环境*/
            envlog_c(1, LSG_ENV_WATCHDOG_HIT, NULL);
            env_fail();
        } else if (hit == 2) {
            /*LSG:ENV_HB_LOST|【失败】Java 心跳丢失(壳被删或被绕过)*/
            envlog_c(1, LSG_ENV_HB_LOST, NULL);
            env_fail();
        }
    }
    return NULL;
}

static void env_watchdog_start(void) {
    pthread_t t;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&t, &attr, env_watchdog, NULL) == 0) {
        /*LSG:ENV_WATCHDOG_START|【流程】常驻复查线程已启动(每 20s 重检)*/
        envlog_c(0, LSG_ENV_WATCHDOG_START, NULL);
    }
    pthread_attr_destroy(&attr);
}

/* ─────────────────────────── 检测主逻辑 ─────────────────────────── */

static void env_check_run(void) {
    int hit = 0;
    int r;

    envlog_detect();

    /*LSG:ENV_START|【流程】so 已加载,进入环境检测 env_check_run*/
    envlog_c(0, LSG_ENV_START, NULL);

    r = frida_port_probe();
    /*LSG:ENV_FRIDA_PORT|【数据】frida 端口探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_PORT, r ? "hit" : "clean");
    if (r) hit = 1;

    r = frida_maps_probe();
    /*LSG:ENV_FRIDA_MAPS|【数据】frida maps 特征探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_MAPS, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = frida_tcp_table_probe();
    /*LSG:ENV_FRIDA_TCP|【数据】frida tcp LISTEN 探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_TCP, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = xposed_maps_probe();
    /*LSG:ENV_XP_MAPS|【数据】Xposed/LSPosed maps 特征探测结果*/
    envlog_c(0, LSG_ENV_XP_MAPS, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = xposed_file_probe();
    /*LSG:ENV_XP_FILE|【数据】Xposed/LSPosed 文件痕迹探测结果*/
    envlog_c(0, LSG_ENV_XP_FILE, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = tracer_probe();
    /*LSG:ENV_TRACER|【数据】调试器 TracerPid 探测结果*/
    envlog_c(0, LSG_ENV_TRACER, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    /* ── 2026-12 追加探测(只追加,不改上方逻辑) ── */
    r = frida_thread_probe();
    /*LSG:ENV_FRIDA_THREAD|【数据】frida 线程名探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_THREAD, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = frida_unix_probe();
    /*LSG:ENV_FRIDA_UNIX|【数据】frida unix socket 探测结果*/
    envlog_c(0, LSG_ENV_FRIDA_UNIX, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = libc_text_crc_probe();
    /*LSG:ENV_CRC|【数据】libc .text 内存完整性校验结果*/
    envlog_c(0, LSG_ENV_CRC, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    r = self_text_crc_probe();
    /*LSG:ENV_SELF_CRC|【数据】本 so .text 内存完整性校验结果*/
    envlog_c(0, LSG_ENV_SELF_CRC, r ? "hit" : "clean");
    if (!hit && r) hit = 1;

    if (hit) {
        /*LSG:ENV_FAIL|【失败】检出危险环境 → 延时退出已安排*/
        envlog_c(1, LSG_ENV_FAIL, NULL);
        env_fail();
    } else {
        /*LSG:ENV_CLEAN|【通过】六项探测全部干净,环境检测通过*/
        envlog_c(0, LSG_ENV_CLEAN, NULL);
    }
}

/* dlopen 后最先执行的入口(与 sig_check_entry 并存,顺序不定,互不依赖) */
__attribute__((constructor)) static void env_check_entry(void) {
    anti_debug_preempt();   /* 2026-10 追加:先抢占(声明不许被调试),再跑探针 */
    env_check_run();
    env_watchdog_start();   /* 2026-12 追加:常驻复查线程(不影响上面的"加载即检") */
}
