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
    /* 哨兵与 sig_check 同一个:用户只建一个开关文件 */
    if (access("/storage/emulated/0/sigcheck_debug", F_OK) != 0) return;
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
 * 与 sig_check.c 的 delayed_kill 同款:分离线程随机延时 abort。
 * 注:两个模块各有一条延时线程,攻击者 hook 掉其一,另一条仍在——天然互为备份。 */
static void *env_delayed_kill(void *arg) {
    (void)arg;
    unsigned int seed = (unsigned int)(time(NULL) ^ getpid());
    int delay = 1 + (int)(rand_r(&seed) % 3);   /* 与 sig_check 调试延时保持一致 */
    sleep(delay);
    abort();
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

/* a2. /proc/self/maps 里有没有 frida 特征库(frida-gadget/frida-agent 注入痕迹) */
static int frida_maps_probe(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    if (!fp) return 0;
    int hit = 0;
    while (fgets(line, sizeof(line), fp)) {
        /* 只认明显的 frida 命名特征,宁漏勿误伤 */
        if (strstr(line, "frida-agent") || strstr(line, "frida-gadget") ||
            strstr(line, "frida-inject") || strstr(line, "gadget_frida")) {
            hit = 1;
            break;
        }
    }
    fclose(fp);
    return hit;
}

/* a3. /proc/net/tcp(及 tcp6) 里 27042/27043 的十六进制端口是否处于 LISTEN(0A) */
static int frida_tcp_table_probe(void) {
    static const char *tables[] = { "/proc/net/tcp", "/proc/net/tcp6" };
    static const char *hexports[] = { ":69A2", ":69A3" };   /* 27042=0x69A2 27043=0x69A3 */
    size_t t, p;
    for (t = 0; t < sizeof(tables) / sizeof(tables[0]); t++) {
        FILE *fp = fopen(tables[t], "r");
        char line[512];
        if (!fp) continue;
        while (fgets(line, sizeof(line), fp)) {
            for (p = 0; p < sizeof(hexports) / sizeof(hexports[0]); p++) {
                /* 形如 "...:69A2 00...:0000 0A ..." — 本地端口匹配 + state=0A(LISTEN) */
                if (strstr(line, hexports[p]) && strstr(line + 10, " 0A ")) {
                    fclose(fp);
                    return 1;
                }
            }
        }
        fclose(fp);
    }
    return 0;
}

/* ─────────────────────────── b. Xposed / LSPosed 检测 ─────────────────────────── */

/* b1. 已加载库特征(读 maps,比文件存在性可靠——hook 框架必然注入自身库) */
static int xposed_maps_probe(void) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    if (!fp) return 0;
    int hit = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "libxposed") || strstr(line, "lspd") ||
            strstr(line, "lsposed") || strstr(line, "edxposed") ||
            strstr(line, "libriru")  || strstr(line, "libzygisk")) {
            hit = 1;
            break;
        }
    }
    fclose(fp);
    return hit;
}

/* b2. 已加载类特征:Xposed 环境 Java 栈里常有 XposedBridge(读自身进程 oatatmp 不可靠,
 * 改为探测 Xposed 安装痕迹文件——仅命中高置信路径) */
static int xposed_file_probe(void) {
    static const char *paths[] = {
        "/data/adb/lspd",                    /* LSPosed daemon */
        "/data/adb/modules/zygisk_lsposed",  /* LSPosed zygisk 模块 */
        "/data/adb/modules/riru_lsposed",    /* LSPosed riru 旧版 */
        "/data/adb/modules/zygisk_edxposed", /* EdXposed */
        "/system/framework/XposedBridge.jar" /* 原版 Xposed */
    };
    size_t i;
    for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
        if (access(paths[i], F_OK) == 0) return 1;
    }
    return 0;
}

/* ─────────────────────────── c. 调试器检测 ─────────────────────────── */

/* /proc/self/status 的 TracerPid:被 ptrace 附着(调试器/memfault 工具)时非 0 */
static int tracer_probe(void) {
    FILE *fp = fopen("/proc/self/status", "r");
    char line[256];
    if (!fp) return 0;
    int hit = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int pid = atoi(line + 10);
            if (pid != 0) hit = 1;
            break;
        }
    }
    fclose(fp);
    return hit;
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
    env_check_run();
}
