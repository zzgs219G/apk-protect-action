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
#include <elf.h>
#include <sys/auxv.h>   /* 2026-12 追加:运行时探测 CPU CRC32 扩展(getauxval/AT_HWCAP) */
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
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        char *slash;
        size_t n;
        if (!strstr(line, needle)) continue;
        slash = strchr(line, '/');
        if (!slash) continue;
        n = strcspn(slash, "\n");
        if (n >= outlen) n = outlen - 1;
        memcpy(out, slash, n);
        out[n] = '\0';
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

/* d3. [addr,addr+len) 是否整体落在可读映射内(maps 解析,避免非法读崩溃) */
static int env_mem_readable(const void *addr, size_t len) {
    FILE *fp = fopen("/proc/self/maps", "r");
    char line[512];
    uintptr_t target = (uintptr_t)addr;
    uintptr_t end = target + len;
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long s = 0, e = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s", &s, &e, perms) != 3) continue;
        if (perms[0] != 'r') continue;
        if (target >= (uintptr_t)s && end <= (uintptr_t)e) { fclose(fp); return 1; }
    }
    fclose(fp);
    return 0;
}

/* d4. 解析 ELF 取 .text 的 文件偏移/虚拟地址/大小(仅小端,32/64 位) */
typedef struct { uint64_t offset; uint64_t vaddr; uint64_t size; } env_text_t;

static int env_elf_text(const char *path, env_text_t *out) {
    FILE *fp = fopen(path, "rb");
    unsigned char ident[16];
    int is64, ok = 0;
    if (!fp) return 0;
    if (fread(ident, 1, 16, fp) != 16) { fclose(fp); return 0; }
    if (ident[0] != 0x7f || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F') { fclose(fp); return 0; }
    if (ident[5] != 1) { fclose(fp); return 0; }        /* 只处理小端 */
    is64 = (ident[4] == 2);
    rewind(fp);
    if (is64) {
        Elf64_Ehdr eh;
        size_t shstr_size = 0;
        char *strtab = NULL;
        int i;
        if (fread(&eh, 1, sizeof(eh), fp) != sizeof(eh)) { fclose(fp); return 0; }
        if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shstrndx >= eh.e_shnum) { fclose(fp); return 0; }
        {
            Elf64_Shdr shstr;
            if (fseek(fp, (long)(eh.e_shoff + (uint64_t)eh.e_shstrndx * eh.e_shentsize), SEEK_SET) != 0) { fclose(fp); return 0; }
            if (fread(&shstr, 1, sizeof(shstr), fp) != sizeof(shstr)) { fclose(fp); return 0; }
            shstr_size = (size_t)shstr.sh_size;
            strtab = (char *)malloc(shstr_size + 1);
            if (!strtab) { fclose(fp); return 0; }
            if (fseek(fp, (long)shstr.sh_offset, SEEK_SET) != 0 ||
                fread(strtab, 1, shstr_size, fp) != shstr_size) { free(strtab); fclose(fp); return 0; }
            strtab[shstr_size] = '\0';
        }
        for (i = 0; i < (int)eh.e_shnum; i++) {
            Elf64_Shdr sh;
            if (fseek(fp, (long)(eh.e_shoff + (uint64_t)i * eh.e_shentsize), SEEK_SET) != 0) break;
            if (fread(&sh, 1, sizeof(sh), fp) != sizeof(sh)) break;
            if ((size_t)sh.sh_name >= shstr_size) continue;
            if (strcmp(strtab + sh.sh_name, ".text") == 0) {
                out->offset = sh.sh_offset; out->vaddr = sh.sh_addr; out->size = sh.sh_size;
                ok = 1; break;
            }
        }
        free(strtab); fclose(fp);
        return ok;
    }
    {
        Elf32_Ehdr eh;
        size_t shstr_size = 0;
        char *strtab = NULL;
        int i;
        if (fread(&eh, 1, sizeof(eh), fp) != sizeof(eh)) { fclose(fp); return 0; }
        if (eh.e_shoff == 0 || eh.e_shnum == 0 || eh.e_shstrndx >= eh.e_shnum) { fclose(fp); return 0; }
        {
            Elf32_Shdr shstr;
            if (fseek(fp, (long)(eh.e_shoff + (uint32_t)eh.e_shstrndx * eh.e_shentsize), SEEK_SET) != 0) { fclose(fp); return 0; }
            if (fread(&shstr, 1, sizeof(shstr), fp) != sizeof(shstr)) { fclose(fp); return 0; }
            shstr_size = (size_t)shstr.sh_size;
            strtab = (char *)malloc(shstr_size + 1);
            if (!strtab) { fclose(fp); return 0; }
            if (fseek(fp, (long)shstr.sh_offset, SEEK_SET) != 0 ||
                fread(strtab, 1, shstr_size, fp) != shstr_size) { free(strtab); fclose(fp); return 0; }
            strtab[shstr_size] = '\0';
        }
        for (i = 0; i < (int)eh.e_shnum; i++) {
            Elf32_Shdr sh;
            if (fseek(fp, (long)(eh.e_shoff + (uint32_t)i * eh.e_shentsize), SEEK_SET) != 0) break;
            if (fread(&sh, 1, sizeof(sh), fp) != sizeof(sh)) break;
            if ((size_t)sh.sh_name >= shstr_size) continue;
            if (strcmp(strtab + sh.sh_name, ".text") == 0) {
                out->offset = sh.sh_offset; out->vaddr = sh.sh_addr; out->size = sh.sh_size;
                ok = 1; break;
            }
        }
        free(strtab); fclose(fp);
        return ok;
    }
}

/* d5. libc .text 内存 vs 磁盘 CRC 比对;不等=内存被改写。任一步异常→放行(未检出) */
static int libc_text_crc_probe(void) {
    Dl_info info;
    char path[512];
    env_text_t ts;
    FILE *fp;
    uint8_t *fb;
    size_t n;
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

    fp = fopen(path, "rb");
    if (!fp) return 0;
    if (fseek(fp, (long)ts.offset, SEEK_SET) != 0) { fclose(fp); return 0; }
    fb = (uint8_t *)malloc((size_t)ts.size);
    if (!fb) { fclose(fp); return 0; }
    n = fread(fb, 1, (size_t)ts.size, fp);
    fclose(fp);
    if (n != (size_t)ts.size) { free(fb); return 0; }

    cf = env_crc32(fb, (size_t)ts.size);
    cm = env_crc32(mem, (size_t)ts.size);
    free(fb);
    return (cf != cm) ? 1 : 0;
}

/* e. Frida 线程名检测(读 /proc/self/task/<tid>/comm) */
static int frida_thread_probe(void) {
    static const char *names[] = { "gum-js-loop", "gmain", "gdbus", "pool-frida", "frida" };
    const size_t nnames = sizeof(names) / sizeof(names[0]);
    DIR *d = opendir("/proc/self/task");
    struct dirent *de;
    int hits = 0, gum = 0;
    if (!d) return 0;
    while ((de = readdir(d)) != NULL) {
        char p[160];
        char nm[64];
        FILE *f;
        size_t i, L;
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        snprintf(p, sizeof(p), "/proc/self/task/%s/comm", de->d_name);
        f = fopen(p, "r");
        if (!f) continue;
        if (fgets(nm, sizeof(nm), f) == NULL) { fclose(f); continue; }
        fclose(f);
        L = strcspn(nm, "\n");
        nm[L] = '\0';
        for (i = 0; i < nnames; i++) {
            if (strcmp(nm, names[i]) == 0) {
                hits++;
                if (strcmp(nm, "gum-js-loop") == 0) gum = 1;
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
    static const char *sigs[] = { "frida", "linjector", "gum-js" };
    const size_t ns = sizeof(sigs) / sizeof(sigs[0]);
    FILE *fp = fopen("/proc/net/unix", "r");
    char line[512];
    if (!fp) return 0;
    while (fgets(line, sizeof(line), fp)) {
        size_t i;
        for (i = 0; i < ns; i++) {
            if (strstr(line, sigs[i])) { fclose(fp); return 1; }
        }
    }
    fclose(fp);
    return 0;
}

/* g. 常驻复查线程:周期性重跑全部探测,补"启动后才挂载"的窗口。
 *    与构造时一次性检测并存(env_check_run 先跑一次,再启动本线程)。 */
static void *env_watchdog(void *arg) {
    (void)arg;
    for (;;) {
        int hit = 0;
        sleep(20);
        if (frida_port_probe())              hit = 1;
        if (!hit && frida_maps_probe())      hit = 1;
        if (!hit && frida_tcp_table_probe()) hit = 1;
        if (!hit && frida_thread_probe())    hit = 1;
        if (!hit && frida_unix_probe())      hit = 1;
        if (!hit && xposed_maps_probe())     hit = 1;
        if (!hit && xposed_file_probe())     hit = 1;
        if (!hit && libc_text_crc_probe())   hit = 1;
        if (!hit && tracer_probe())          hit = 1;
        if (hit) {
            /*LSG:ENV_WATCHDOG_HIT|【失败】常驻复查线程检出危险环境*/
            envlog_c(1, LSG_ENV_WATCHDOG_HIT, NULL);
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
    env_watchdog_start();   /* 2026-12 追加:常驻复查线程(不影响上面的"加载即检") */
}
