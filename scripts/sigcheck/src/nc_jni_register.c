/* nc_jni_register.c — 手写 JNI 入口的动态注册（2026-10-19）
 *
 * 修实测报告 §1/§7.1：`nm -D` 一条命令拿到 7 个 JNI 入口名 + 精确大小
 * （`MainActivity.k` 21692 B），等于免费送业务复杂度地图。
 *
 * ── 为什么不用 JNI_OnLoad（CI 39172522061 实证）──────────────────
 * dex2c 引擎【自己也定义了 JNI_OnLoad】（`Dex2C.cpp:270`），且是 strong
 * 符号。我们再定义一个 → `duplicate symbol: JNI_OnLoad` → 链接失败。
 *
 * 也不能用 weak 覆盖：dex2c 的 JNI_OnLoad 里已经在调
 * `dynamic_register_compile_methods(env)` —— dex2c 产物本来就是
 * 动态注册的，我们不能也不该替换它。
 *
 * ── 所以本文件只做两件事 ──────────────────────────────────────
 * 1. 用 constructor 注册【我们自己手写的三个入口】（dex2c 不管它们）：
 *      NcLink.selftest / NcLink.ncVerify / NcLink.heartbeat
 * 2. 不做 JNI_OnLoad。dex2c 的产物继续由 Dex2C.cpp 的 JNI_OnLoad 注册。
 *
 * ⚠️ constructor 能否拿到 JavaVM：
 *    JNI 规范里只有 JNI_OnLoad 直接给 vm。但 `JNI_GetCreatedJavaVMs()`
 *    在 constructor 阶段可用（ART 已初始化 vm 才会 dlopen 我们的 so）。
 *    实测：拿不到就静默跳过，Java 侧会 ULE —— 但那属于"dot 没接上"，
 *    不是崩溃（报错四十九的教训：防御代码自身失败不能变成崩溃源）。
 *
 * ⚠️ 顺序：constructor(101) 与 dex2c 的 JNI_OnLoad 谁先谁后不确定，
 *    但两者注册的是【不同类的方法】，互不干扰，顺序无关。
 *
 * ── 符号隐藏的两条腿（缺一不可）────────────────────────────────
 *   a) 编译期 -DJava_xxx=ncg_d2c_<n> 改名 + visibility("hidden")
 *      → 实现函数本身不出 .dynsym
 *   b) 链接期 --version-script 只导出 JNI_OnLoad
 *      → 兜住所有漏网的 Java_* 符号（含 dex2c 产物）
 * 本文件只管 (a) 里的三个手写入口；dex2c 产物由 gen-jni-register.py 生成改名宏。
 */
#include <jni.h>
#include <string.h>

#include "nc_jni_register.h"

/* 由各 .c 提供的实现（visibility("hidden")，不出 .dynsym） */
extern jint  nc_jni_selftest(JNIEnv *env, jobject thiz);
extern jboolean nc_jni_ncVerify(JNIEnv *env, jclass clazz, jbyteArray measured);
extern void  nc_jni_heartbeat(JNIEnv *env, jclass clazz);

/* 桥接类名：与 inject-javacheck.py 注入的 smali 保持同包同名。 */
static const char *const NC_BRIDGE_CLASS = "com/nc/link/NcLink";

/* 取 JavaVM：`JNI_GetCreatedJavaVMs` 在 constructor 阶段可用
 * （ART 必须先建好 vm 才会 dlopen 我们的 so）。
 * 拿不到返回 NULL，调用方静默跳过。 */
/* ⚠️ JNI_GetCreatedJavaVMs 用 weak 声明（2026-10-19）：
 * 它是 ART 导出的 JNI 接口，但：
 *   ① 宿主测试环境（无 ART）没有它 → 若强引用，dlopen 直接失败
 *      （实测：`cannot locate symbol "JNI_GetCreatedJavaVMs"`）
 *   ② 极端情况下某些精简 / 定制 ROM 也可能不导出
 * 用 __attribute__((weak)) 声明后，符号缺失时地址为 NULL，
 * 我们静默跳过注册（Java 侧 ULE，但 so 本身能正常加载）。
 * 这符合"防御代码自身失败不能变成崩溃源"的纪律（报错四十九）。 */
extern int JNI_GetCreatedJavaVMs(JavaVM **vmBuf, jsize bufLen, jsize *nVMs)
        __attribute__((weak));

static JavaVM *nc_get_java_vm(void) {
    JavaVM *vm = NULL;
    jsize n = 0;
    if (JNI_GetCreatedJavaVMs == NULL) return NULL;   /* 无 ART，跳过 */
    if (JNI_GetCreatedJavaVMs(&vm, 1, &n) != JNI_OK || n < 1) return NULL;
    return vm;
}

__attribute__((constructor(200)))
static void nc_jni_register_entries(void) {
    JavaVM *vm = nc_get_java_vm();
    JNIEnv *env = NULL;
    jclass clazz;
    JNINativeMethod methods[3];

    if (vm == NULL) return;
    /* 已在本线程 attached（constructor 跑在加载 so 的线程上，通常是
     * Java 主线程或 ART 内部线程，两种都可能）。
     * GetEnv 失败时尝试 AttachCurrentThread —— 但不要 Detach，
     * 因为本线程可能是 Java 线程，Detach 会把它拆掉。 */
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        return;   /* 静默跳过，不 Attach（避免破坏调用线程状态） */
    }

    clazz = (*env)->FindClass(env, NC_BRIDGE_CLASS);
    if (clazz == NULL) {
        /* 桥接类不存在 = Java 侧没注入（例如只勾 envcheck 的组合）。
         * 这不是错误，清掉 pending exception 即可。 */
        (*env)->ExceptionClear(env);
        return;
    }

    {
        JNINativeMethod m0 = { (char *)"ncVerify", (char *)"([B)Z",
                               (void *)(jboolean (*)(JNIEnv *, jclass, jbyteArray))
                               nc_jni_ncVerify };
        JNINativeMethod m1 = { (char *)"heartbeat", (char *)"()V",
                               (void *)(void (*)(JNIEnv *, jclass))
                               nc_jni_heartbeat };
        JNINativeMethod m2 = { (char *)"selftest", (char *)"()I",
                               (void *)(jint (*)(JNIEnv *, jobject))
                               nc_jni_selftest };
        methods[0] = m0;
        methods[1] = m1;
        methods[2] = m2;
    }

    if ((*env)->RegisterNatives(env, clazz, methods, 3) != 0) {
        /* 注册失败不阻断：Java 侧拿 ULE，会被 try/catch 兜住
         * （报错四十九的教训：防御代码自身失败不能变成崩溃源）。 */
        (*env)->ExceptionClear(env);
    }
}
