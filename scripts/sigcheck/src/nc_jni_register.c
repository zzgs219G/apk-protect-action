/* nc_jni_register.c — JNI 动态注册（2026-10-19）
 *
 * 修实测报告 §1/#1 与 §7.1「符号隐藏 ☆☆☆☆☆」：
 *   此前 7 个 JNI 函数以 `Java_<pkg>_<Class>_<method>` 形式导出在 .dynsym，
 *   `nm -D` 一条命令即可拿到全部入口名 + 每个函数的精确大小：
 *
 *     Java_com_nc_link_NcLink_ncVerify                 152 B
 *     Java_com_nc_link_NcLink_heartbeat                136 B
 *     Java_com_nc_link_NcLink_selftest                 ...
 *     Java_amimo_dcc_DccApplication_init__               4 B
 *     Java_com_xixin_box_MainActivity_k__...          21692 B   ← 业务复杂度地图
 *     Java_com_xixin_box_MainActivity_onCreate__...    5460 B
 *     Java_com_xixin_box_MainActivity_onConfigurationChanged__... 1084 B
 *
 *   报告实测据此"不解密就拿到业务方法清单 + 每个方法的边界和大小"。
 *   加密层保护了代码内容，却把代码地图免费送出。
 *
 * 修法：改用 RegisterNatives 动态注册。
 *   · 注册表里以【字符串】写方法名与签名（这是运行期才需要的，不进符号表）
 *   · 所有 JNI 实现函数改 static → 编译器不导出符号
 *   · .dynsym 只剩一个必须保留的 JNI_OnLoad（ART 确实按名查找它）
 *
 * ⚠️ 为什么不能只靠 -fvisibility=hidden：JNIEXPORT 本身带 default 可见性
 *    （JNI 短名绑定要求如此），所以 hidden 对它无效。必须改成动态注册。
 *
 * ⚠️ 保留 JNI_OnLoad 的代价：它仍然可见，但只剩一个符号、无大小信息，
 *    报告里"业务方法清单 + 精确大小"这两个最致命的信息全部消失。
 *
 * ⚠️ 方法名与签名必须与 Java 侧逐一对应，否则运行期 RegisterNatives 失败。
 *    对拍由 javalink 侧保证：inject-javacheck.py 注入的 smali 方法名固定。
 *
 * 性能：注册只在 JNI_OnLoad 时做一次，几十个字符串比较，微秒级。
 *       之后 Java→Native 调用走 ART 缓存，与短名绑定无差异。
 */
#include <jni.h>
#include <string.h>

#include "nc_jni_register.h"

/* 由各 .c 提供的实现（static，不出符号表） */
extern jint  nc_jni_selftest(JNIEnv *env, jobject thiz);
extern jboolean nc_jni_ncVerify(JNIEnv *env, jclass clazz, jbyteArray measured);
extern void  nc_jni_heartbeat(JNIEnv *env, jclass clazz);

/* dex2c 转译方法（可变数量）的注册表，由 gen-jni-register.py 生成。
 * 没有 dex2c（只勾 sigcheck）时该文件不存在 → 用 weak 符号落空跳过，
 * 组合自洽（与 nc_link 的 weak 心跳同一思路）。 */
#if defined(NC_HAS_D2C_REG)
extern int nc_jni_gen_register(JNIEnv *env);
#endif

/* 桥接类名：与 inject-javacheck.py 注入的 smali 保持同包同名。
 * 用字符串而非常量拼接，避免编译器把它内联成符号引用。 */
static const char *const NC_BRIDGE_CLASS = "com/nc/link/NcLink";

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env = NULL;
    jclass clazz;
    JNINativeMethod methods[3];

    (void)reserved;
    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6) != JNI_OK || env == NULL) {
        return JNI_ERR;
    }

    clazz = (*env)->FindClass(env, NC_BRIDGE_CLASS);
    if (clazz == NULL) {
        /* 桥接类不存在 = Java 侧没注入（例如只勾 envcheck 的组合）。
         * 这不是错误：此时没有任何 Java 侧调用者，静默放行即可。
         * 但必须清掉 pending exception，否则后续 JNI 调用全乱。 */
        (*env)->ExceptionClear(env);
        return JNI_VERSION_1_6;
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
        /* 注册失败不阻断 so 加载：Java 侧会拿到 UnsatisfiedLinkError，
         * 那是 Java 层的事（且会被 try/catch 兜住，见报错四十九的教训
         * ——防御代码自身失败不能变成新的崩溃源）。 */
        (*env)->ExceptionClear(env);
    }

#if defined(NC_HAS_D2C_REG)
    /* dex2c 转译方法：数量随 APK 变化，由生成器产出。
     * 失败同样不阻断（各方法自己的 Java 侧会报 ULE）。 */
    (void) nc_jni_gen_register(env);
#endif
    return JNI_VERSION_1_6;
}
