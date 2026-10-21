/* nc_guard_jni.c — .ncx 机制的 JNI 自检入口
 *
 * 为什么需要：加固包跑在真机上【没有任何现象】可观测 ——
 *   -fvisibility=hidden 把 ncguard_unlock/ncguard_probe 全藏了，
 *   "不闪退"因此什么都证明不了（那段密文可能根本没被执行）。
 * 本文件给一个显式入口，让 CI/真机拿到【可判读的回执】：
 *   Java: NcLink.selftest()   C: Java_com_nc_link_NcLink_selftest()
 *
 * ⚠️ 曾用独立类 Lcom/nc/guard/NcGuard;，但那类从未被 inject-javacheck.py
 *   生成 → selftest 抛 UnsatisfiedLinkError 被 catch 吞掉 → 连带跳过
 *   heartbeat（报错四十九）。现挂到已注入的 NcLink 上，与 ncVerify/
 *   heartbeat 同源。
 *
 * 返回值语义：
 *    59     完整链路通过：解锁 → 解密 → 执行 .ncx 代码（见 nc_guard_probe.c）
 *    -1     dladdr 失败（拿不到 so 基址）
 *    -2     .ncx 段定位失败
 *    -3     .nck 段定位失败
 *    -4/-5  .ncx 段为空 / 非 SHF_ALLOC
 *    -6/-7  open so 失败 / slot 读取不足
 *    -8/-10 mprotect 失败（Android 对 SHF_EXECINSTR 页的限制比 Linux 严）
 *    -9     内存分配失败
 *    -11    密文 MAC 校验失败（.ncx/.ncxr 被篡改，或密钥与密文不匹配）
 *    -12    证书/包名不可得（fail-closed：读不到 APK 证书或包名指纹不符）
 *    -100   重入（本进程已自检过）
 *
 * ⚠️ 调用本函数即触发【一次性】解锁。再次调用走幂等分支返回 0
 *   （不再是 59）—— 故自检只调一次。
 */
#include <jni.h>
#include <stdatomic.h>

/* 实现在 nc_guard_boot.c / nc_guard_probe.c（同一 NDK 工程，非 static） */
extern int ncguard_unlock(void);
extern int ncguard_probe(int token);

/* 一次性守门。为什么必须挡第二次：ncguard_unlock() 在槽已擦时走幂等分支
 * 返回 0，无法区分"首次解锁成功"与"槽已空故跳过"→ 会再走一次 probe()，
 * 而首次解锁尾部的 mprotect(RX)/clear_cache 时序会让第二次取指命中
 * I-cache 不一致 → SIGILL（2026-10-17 实测：第一次 59，第二次 Illegal
 * instruction）。自检语义本就是"只验一次"，别去修 unlock 的时序。 */
static atomic_int ncg_selftest_done = 0;

/* 解锁 + 执行密文段代码，返回可判读的回执。
 * 显式 visibility("default")：库是 -fvisibility=hidden 编的，
 * 不加这个 JNI 符号不会被导出，Java 侧找不到。
 * ⚠️ 用短名绑定而非动态注册：后者在 so 加载时机（Application 初始化中）
 *   调 FindClass 会崩，真机实证（见 nc_link.c 同处注释）。 */
#define NC_SELFTEST_DECL \
    __attribute__((visibility("default"))) JNIEXPORT jint JNICALL \
    Java_com_nc_link_NcLink_selftest(JNIEnv *env, jobject thiz)
NC_SELFTEST_DECL {
    int expected = 0;
    if (!atomic_compare_exchange_strong(&ncg_selftest_done, &expected, 1)) {
        return (jint) -100;      /* 已自检过，拒绝重入 */
    }
    int rc = ncguard_unlock();
    if (rc != 0) {
        return (jint) rc;        /* 解锁失败：把失败码透传，别吞 */
    }
    /* 解密成功后才可执行 .ncx 里的代码；契约值 59 见 nc_guard_probe.c */
    return (jint) ncguard_probe(0);
}
