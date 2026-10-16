/* nc_guard_jni.c — .ncguard 机制的 JNI 自检入口（非冻结，可随时删）
 *
 * 为什么需要它：e97a761 落地后，真机跑加固包【没有任何现象】可观测——
 *   -fvisibility=hidden 把 ncguard_unlock/ncguard_probe 全藏了，Java 侧
 *   native 侧都找不到入口；.nckey 密钥槽在产物里是满的（未擦 = 没跑过）。
 *   "不闪退"因此什么都证明不了（那段密文根本没被执行）。
 *
 * 本文件给一个显式入口，让 CI/真机能拿到【可判读的回执】：
 *
 *   Java:  NcGuard.selftest()
 *   C:     jint Java_com_nc_guard_NcGuard_selftest(JNIEnv*, jobject)
 *
 *   返回值语义（Android 上才能测出的部分）：
 *     59     ✅ 完整链路通过：解锁 → 解密 → 执行 .ncguard 代码
 *     -1     dladdr 失败（拿不到 so 基址）
 *     -2     .ncguard 段定位失败
 *     -3     .nckey 段定位失败
 *     -7/-8  mprotect 失败（Android 对 SHF_EXECINSTR 页的限制比 Linux 严）
 *     -9     内存分配失败
 *     -10    恢复 PROT_EXEC 失败
 *     其它   见 ncguard_unlock() 内部注释
 *
 *   ⚠️ 调用本函数即触发【一次性】解锁；解锁后 .nckey 槽被擦除，再次调用
 *      会因"槽已空"走幂等分支返回 0（不再是 59）。故自检只调一次。
 *
 * 名字里的 com/nc/guard 由 protect.sh 的 Java 侧注入保持同包；若 Java 侧
 * 未注入对应类，本导出函数只是不被调用，不影响其它任何东西。
 */
#include <jni.h>
#include <stdatomic.h>

/* 来自 nc_guard_unlock.c / nc_guard_probe.c（同一 NDK 工程，非 static） */
extern int ncguard_unlock(void);
extern int ncguard_probe(int token);

/* ── 一次性守门 ─────────────────────────────────────────────────────
 * 为什么必须挡第二次：ncguard_unlock() 在槽已擦（磁盘 magic 清零）时走
 * 幂等分支返回 0，此时 .ncguard 虽在内存里是明文，但 selftest() 无法区分
 * "首次解锁成功"(rc=0) 与"槽已空故跳过"(rc 同样 0) → 会再走一次
 * probe() → 而首次解锁尾部的 mprotect(RX)/clear_cache 时序会让第二次取指
 * 命中 I-cache 不一致 → SIGILL（2026-10-17 实测：第一次 59 成功，第二次
 * Illegal instruction）。
 * 自检语义本就是"只验一次"，用原子守门挡住重入，别去修 unlock 的时序
 * （那是从 Xop 抄来的、经过真机验证的顺序）。
 * 副作用：重入返回 -100（自定义码，不和 unlock 的负数码混淆）。 */
static atomic_int ncg_selftest_done = 0;

/* 解锁 + 执行密文段代码，返回可判读的回执。
 * 显式 visibility("default")：库是 -fvisibility=hidden 编的，
 * 不加这个 JNI 符号不会被导出，Java 侧照旧找不到。 */
__attribute__((visibility("default")))
JNIEXPORT jint JNICALL
Java_com_nc_guard_NcGuard_selftest(JNIEnv *env, jobject thiz) {
    int expected = 0;
    if (!atomic_compare_exchange_strong(&ncg_selftest_done, &expected, 1)) {
        return (jint) -100;      /* 已自检过，拒绝重入 */
    }
    int rc = ncguard_unlock();
    if (rc != 0) {
        return (jint) rc;        /* 解锁失败：把失败码透传，别吞 */
    }
    /* 解密成功后才可执行 .ncguard 里的代码；契约值见 nc_guard_probe.c */
    return (jint) ncguard_probe(0);
}
