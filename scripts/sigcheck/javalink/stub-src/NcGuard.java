package com.nc.guard;

/**
 * .ncguard 段自解密自检入口 · 语义真相源(人读参照)
 *
 * ⚠️ 宿主无 d8,实际注入的 smali 由 inject-javacheck.py 按本语义生成
 *    (模板里的 SELFTEST_DESC 常量),本文件是 javac 语义校验与改名时的对照。
 * ⚠️ 类名/方法名参与 JNI 短名绑定 —— native 侧 nc_guard_jni.c 的函数名必须是
 *    Java_com_nc_guard_NcGuard_selftest,改任何一边都要同步另一边,
 *    否则运行期 UnsatisfiedLinkError(自检失败被 catch 吞掉,主流程不受影响,
 *    但你会失去"机制是否工作"的唯一观测点)。
 *
 * 返回值语义(全部可判读,负数为 ncguard_unlock() 的失败码):
 *   59    ✅ 完整链路通过:解锁 → 解密 → 执行 .ncguard 里的代码
 *   -100   已自检过(原子守门挡住重入;第二次调用是预期行为,不是错误)
 *   -1     dladdr 失败,拿不到 so 基址
 *   -2     .ncguard 段定位失败(段名不符,或链接器没保留它)
 *   -3     .nckey 段定位失败
 *   -7/-8  读 slot / mprotect(RWX) 失败 —— Android 对 SHF_EXECINSTR 页的
 *          限制比 Linux 严,这一层最容易在真机上暴露差异
 *   -9     内存分配失败
 *   -10    恢复 PROT_EXEC 失败
 *
 * 设计约束:这是【观测探针】不是防御支点。调用方(Guard.ncguardSelftest)必须
 * 全吞 Throwable、不得 kill、不得阻断测量链。若将来把 env_check 的探针也移进
 * .ncguard 并要 fail-closed,那是另一次设计,需重新评估误杀面。
 */
public final class NcGuard {

    private NcGuard() {
    }

    /** 触发一次性解锁并执行 .ncguard 代码,返回可判读回执。 */
    public static native int selftest();
}
