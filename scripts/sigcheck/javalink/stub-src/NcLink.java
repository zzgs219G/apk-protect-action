package com.nc.link;

/**
 * nc_link 桥接类 · 语义真相源(人读参照)
 *
 * ⚠️ 宿主无 d8,实际注入的 smali 由 inject-javacheck.py 按本文件语义生成,
 *    并由 tests/test-javacheck.sh 做 SmaliBuilder 真汇编 + androguard 读回验证。
 * ⚠️ 类名/方法名参与 JNI 短名绑定(Java_com_nc_link_NcLink_ncVerify),
 *    改名必须同步 nc_link.c,否则运行期 UnsatisfiedLinkError。
 */
public final class NcLink {

    private NcLink() {
    }

    /** 幂等加载 libnc.so(重复调用为 no-op);so 缺失时抛 UnsatisfiedLinkError。 */
    public static void ensureLoaded() {
        System.loadLibrary("nc");
    }

    /**
     * 判决入口:入参 t1 = SHA256(SHA256(实测证书 DER))(双重哈希,由 Guard 计算)。
     * 返回 true = 通过(或调试模式槽位全零跳过);false = 不过(Guard 执行杀)。
     * 标准答案常驻 so 内部,从不出 now——这就是"判决式"与"答案下发对比"的区别。
     */
    public static native boolean ncVerify(byte[] t1);

    /**
     * 心跳喂食入口(2026-10 借鉴 XopProtector 双向绑定):Guard 校验通过后
     * 启动 daemon 线程每 5 秒喂一次。native 侧(nc_link.c)先校验调用者身份
     * (IsSameObject 锁死 NcLink 本类,防反射/重绑定冒充),通过后记录时间戳;
     * env_check.c 的 watchdog 在 armed 后首喂宽限 90s / 之后保活 25s,
     * 超时未喂 = Java 壳被删/被绕过 → delayed_kill。
     * ⚠️ 改名必须同步 nc_link.c 的 Java_com_nc_link_NcLink_heartbeat,
     *    否则运行期 UnsatisfiedLinkError(喂循环吞掉,watchdog 超时兜底)。
     */
    public static native void heartbeat();

    /**
     * .ncguard 段自解密自检(2026-12)。
     * 返回 59 = 完整链路通过(解锁→解密→执行 .ncguard 里的密文代码)；
     * -100 = 已自检过(原子守门挡重入)；负数 = 解锁失败，见 nc_guard_unlock.c。
     * 纯观测探针，不参与任何防御判定。改名必须同步 nc_guard_jni.c。
     */
    public static native int selftest();
}
