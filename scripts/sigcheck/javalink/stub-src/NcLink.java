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
}
