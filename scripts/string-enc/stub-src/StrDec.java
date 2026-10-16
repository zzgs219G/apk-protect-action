/**
 * StrDec — dex 层字符串常量解密桩(S2: 纯 XOR + splitmix64 种子现算密钥流;L1 缓存)
 *
 * 本文件是唯一源码真相:算法只改这里,然后重跑 build-stub.sh 再生 smali;
 * 人永远不要手改 StrDec.smali(报错二十一/二十二/二十五)。
 * 密文形态 / 密钥流定义 / SEED 注入契约 / L1 缓存设计 / 历史教训:
 * 全部见 scripts/string-enc/README.md(改本文件前必读其"易错点"一节)。
 *
 * 【两层拆分:壳 d() / 内核 dn()】2026-10 字符串加密↔dex2c 联动引入。
 *   - d()  解密入口,只做 try/catch 兜底,再转调 dn()。
 *   - dn() 算法本体,方法体内【不含任何 try/catch】。
 * 拆分后:算法/种子/常量全部随联动转译进 so,dex 内不再有可读实现;
 * 防崩语义不变 —— 密文损坏时 dn() 抛异常,由 d() 捕获后原样返回密文。
 *
 * 【2026-12 更正】原注释称"dn() 必须无 try/catch 才能转译,否则 dex2c
 * 不支持异常表"——该说法已被实测证伪。T1~T8 八个 try/catch 形态验证
 * dex2c v1.0.2 对异常表的支持:全部转译成功,生成 EX_LandingPad +
 * d2c_is_instance_of 分发,catch(Throwable) 兜底在 C 侧完整保留
 * (goto 返回原密文)。故 stringenc↔dex2c 联动已改为【全抽】:
 * filter 覆盖 d/dn/mix64/keyByte 四个方法,d() 的 try/catch 壳也进 so。
 * 保留拆分的原因不再是转译限制,而是:①算法与兜底分层可读;
 * ②失败兜底语义在 C 侧仍由 catch(Throwable) 分发承担,与 Java 等价;
 * ③dn() 是报错二十二的寄存器自检锚点(真正调用系统 Base64 解码的方法)。
 */
public final class StrDec {

    /** splitmix64 黄金比例增量,与 Python 侧 GAMMA 同常量。 */
    private static final long GAMMA = 0x9E3779B97F4A7C15L;

    /** 全包密钥种子,构建期由 encrypt-strings.py 按结构改写本行初值(8 字节随机)。
     *  注:本行(含行尾的 SEED_LITERAL 标记)是 build-stub.sh 的替换锚点,勿改写法。 */
    private static final long SEED = 0L; /*%SEED_LITERAL%*/

    /** L1 解密缓存(README"设计"节):命中零分配 + intern 语义;失败/退化结果不进缓存。 */
    private static final java.util.concurrent.ConcurrentHashMap CACHE
            = new java.util.concurrent.ConcurrentHashMap();  // raw:泛型会产出 Signature 注解,撞桩骨架守卫
    private static final int CACHE_CAP = 30000;

    private StrDec() {}

    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    private static int keyByte(long seed, long i) {
        long w = mix64(seed + (i >>> 3) * GAMMA);
        return (int) ((w >>> ((i & 7L) * 8)) & 0xFFL);
    }

    /** 解密:payload = Base64( offset_be24 || cipher )。失败时原样返回。
     *  【壳】try/catch 兜底,实际计算转调 dn()。
     *  注:dex2c 已实测支持异常表,故本方法在 stringenc↔dex2c 全抽联动时
     *  也会随 filter 进入 so;C 侧兜底由 d2c_is_instance_of(Throwable)
     *  分发承担,与 Java catch 等价。 */
    public static String d(String payload) {
        try {
            return dn(payload);
        } catch (Throwable t) {
            // 兜底与 v1 一致:解密失败原样返回;失败结果不进缓存(防毒缓存)
            return payload;
        }
    }

    /** 解密内核:算法本体(与拆分前的 d() 逐字一致),【方法体内无 try/catch】。
     *  本方法是报错二十二的寄存器自检锚点(真正调用系统 Base64 解码的方法),
     *  也是 stringenc↔dex2c 联动转译进 libnc.so 的目标。
     *  失败语义:本方法不捕获异常,任何异常向上冒泡给 d() 兜底。 */
    public static String dn(String payload) throws java.io.UnsupportedEncodingException {
        String hit = (String) CACHE.get(payload);
        if (hit != null) {
            return hit;
        }
        byte[] raw = android.util.Base64.decode(payload, android.util.Base64.NO_WRAP);
        if (raw.length < 4) {
            return payload;
        }
        long offset = ((long) (raw[0] & 0xFF) << 16)
                | ((long) (raw[1] & 0xFF) << 8)
                | (long) (raw[2] & 0xFF);
        int len = raw.length - 3;
        byte[] out = new byte[len];   // 必须 byte[]+UTF-8 构造(char[] 是 Latin-1 语义,中文会乱码)
        // 块展开:一个 mix64 产 8 字节密钥流;内层 j 从 (offset+k)&7 起(对齐陷阱见 README),
        // 尾部不足 8 字节时多余的位丢弃。
        for (int k = 0; k < len; ) {
            long w = mix64(SEED + ((offset + k) >>> 3) * GAMMA);
            for (int j = (int) ((offset + k) & 7L); j < 8 && k < len; j++, k++) {
                int kb = (int) (w >>> (j * 8));
                out[k] = (byte) ((raw[k + 3] & 0xFF) ^ (kb & 0xFF));
            }
        }
        String decrypted = new String(out, "UTF-8");
        if (CACHE.size() < CACHE_CAP) {   // 上限守卫:racy 检查,极端并发下略超无害
            CACHE.put(payload, decrypted);
        }
        return decrypted;
    }
}
