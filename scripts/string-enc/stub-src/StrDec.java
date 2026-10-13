/**
 * StrDec — dex 层字符串常量解密桩(S2: 纯 XOR + splitmix64 种子现算密钥流;L1 缓存)
 *
 * 本文件是唯一源码真相:算法只改这里,然后重跑 build-stub.sh 再生 smali;
 * 人永远不要手改 StrDec.smali(报错二十一/二十二/二十五)。
 * 密文形态 / 密钥流定义 / SEED 注入契约 / L1 缓存设计 / 历史教训:
 * 全部见 scripts/string-enc/README.md(改本文件前必读其"易错点"一节)。
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

    /** 解密:payload = Base64( offset_be24 || cipher )。失败时原样返回。 */
    public static String d(String payload) {
        try {
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
        } catch (Throwable t) {
            // 兜底与 v1 一致:解密失败原样返回;失败结果不进缓存(防毒缓存)
            return payload;
        }
    }
}
