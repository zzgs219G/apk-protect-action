/**
 * StrDec — dex 层字符串常量解密桩(v2/S2: 纯 XOR + splitmix64 种子现算密钥流)
 *
 * 【本文件是唯一源码真相】
 * smali 由 scripts/string-enc/build-stub.sh 自动生成(javac → d8 → baksmali),
 * 人永远不要手改 StrDec.smali(历史: 报错二十一/二十二/二十五)。
 * 改算法只改本文件,然后重跑 build-stub.sh。
 *
 * 【为什么从 v1 改成 S2】
 * v1 每条解密 = Base64.decode + N 次 MessageDigest.update/digest + intern +
 * ConcurrentHashMap 查表,全包 1.3 万条在 debuggable 解释执行下把冷启动首帧
 * 卡死(2026-09-11 排查结论,见 docs/字符串加密v2重构方案.md §1)。
 * S1 把密钥流预生成为一张全包共享的 byte[] 表(KEYS),运行期读表 XOR;
 * S2 更进一步: 表也不要,只存 8 字节种子,运行期用 splitmix64 现算密钥字节。
 * 全包仅 1 个解密方法 + 0 张表,比第三方方案(每类一张 short[])更轻。
 *
 * 【密文形态(构建期 encrypt-strings.py 生成)】
 *   const-string vX, "<b64>"
 *   invoke-static/range {vX .. vX}, Lcom/nc/strdec/StrDec;->d(Ljava/lang/String;)Ljava/lang/String;
 * 其中 b64 = Base64( offset_be24 || cipher_bytes )
 *   offset  — 该条明文的 UTF-8 字节在'全包虚拟密钥流'里的起始下标(3 字节大端)
 *   cipher  — plain_utf8[k] ^ keyByte(SEED, offset + k)
 * 分配器保证全包各条密文的 [offset, offset+len) 区段互不重叠。
 *
 * 【密钥流定义(Python/Java 必须逐字节一致,由 P3 对拍锁定)】
 *   splitmix64:  z ^= z >>> 30; z *= 0xBF58476D1CE4E5B9L;
 *                z ^= z >>> 27; z *= 0x94D049BB133111EBL; return z ^ (z >>> 31);
 *   keyByte(seed, i) = (mix64(seed + (i >>> 3) * GAMMA) >>> ((i & 7) * 8)) & 0xFF
 *   GAMMA = 0x9E3779B97F4A7C15L
 * 易错点: ① Java 用 >>>(无符号右移),long 溢出天然 = mod 2^64;
 *         ② Python 侧每步 & MASK64,且 >> 只作用在已掩码的非负数上。
 *
 * 【SEED 的注入方式(结构性约束,勿改形态)】
 * build-stub.sh 只在编译期用 0L 顶位,smali 里长这样:
 *   .field private static final SEED:J = 0x0L
 * encrypt-strings.py 按此结构定位该行、只替换初值字面量(不新增字段)。
 * 绝不允许把种子写成运行期回填: 那需要把解密提前到 <clinit>,而字段常量
 * 回填链必须在 SEED 就绪之后执行 —— 顺序会被迫打乱(报错二十四同型)。
 */
public final class StrDec {

    /** splitmix64 黄金比例增量,与 Python 侧 GAMMA 同常量。 */
    private static final long GAMMA = 0x9E3779B97F4A7C15L;

    /** 全包密钥种子,构建期由 encrypt-strings.py 按结构改写本行初值(8 字节随机)。 */
    private static final long SEED = 0L; /*%SEED_LITERAL%*/

    private StrDec() {}

    /** splitmix64 终混合。Java long 溢出即 mod 2^64,与 Python 的 & MASK64 天然对齐。 */
    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    /** 密钥流第 i 个字节,O(1) 现算,无需任何表。 */
    private static int keyByte(long seed, long i) {
        long w = mix64(seed + (i >>> 3) * GAMMA);
        return (int) ((w >>> ((i & 7L) * 8)) & 0xFFL);
    }

    /** 解密:payload = Base64( offset_be24 || cipher )。失败时原样返回(与 v1 兜底一致)。 */
    public static String d(String payload) {
        try {
            byte[] raw = android.util.Base64.decode(payload, android.util.Base64.NO_WRAP);
            if (raw.length < 4) {
                return payload;
            }
            long offset = ((long) (raw[0] & 0xFF) << 16)
                    | ((long) (raw[1] & 0xFF) << 8)
                    | (long) (raw[2] & 0xFF);
            int len = raw.length - 3;
            // 必须用 byte[] + new String(byte[], "UTF-8"):v1/S1 草稿用 char[] +
            // new String(char[]) 的语义是 Latin-1,中文/emoji 多字节 UTF-8 会乱码。
            byte[] out = new byte[len];
            for (int k = 0; k < len; k++) {
                out[k] = (byte) ((raw[k + 3] & 0xFF) ^ keyByte(SEED, offset + k));
            }
            return new String(out, "UTF-8");
        } catch (Throwable t) {
            // 兜底与 v1 一致:解密失败原样返回,绝不让字符串解密把业务炸掉
            return payload;
        }
    }
}
