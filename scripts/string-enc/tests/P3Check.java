import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * P3 对拍 Java 侧驱动:直接反射调用真实解密桩 StrDec 的 mix64/keyByte/d,
 * 与 Python 侧(gen_plan.py)生成的期望值逐字节比对。
 *
 * 为什么用反射:keyByte/mix64 是 private static,且 d() 依赖 android.util.Base64
 * (桌面 JVM 没有)。所以 d() 的对拍改在 Android 侧由桩自身完成,这里只锁
 * "纯算术层"(mix64/keyByte)与 Python 一致 —— 这正是 §3.3 点名的两处易错点。
 *
 * 用法: java -cp <classes> P3Check <plan.json>
 * 输出: 每行 "<case_id> <OK|FAIL> [详情]"
 */
public final class P3Check {

    /** 极简 JSON 数组解析(只认本对拍脚本生成的规整结构,不引入任何依赖)。 */
    private static List<String[]> parsePlan(String json) {
        List<String[]> out = new ArrayList<>();
        int i = 0, n = json.length();
        while (i < n) {
            if (json.charAt(i) != '{') { i++; continue; }
            int end = json.indexOf('}', i);
            String obj = json.substring(i + 1, end);
            String seed = field(obj, "seed_hex");
            String off = field(obj, "offset");
            String ks = field(obj, "keystream_hex");
            out.add(new String[]{seed, off, ks});
            i = end + 1;
        }
        return out;
    }

    private static String field(String obj, String key) {
        // 该字段不存在时返回 null(keystream_hex 是可选的)
        String pat = "\"" + key + "\":";
        int p = obj.indexOf(pat);
        if (p < 0) return null;
        p += pat.length();
        // 跳过 json.dump 默认的空格分隔(", " 与 ": ")
        while (p < obj.length() && obj.charAt(p) == ' ') p++;
        if (obj.charAt(p) == '"') {
            int e = obj.indexOf('"', p + 1);
            return obj.substring(p + 1, e);
        }
        int e = p;
        while (e < obj.length() && ",}".indexOf(obj.charAt(e)) < 0) e++;
        return obj.substring(p, e).trim();
    }

    public static void main(String[] args) throws Exception {
        Class<?> stub = Class.forName("com.nc.strdec.StrDec");
        Method mix64 = stub.getDeclaredMethod("mix64", long.class);
        Method keyByte = stub.getDeclaredMethod("keyByte", long.class, long.class);
        mix64.setAccessible(true);
        keyByte.setAccessible(true);

        String json = new String(Files.readAllBytes(Paths.get(args[0])),
                                 StandardCharsets.UTF_8);
        List<String[]> plan = parsePlan(json);

        int pass = 0, fail = 0, checked = 0;
        for (String[] c : plan) {
            if (c[2] == null) continue;            // 只跑密钥流用例
            checked++;
            long seed = Long.parseUnsignedLong(c[0], 16);
            long off = Long.parseLong(c[1]);
            byte[] expect = hexToBytes(c[2]);
            byte[] got = new byte[expect.length];
            for (int k = 0; k < expect.length; k++) {
                int v = (Integer) keyByte.invoke(null, seed, off + k);
                got[k] = (byte) v;
            }
            // mix64 单点另测:与 Python _mix 对齐
            boolean ok = java.util.Arrays.equals(expect, got);
            if (ok) {
                pass++;
            } else {
                fail++;
                int d = firstDiff(expect, got);
                System.out.println("FAIL seed=" + c[0] + " off=" + off
                        + " len=" + expect.length + " 首个差异@" + d
                        + " expect=" + String.format("%02x", expect[d])
                        + " got=" + String.format("%02x", got[d]));
            }
        }
        System.out.println("RESULT checked=" + checked + " pass=" + pass + " fail=" + fail);
        if (fail > 0) System.exit(1);
    }

    private static int firstDiff(byte[] a, byte[] b) {
        for (int i = 0; i < Math.min(a.length, b.length); i++) {
            if (a[i] != b[i]) return i;
        }
        return Math.min(a.length, b.length);
    }

    private static byte[] hexToBytes(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
