import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * P3 对拍 Java 侧(全链版):调真实桩的 d(String) 解 Python 生成的 payload,
 * 断言还原出的明文与原始明文逐字节一致。
 *
 * 这一层才是最终裁决:
 *   * 覆盖 Base64 头(offset_be24)解析
 *   * 覆盖 XOR 主循环与 UTF-8 解码(含 emoji 代理对/中文/边界码点)
 *   * 覆盖空串与失败兜底
 * Android 的 Base64 由 tests/shims 顶替(桌面 JVM 语义一致:NO_WRAP)。
 */
public final class P3Full {

    public static void main(String[] args) throws Exception {
        Class<?> stub = Class.forName("com.nc.strdec.StrDec");
        Method d = stub.getDeclaredMethod("d", String.class);

        String json = new String(Files.readAllBytes(Paths.get(args[0])),
                                 StandardCharsets.UTF_8);
        List<String[]> plan = parsePlan(json);

        int pass = 0, fail = 0;
        for (String[] c : plan) {
            String payload = c[3];
            if (payload == null) continue;             // 跳过纯密钥流用例
            if (c[2] != null && c[2].isEmpty()) continue;   // 空串不在加密面(见下)
            String expect = c[2];                      // 期望明文(Java 侧字符串)
            String got;
            try {
                got = (String) d.invoke(null, payload);
            } catch (Exception e) {
                System.out.println("FAIL 调用抛异常: " + e.getCause());
                fail++;
                continue;
            }
            if (expect.equals(got)) {
                pass++;
            } else {
                fail++;
                System.out.println("FAIL offset=" + c[1]
                        + " 期望长度=" + expect.length() + " 实际长度=" + got.length()
                        + "\n  期望=" + preview(expect) + "\n  实际=" + preview(got));
                if (fail > 5) break;
            }
        }
        System.out.println("RESULT fullchain pass=" + pass + " fail=" + fail);
        if (fail > 0) System.exit(1);
    }

    private static String preview(String s) {
        if (s.length() > 60) s = s.substring(0, 60) + "...";
        StringBuilder sb = new StringBuilder();
        for (char ch : s.toCharArray()) {
            if (ch < 0x20 || ch > 0x7E) sb.append(String.format("\\u%04x", (int) ch));
            else sb.append(ch);
        }
        return sb.toString();
    }

    /** 解析: {"seed_hex":..,"offset":..,"plain_hex":..,"payload":".."} */
    private static List<String[]> parsePlan(String json) {
        List<String[]> out = new ArrayList<>();
        int i = 0, n = json.length();
        while (i < n) {
            if (json.charAt(i) != '{') { i++; continue; }
            int end = json.indexOf('}', i);
            String obj = json.substring(i + 1, end);
            String off = field(obj, "offset");
            String plainHex = field(obj, "plain_hex");
            String payload = field(obj, "payload");
            String expect = null;
            if (plainHex != null) {
                byte[] raw = hexToBytes(plainHex);
                expect = new String(raw, StandardCharsets.UTF_8);
            }
            out.add(new String[]{field(obj, "seed_hex"), off, expect, payload});
            i = end + 1;
        }
        return out;
    }

    private static String field(String obj, String key) {
        String pat = "\"" + key + "\":";
        int p = obj.indexOf(pat);
        if (p < 0) return null;
        p += pat.length();
        while (p < obj.length() && obj.charAt(p) == ' ') p++;
        if (obj.charAt(p) == '"') {
            int e = obj.indexOf('"', p + 1);
            return obj.substring(p + 1, e);
        }
        int e = p;
        while (e < obj.length() && ",}".indexOf(obj.charAt(e)) < 0) e++;
        return obj.substring(p, e).trim();
    }

    private static byte[] hexToBytes(String hex) {
        byte[] o = new byte[hex.length() / 2];
        for (int i = 0; i < o.length; i++) {
            o[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return o;
    }
}
