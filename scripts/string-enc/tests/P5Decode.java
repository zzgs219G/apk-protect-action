import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

/**
 * P5 端到端闭环驱动:读「加密脚本真实产物里抽出来的密文清单」,用编译后的真实桩
 * 逐条解密,断言还原出构建期的原文。
 *
 * 与 P3Full 的区别(为什么还要一个):
 *   P3Full 的 payload 是 gen_plan.py 现算的,只证明"算法一致";
 *   P5Decode 的 payload 是 encrypt-strings.py 真写进 smali 的字节,证明
 *   「脚本的 offset 分配 + 桩的 offset 解析」这条链也一致 —— 即 A3 的关键:
 *   offset 不复用。若分配器退化(每类从 0 重来),同一 offset 会配两把不同密钥,
 *   此处必然解错。
 *
 * 输入文件每行: <期望明文(Java 转义)>\t<payload>
 */
public final class P5Decode {

    public static void main(String[] args) throws Exception {
        Class<?> stub = Class.forName("com.nc.strdec.StrDec");
        Method d = stub.getDeclaredMethod("d", String.class);

        List<String> lines = Files.readAllLines(Paths.get(args[0]),
                                                StandardCharsets.UTF_8);
        int pass = 0, fail = 0;
        for (String line : lines) {
            if (line.isEmpty()) continue;
            int tab = line.indexOf('\t');
            if (tab < 0) continue;
            String expect = unescape(line.substring(0, tab));
            String payload = line.substring(tab + 1);
            String got = (String) d.invoke(null, payload);
            if (expect.equals(got)) {
                pass++;
            } else {
                fail++;
                System.out.println("FAIL payload=" + payload
                        + "\n  期望=" + preview(expect) + "\n  实际=" + preview(got));
            }
        }
        System.out.println("RESULT p5decode pass=" + pass + " fail=" + fail);
        if (fail > 0) System.exit(1);
    }

    private static String unescape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            if (ch == '\\' && i + 1 < s.length()) {
                char n = s.charAt(++i);
                if (n == 'n') sb.append('\n');
                else if (n == 't') sb.append('\t');
                else if (n == 'r') sb.append('\r');
                else if (n == '\\') sb.append('\\');
                else if (n == 'u') {
                    sb.append((char) Integer.parseInt(s.substring(i + 1, i + 5), 16));
                    i += 4;
                } else sb.append(n);
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
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
}
