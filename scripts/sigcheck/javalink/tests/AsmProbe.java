import brut.androlib.smali.SmaliBuilder;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.writer.builder.DexBuilder;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;
import java.io.File;

/**
 * AsmProbe — 宿主端 smali 真汇编探针(报错三十一验证的手段)。
 * 用 apktool 内置 SmaliBuilder 把若干 .smali 组装成 dex;
 * 任何语法/寄存器错误在此暴露(exit 2),成功产出 dex 供 androguard 读回。
 * 用法: java AsmProbe <out.dex> <a.smali> [b.smali ...]
 */
public class AsmProbe {
    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: AsmProbe <out.dex> <a.smali> [b.smali ...]");
            System.exit(1);
        }
        DexBuilder dexBuilder = new DexBuilder(new Opcodes(21));
        SmaliBuilder builder = new SmaliBuilder(21);
        for (int i = 1; i < args.length; i++) {
            boolean ok = builder.buildFile(new File(args[i]), dexBuilder);
            if (!ok) {
                System.err.println("ASSEMBLE FAILED: " + args[i]);
                System.exit(2);
            }
        }
        dexBuilder.writeTo(new FileDataStore(new File(args[0])));
        System.out.println("assembled " + (args.length - 1) + " smali -> " + args[0]);
    }
}
