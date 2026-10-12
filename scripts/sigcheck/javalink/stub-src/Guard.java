package com.test.placeholder;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.os.Process;
import com.nc.link.NcLink;
import java.security.MessageDigest;

/**
 * Java 层判决式签名校验 · 测量与执行 · 语义真相源(人读参照)
 *
 * ⚠️ 实际包名/类名由 inject-javacheck.py 按宿主混淆状态自适应生成
 *    (R8 短名包 → 短名风格;普通包 → app 包名派生),本文件只是逻辑参照。
 *
 * 三条分支(与用户对齐的"联动不削弱"原则):
 *   - 判定不过            → 杀(快死/可见,so 侧另有延时暗杀兜底)
 *   - UnsatisfiedLinkError → 杀(fail-closed:so 缺失 = 防线不成立,
 *                            loadLibrary 由此成为"承重墙")
 *   - 其他 Throwable      → 静默跳过(测量环境异常不误杀;
 *                            sig_check.c 的独立校验仍是权威)
 */
public final class Guard {

    private Guard() {
    }

    public static void c(Context ctx) {
        try {
            /* 报错四十二:so 加载必须是第一步——它排在测量链之后时,测量抛
               任何非 ULE 异常都会走 catch(Throwable) 静默跳过,ensureLoaded
               永不执行 → so 永不加载 → sig_check.c constructor 永不运行,
               两层防线静默全灭(真机实证:删净 so 自带 loadLibrary 注入点后
               换 key 重签不杀)。先加载后测量,so 层校验不再受测量摆布。 */
            NcLink.ensureLoaded();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            PackageManager pm = ctx.getPackageManager();
            String pkg = ctx.getPackageName();
            byte[] der;
            if (Build.VERSION.SDK_INT >= 28) {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES);
                SigningInfo si = pi.signingInfo;
                Signature[] sigs = si.getApkContentsSigners();
                der = sigs[0].toByteArray();
            } else {
                PackageInfo pi = pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES);
                der = pi.signatures[0].toByteArray();
            }
            byte[] fp = md.digest(der);   /* SHA256(certDER) */
            byte[] t1 = md.digest(fp);    /* SHA256(fp) —— 送 so 判决的只有它 */
            boolean ok = NcLink.ncVerify(t1);
            if (!ok) {
                kill();
            }
        } catch (UnsatisfiedLinkError e) {
            kill();
        } catch (Throwable e) {
            /* 静默跳过(仅损失 Java 判决;so 已加载,constructor 校验照跑) */
        }
    }

    private static void kill() {
        Process.killProcess(Process.myPid());
    }
}
