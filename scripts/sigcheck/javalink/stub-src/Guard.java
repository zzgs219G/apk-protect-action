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

    /* ── Java→Native 心跳(2026-10 借鉴 XopProtector 双向绑定) ──
     * 校验通过后启动 daemon 线程,每 5 秒喂一次 NcLink.heartbeat()。
     * native 侧(nc_link.c)记录时间戳,env_watchdog 超时未喂(armed 后
     * 首喂宽限 90s/之后保活 25s)= Java 层被删/被绕过 → delayed_kill。
     * 这堵住了最大的架构单点:攻击者删掉 c() 调用 → so 不加载 → 全防失效;
     * 有了心跳,"删调用"反而变成自杀(so 加载后心跳停 = 杀)。
     * ⚠️ 必须在 ncVerify 通过之后才 start(判不过/ULE 直接 kill,无需喂);
     *    单发守卫防重复开线程;daemon 保证不拖进程退出;
     *    循环内 Throwable 全吞(Xop 同款:喂失败 native 侧超时自会兜底)。 */
    private static volatile boolean heartbeatStarted;

    private static void startHeartbeat() {
        if (heartbeatStarted) {
            return;
        }
        heartbeatStarted = true;
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        NcLink.heartbeat();
                        Thread.sleep(5000);
                    } catch (Throwable ignored) {
                        /* 喂失败继续循环;native 侧超时自会处置 */
                    }
                }
            }
        });
        t.setDaemon(true);
        t.start();
    }
}
