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
            /* .ncguard 段自解密自检(2026-12)：so 已加载,立即触发一次性解锁。
               返回值 59 = 完整链路通过(解锁→解密→执行密文段代码)。
               刻意【不影响主流程】:任何异常/非 59 都只静默记录,不 kill、
               不阻断测量——本自检只是可观测性探针,不是防御支点。
               若将来要把 .ncguard 变成真防御(把 env_check 探针移进去),
               那时才需要 fail-closed。 */
            ncguardSelftest();
            /* 报错四十九(2026-10-16):心跳喂食必须与"测量是否成功"解耦。
               旧形态把 heartbeat()/startHeartbeat() 放在 ncVerify 通过之后——
               测量链抛任何非 ULE Throwable(NameNotFoundException / signingInfo
               为 null 的 NPE / 签名数组空越界,targetSdk 37 下均有现实通道)
               就跳 catch(Throwable) 静默返回 → 一次都不喂 → env_watchdog 把
               "没喂"误判成"Java 壳被删" → 正常包冷启动 ~6s 必杀(真机实证:
               docs/sigcheck_log.txt 三次"Java 心跳丢失" + tombstone 无线程
               NativeGuard$Hb)。so 已加载即开始喂,处置各归各路:
               判决不过 → kill();测量异常 → catch 静默跳过(喂食照常进行)。 */
            NcLink.heartbeat();
            startHeartbeat();
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

    /* ── .ncguard 段自解密自检(2026-12) ────────────────────────────
     * native 侧 com/nc/link/NcLink.selftest() 返回：
     *   59   完整链路通过（解锁→解密→执行 .ncguard 代码）
     *   -100 已自检过（原子守门挡住重入）
     *   负数 解锁失败（段定位/mprotect 等，见 nc_guard_unlock.c）
     * 本方法是纯观测探针：不 kill、不阻断、不改变任何防御行为。
     * 全吞 Throwable——自检本身绝不许成为新崩溃源。 */
    private static void ncguardSelftest() {
        try {
            int r = com.nc.link.NcLink.selftest();
            if (r != 59) {
                android.util.Log.w("ncguard", "selftest rc=" + r);
            }
        } catch (Throwable ignored) {
            /* 自检失败不影响主流程 */
        }
    }

    /* ── Java→Native 心跳(2026-10 借鉴 XopProtector 双向绑定) ──
     * 校验通过后启动 daemon 线程,每 5 秒喂一次 NcLink.heartbeat()。
     * native 侧(nc_link.c)记录时间戳,env_watchdog 超时未喂(armed 后
     * 首喂宽限 90s/之后保活 25s)= Java 层被删/被绕过 → delayed_kill。
     * 这堵住了最大的架构单点:攻击者删掉 c() 调用 → so 不加载 → 全防失效;
     * 有了心跳,"删调用"反而变成自杀(so 加载后心跳停 = 杀)。
     * ⚠️ 必须在 ensureLoaded() 之后、【测量链之前】start(报错四十九):
     *    旧版"ncVerify 通过后才 start"会让测量异常经 catch 静默跳过 → 一次
     *    不喂 → 正常包被误杀。现在 so 一加载就开始喂,判不过/ULE 仍各自 kill。
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
