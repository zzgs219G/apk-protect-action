/*
 * nc_link.c — Java 层判决式签名联动(2026-XX 用户需求,新文件,不改动 sig_check.c)
 *
 * 协议(与 Java 侧 inject-javacheck.py 生成的 Guard/NcLink 对应):
 *   1. Java 用 PackageManager 实测当前安装包签名 → fp = SHA256(certDER)
 *   2. Java 再算 t1 = SHA256(fp) 并经 JNI 送入本模块
 *   3. 本模块还原存储形态: out[i] = t1[i] ^ SIG_SALT[i%16] ^ (i*0x9E & 0xFF)
 *      恒定时间比对 out == SIG_HASH_STORED → 返回判定
 *
 * 设计红线(与用户对齐的"联动不削弱"原则):
 *   - 标准答案(SIG_HASH_STORED)全程不出 so,Java 层只拿"过/不过"一个结论;
 *   - 本模块【只判不杀】:杀由 Java 侧执行(快死/可见),与 sig_check.c 的
 *     延时暗杀相互独立 —— 攻击者 patch 本函数返回恒真,只能废掉 Java 这条
 *     快线,sig_check 的独立校验(直读 APK 文件)不受影响;
 *   - so 缺失时 Java 侧拿不到结论 → fail-closed(loadLibrary 从"可删开关"
 *     变"承重墙"),这是本模块存在的第一意义;
 *   - 与 sig_check.c 的派生公式逐字节同源(生成侧 make-sig-hash.sh 唯一真相),
 *     两侧一致性由对拍测试钉死(tests/test-javacheck.sh 内 host 编译场景)。
 *
 * 调试模式:SIG_HASH_STORED 全零 → 返回真(与 sig_check.c 的 slot 判定同语义)。
 * 零日志设计:本文件不含任何字符串常量(strings 扫 so 零语义泄露)。
 */

/* 心跳接口(实现在本文件下方;env_check.c 的 watchdog 调用检查端)
 * nc_heartbeat_arm_constructor 供 so constructor(env_check.c / sig_check.c)调用——
 * 2026-10-16 修复:武装点从「首次喂」移到「so 加载」,
 * 删喂食调用从「永久沉默」变成「倒计时死刑」。 */
void nc_heartbeat_touch(void);
int nc_heartbeat_expired(void);
void nc_heartbeat_arm_constructor(void);

#include <jni.h>
#include <stddef.h>
#include <time.h>
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移 */
#include "sig_hash.h"

/* ── 判决核心进加密段（2026-10-19，修实测报告 §8.1 最致命缺陷）───────
 *
 * 实测报告（docs/so层防御/简盒-so层静态防御实测报告.md §3.6/§8.1）指控：
 *   加密了壳（ncVerify 转发器），把核留在明文——
 *   真正的判定算法 nc_verify_t1 与两张表 SIG_SALT/SIG_HASH_STORED
 *   全在 .rodata，攻击者 `od` 一条命令就能读出来，反问出通过值。
 *   实测代价：报告作者据此 5 分钟反推出 32 字节通过凭据。
 *
 * 本处修复把【判定函数 + 两张表】一并标进 .ncx 段，运行期由
 * nc_guard_boot.c 解锁后才可执行/可读：
 *   - 未解锁时它们是密文 → objdump 读到 <unknown>，od 读到随机字节
 *   - 解锁后才参与判定（触发点：NcLink.selftest → ncguard_unlock）
 *
 * ⚠️ 三条纪律（违反任一即死锁或崩溃）：
 *   ① ncVerify / heartbeat 这两个 JNI 入口【绝不能】进 .ncx——
 *      它们是 unlock 的调用方，锁进去 = 开锁器被锁进箱子 = 死锁。
 *      本文件只标判决核心，不标 JNI 入口。
 *   ② 宿主测试（NCLINK_HOST_TEST）下必须【不标段】：宿主 clang 没有
 *      解锁设施，标了段就读到密文 → 测试假红。用宏条件化。
 *   ③ 表必须 retain：lib-ndk.sh 的 LOCAL_LDFLAGS 含 -Wl,--gc-sections，
 *      无引用会被连段回收（报错十一同款）。
 *
 * 性能：零开销。段标记只是链接期属性，判定逻辑与数据布局不变；
 * 解锁本身只在 constructor 跑一次（实测 104 us，其中 RC4 占 102 us）。
 */
/* 开关只有一个：NC_GUARD_SECTIONED。
 * 为什么不用 __ANDROID__ 自动判断——那样宿主端任何一次"想验证段布局"
 * 的编译都会踩坑（标了段却没人解锁 → 读到密文 → 假红）。显式开关让
 * "我要标段"成为必须说出口的事，protect.sh 负责定义它。 */
#if defined(NC_GUARD_SECTIONED) && !defined(NCLINK_HOST_TEST)
#  define NC_VERIFY_SECTION __attribute__((section(NC_SEC_CODE), retain, used))
#else
#  define NC_VERIFY_SECTION            /* 宿主测试/普通宿主构建：不标段 */
#endif

/* 表进加密段的宏：与函数同理，但额外要求 used+retain（防 gc-sections）。
 *
 * ⚠️ 2026-10-19 实测踩坑（必须记住）：表【不能】与函数放同一个段。
 *    clang 报 `'nc_verify_t1' causes a section type conflict with 'SIG_SALT'`
 *    —— 因为 .ncx 是 AXR（可执行）段，而 SIG_SALT 是 const 数据，
 *    LLVM 拒绝让同一段既装代码又装只读数据。
 *    解法：数据单独进 .ncxr（AWR，不可执行），由锁箱器一并加密。
 *    这也更合理——代码段解出来是 RX，数据段解出来是 R，权限各自最小。 */
#if defined(NC_GUARD_SECTIONED) && !defined(NCLINK_HOST_TEST)
#  define NC_VERIFY_TABLE_SECTION \
        __attribute__((section(NC_SEC_CONST), retain, used))
#else
#  define NC_VERIFY_TABLE_SECTION
#endif

/* ── Java 心跳状态(记录侧) ───────────────────────────────────────
 * nc_link.c 是心跳记录的正确归属:它是 Java↔Native 的桥接层,
 * 且在 sigcheck/envcheck 两种勾选组合下都会参与编译(protect.sh:354/363
 * 把它随 sigcheck 拷入;envcheck 单勾时 nc_link 不在工程里,此时没有
 * Java 壳喂心跳,watchdog 侧 armed==0 自然跳过检查,组合自洽)。
 * volatile + noinline 防 -O2 常量折叠(同 LSGS 的实测教训)。
 * 纯静态,不导出符号。 */
volatile long long nc_heartbeat_last_ms = 0;   /* 最近一次心跳时间 */
volatile long long nc_heartbeat_armed_ms = 0;  /* 武装时刻(constructor 置) */

__attribute__((noinline))
void nc_heartbeat_arm_constructor(void)
{
    long long now = (long long)time(NULL) * 1000LL;
    long long expected = 0;
    /* CAS 武装:constructor 可能多个(sig_check/env_check 都调),只取第一个 */
    if (nc_heartbeat_armed_ms == 0) {
        __atomic_compare_exchange_n(&nc_heartbeat_armed_ms, &expected, now,
                                    0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
}

__attribute__((noinline))
void nc_heartbeat_touch(void)
{
    long long now = (long long)time(NULL) * 1000LL;
    if (nc_heartbeat_armed_ms == 0) {
        nc_heartbeat_armed_ms = now;    /* 首次喂 = 武装(CAS 语义可省:
                                           重复武装只是时间窗略移,无害) */
    }
    nc_heartbeat_last_ms = now;
}

/* watchdog 检查端(env_check.c 调用):
 * 返回 0 = 正常(未武装/宽限期内/保活窗口内),非 0 = 超时(该杀)。
 * 语义(2026-10-16 修复):武装点移到 so constructor——so 加载即倒计时,
 * N 秒内 Java 必须开始喂,否则视为 Java 壳被删 → 杀。
 * (旧版 armed 由首喂置位 → 删喂食调用 = 永久沉默,真机实证为盲区。)
 *
 * ── 参数(2026-10-21 改为构建期开关,根治"发布前忘记改回")──────────
 *
 * 历史教训:2026-10-16 为调试改成了 5s/5s,注释写"发布前必须改回
 * GRACE=90000/KEEPALIVE=25000",但这个"必须"靠人记——一直停在调试值
 * 没改回。5s 宽限意味着【冷启动超过 5 秒的设备(低端机/加载重活)会被
 * 误杀】,且 5s 保活窗与 Guard.java 的 5s 喂食周期零余量(一次 GC 停顿
 * 就死)。这类"参数忘了改回"靠注释提醒拦不住,只能靠结构。
 *
 * 现行结构:
 *   默认(不带宏)     = 发布值 GRACE=90s / KEEPALIVE=25s
 *                      90s 承接低端机冷启动;25s ≥ watchdog 的 20s 轮询
 *                      周期(env_check.c env_watchdog),宁可稍宽不误杀,
 *                      且相对 5s 喂食周期留了 5 倍余量。
 *   -DNC_HB_DEBUG_FAST = 调试值 5s/5s("5 秒附近闪退方便调试")
 *
 * 【默认即发布值】是刻意的:CI 走 protect.sh → ndk_write_mk,不定义
 * 该宏 → 物理上不可能再把调试值带进发布包。要快闪退,本地加宏,
 * 忘了加宏的后果是"调试时死得慢",而不是"用户包误杀"——
 * 把犯错成本从用户侧挪回开发者侧。 */
/* ⚠️ 参数选型（2026-10-21 第二版，推翻 ca3fce1 的"发布 25s/调试 5s"方案）：
 *
 * 用户指出关键盲点：本项目的调试方式就是【拿 CI 发布包做逆向实验】
 * （原始需求即"让 AI 静态分析消耗上去"，验证手段是重打包实测），
 * 不存在"发布包/调试包"两种产物——宏开关对真实工作流无效。
 *
 * 重新推导后确认：保活窗【不需要为攻击者收紧】。
 *   心跳超时是状态检测("喂食停了没")，不是一次性定时炸弹——
 *   攻击者 patch 喂食后，早 5s 发现与晚 25s 发现，他没有可利用的
 *   时间窗（发现即杀，杀前他干不了任何事）。延迟的真实成本全部
 *   落在开发者调试体验上。
 *   真正必须大的只有 FIRST_GRACE：那是防误杀（低端机冷启动慢），
 *   与检测无关，只在"启动后第一次喂食前"生效。
 *
 * 故现行发布值（不再分调试/发布两套，一套走天下）：
 *   FIRST_GRACE 90s —— 防误杀低端机冷启动，唯一必须大的
 *   KEEPALIVE    8s  —— 对 Guard.java 的 5s 喂食周期留 1.6 倍余量
 *                       （一次 GC 停顿/线程调度延迟不致死），
 *                       调试时删喂食 ~8s 内 expired() 置位
 *   -DNC_HB_DEBUG_FAST 仍保留：本地编 so 验证时可用 5s/5s，
 *   但【不再必要】——发布包本身已达 ~13s 调试体感（见下）。
 *
 * 实际死期构成（配 env_check.c 的 watchdog 轮询 5s，见彼处注释）：
 *   删喂食后到进程死 ≈ KEEPALIVE(8s) 内某刻 expired() 置位，
 *   下一轮轮询(≤5s)读到 → 最坏 ~13s，典型 ~8-10s。
 *   与旧调试配置(2s+5s=7s)接近，远好于 ca3fce1 的 25s+20s=45s。 */
#ifdef NC_HB_DEBUG_FAST
#  define NC_HB_FIRST_GRACE_MS   5000LL
#  define NC_HB_KEEPALIVE_MS     5000LL
#else
#  define NC_HB_FIRST_GRACE_MS  90000LL
#  define NC_HB_KEEPALIVE_MS     8000LL
#endif

__attribute__((noinline))
int nc_heartbeat_expired(void)
{
    long long armed = nc_heartbeat_armed_ms;
    long long last, now;
    if (armed == 0)
        return 0;                        /* so 尚未加载完(constructor 未跑),防御性兜底 */
    last = nc_heartbeat_last_ms;
    now = (long long)time(NULL) * 1000LL;
    if (last == 0)
        return (now - armed) > NC_HB_FIRST_GRACE_MS;
    return (now - last) > NC_HB_KEEPALIVE_MS;
}


/*
 * 判决核心(宿主可测:NCLINK_HOST_TEST 时编译为纯逻辑函数)。
 * 非静态:由 -fvisibility=hidden 收敛符号面,JNI 入口是唯一导出面。
 * 返回 1 = 判定通过(或调试模式跳过),0 = 判定不过(Java 侧执行杀)。
 *
 * ⚠️ NC_VERIFY_SECTION（2026-10-19）：生产构建下本函数进 .ncx 密文段。
 *    它【不是】unlock 的调用方，是纯被调方，所以可以安全上锁。
 *    调用方 ncVerify（JNI 入口）刻意不标——那会造成解锁死锁。
 */
NC_VERIFY_SECTION
int nc_verify_t1(const unsigned char *t1, int len)
{
    unsigned char expected[SIG_HASH_LEN];
    int i, mismatch = 0, slot_configured = 0;

    if (t1 == NULL || len != SIG_HASH_LEN)
        return 0;                       /* 异形入参 = 不过(fail-closed) */

    for (i = 0; i < SIG_HASH_LEN; i++) {
        if (SIG_HASH_STORED[i] != 0) { slot_configured = 1; break; }
    }
    if (!slot_configured)
        return 1;                       /* 调试模式:槽位全零跳过(同 sig_check.c) */

    for (i = 0; i < SIG_HASH_LEN; i++) {
        expected[i] = (unsigned char)(t1[i] ^ SIG_SALT[i % SIG_SALT_LEN]
                                      ^ (unsigned char)((i * 0x9E) & 0xFF));
    }
    for (i = 0; i < SIG_HASH_LEN; i++)
        mismatch |= expected[i] ^ SIG_HASH_STORED[i];   /* 恒定时间 */
    return mismatch == 0;
}

#ifndef NCLINK_HOST_TEST
/* JNI 入口:Java_com_nc_link_NcLink_ncVerify([B)Z
 * 类名固定 com.nc.link.NcLink(桥接类,与 StrDec 同为工具基础设施命名),
 * JNI 短名绑定构建期即可确定,无需 RegisterNatives。 */
/* ⚠️ 2026-10-19 真机实证：动态注册方案会导致启动崩溃（sig_check 通过后
 * 进程立即消失，selftest 从未被调用）。根因是 constructor 里调
 * FindClass("com/nc/link/NcLink") —— so 由 Application.onCreate 触发加载，
 * 此时 Application 类正在初始化，该时机 FindClass 不安全。
 *
 * 回退为 JNI 短名绑定（ART 原生机制，不涉时机问题）。
 * 代价：符号名仍在 .dynsym —— 这是 JNI 短名绑定的硬要求，
 * 想隐藏就必须动态注册，而动态注册在此时机不安全。
 * 取舍：宁可保留符号名，也不能让 App 起不来。 */
JNIEXPORT jboolean JNICALL
Java_com_nc_link_NcLink_ncVerify(JNIEnv *env, jclass clazz, jbyteArray measured)
{
    jsize len;
    jbyte *buf;
    jboolean ok = JNI_FALSE;

    (void)clazz;
    if (measured == NULL)
        return JNI_FALSE;
    len = (*env)->GetArrayLength(env, measured);
    if (len != SIG_HASH_LEN)
        return JNI_FALSE;
    buf = (*env)->GetByteArrayElements(env, measured, NULL);
    if (buf == NULL)
        return JNI_FALSE;
    ok = nc_verify_t1((const unsigned char *)buf, (int)len) ? JNI_TRUE : JNI_FALSE;
    (*env)->ReleaseByteArrayElements(env, measured, buf, JNI_ABORT);
    return ok;
}

/* Java→Native 心跳(2026-10 借鉴 XopProtector 双向绑定设计):
 * Guard 注入壳每 5 秒喂一次;env_watchdog 检查 armed 后超时未喂 = Java 层
 * 被删/被绕过 → 走 delayed_kill。记录侧只做原子时间戳(纳秒级,零开销)。
 * ⚠️ 身份校验防冒充:攻击者 patch 掉 Java 校验后自己喂 ping 即可绕过整个
 * 心跳机制 —— 所以 clazz 必须是 NcLink 本类(IsSameObject 锁死),
 * 这是 Xop shell_heartbeat_ok 的同款纪律。 */
JNIEXPORT void JNICALL
Java_com_nc_link_NcLink_heartbeat(JNIEnv *env, jclass clazz)
{
    jclass self;
    /* 仅允许 NcLink 本类调用(短名绑定的调用类必然正确,这里是纵深:
     * 防 RegisterNatives 重绑/反射冒充)。self 为 NULL 时视为异常环境,
     * 不记录本次心跳(watchdog 超时路径自会兜底,fail-closed)。 */
    self = (*env)->FindClass(env, "com/nc/link/NcLink");
    if (self != NULL) {
        if ((*env)->IsSameObject(env, clazz, self)) {
            nc_heartbeat_touch();
        }
        (*env)->DeleteLocalRef(env, self);
    }
}
#endif /* NCLINK_HOST_TEST */
