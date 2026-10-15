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

/* 心跳接口(实现在本文件下方;env_check.c 的 watchdog 调用检查端) */
void nc_heartbeat_touch(void);
int nc_heartbeat_expired(void);

#include <jni.h>
#include <stddef.h>
#include <time.h>
#include "sig_hash.h"

/* ── Java 心跳状态(记录侧) ───────────────────────────────────────
 * nc_link.c 是心跳记录的正确归属:它是 Java↔Native 的桥接层,
 * 且在 sigcheck/envcheck 两种勾选组合下都会参与编译(protect.sh:354/363
 * 把它随 sigcheck 拷入;envcheck 单勾时 nc_link 不在工程里,此时没有
 * Java 壳喂心跳,watchdog 侧 armed==0 自然跳过检查,组合自洽)。
 * volatile + noinline 防 -O2 常量折叠(同 LSGS 的实测教训)。
 * 纯静态,不导出符号。 */
volatile long long nc_heartbeat_last_ms = 0;   /* 最近一次心跳时间 */
volatile long long nc_heartbeat_armed_ms = 0;  /* 武装时刻(首次喂时置) */

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
 * 首喂宽限 90s(Xop 同款:冷启动重活),之后保活窗 25s
 * (≥ env_watchdog 的 20s 轮询周期,宁可稍宽不误杀)。 */
/* 调试参数(2026-10-16 用户要求"5 秒附近闪退方便调试"):
 * ⚠️ 发布前必须改回正式值 GRACE=90000 / KEEPALIVE=25000——调试值意味着
 * 正常冷启动超过 5 秒的设备(低端机/加载重活)会被误杀。
 * 调试语义:首喂宽限 5s / 保活窗 5s → 删 c() 调用或停喂后 ~25s 内必死
 * (watchdog 20s 轮询 + 5s 窗口)。 */
#define NC_HB_FIRST_GRACE_MS   5000LL
#define NC_HB_KEEPALIVE_MS     5000LL

__attribute__((noinline))
int nc_heartbeat_expired(void)
{
    long long armed = nc_heartbeat_armed_ms;
    long long last, now;
    if (armed == 0)
        return 0;                        /* 未武装(Guard 未跑/无壳)不检查 */
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
 */
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
