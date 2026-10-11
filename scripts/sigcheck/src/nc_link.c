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
#include <jni.h>
#include <stddef.h>
#include "sig_hash.h"

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
#endif /* NCLINK_HOST_TEST */
