/* 运行时解码正确性验证:模拟 lsg_s() 的调用方式,解码全部 LSGS_* 条目,
 * 与明文期望比对 —— 证明"密文表+volatile+noinline"方案解码逐字节正确 */
#include <stdio.h>
#include <string.h>
#include "sig_log_data.h"

struct { lsg_id_t id; const char *expect; } cases[] = {
    { LSGS_FRIDA_AGENT, "frida-agent" },
    { LSGS_FRIDA_GADGET, "frida-gadget" },
    { LSGS_FRIDA_INJECT, "frida-inject" },
    { LSGS_GADGET_FRIDA, "gadget_frida" },
    { LSGS_TCP_69A2, ":69A2" },
    { LSGS_TCP_69A3, ":69A3" },
    { LSGS_XP_LIBXPOSED, "libxposed" },
    { LSGS_XP_LSPD, "lspd" },
    { LSGS_XP_LSPOSED, "lsposed" },
    { LSGS_XP_EDXPOSED, "edxposed" },
    { LSGS_XP_LIBRIRU, "libriru" },
    { LSGS_XP_LIBZYGISK, "libzygisk" },
    { LSGS_XP_PATH_LSPD, "/data/adb/lspd" },
    { LSGS_XP_PATH_ZYGISK_LSP, "/data/adb/modules/zygisk_lsposed" },
    { LSGS_XP_PATH_RIRU_LSP, "/data/adb/modules/riru_lsposed" },
    { LSGS_XP_PATH_ZYGISK_EDX, "/data/adb/modules/zygisk_edxposed" },
    { LSGS_XP_PATH_XBRIDGE, "/system/framework/XposedBridge.jar" },
    { LSGS_TRACERPID, "TracerPid:" },
    { LSGS_THR_GUMJS, "gum-js-loop" },
    { LSGS_THR_GMAIN, "gmain" },
    { LSGS_THR_GDBUS, "gdbus" },
    { LSGS_THR_POOL, "pool-frida" },
    { LSGS_THR_FRIDA, "frida" },
    { LSGS_UNX_FRIDA, "frida" },
    { LSGS_UNX_LINJECTOR, "linjector" },
    { LSGS_UNX_GUMJS, "gum-js" },
};

int main(void) {
    int n = sizeof(cases)/sizeof(cases[0]), i, fail = 0;
    char buf[64];
    for (i = 0; i < n; i++) {
        const char *s = lsg_s(cases[i].id, buf, sizeof(buf));
        if (!s || strcmp(s, cases[i].expect) != 0) {
            printf("❌ case %d: got=%s want=%s\n", i, s ? s : "(null)", cases[i].expect);
            fail++;
        }
    }
    if (fail) { printf("FAIL %d/%d\n", fail, n); return 1; }
    printf("✅ 全部 %d 条 LSGS 解码逐字节正确\n", n);
    return 0;
}
