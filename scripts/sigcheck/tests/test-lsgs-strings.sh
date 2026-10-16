#!/usr/bin/env bash
# test-lsgs-strings.sh — LSGS 检测特征串密文化的端到端验证(宿主端)
#
# 验证三件事(任何一环漂移都会被钉住):
#   ① 明文不入 so:把 env_check.c 编成真实 so(-O2 --gc-sections 严格模式),
#      攻击者视角 strings 搜 20 个特征串 → 必须全零命中
#   ② 解码逐字节正确:lsgs_decode_test.c 对全部 LSGS_* 条目与明文期望比对
#   ③ 防常量折叠回归:密文表 volatile + lsg_decode noinline 在生成的头里在位
#      (缺失 = 上一版实测的"前 8 字节明文 SIMD 泄漏"bug 复活)
#
# 用法: bash scripts/sigcheck/tests/test-lsgs-strings.sh
# 依赖: clang(或 gcc)、python3;sig_log_data.h 由本脚本临时生成(不进 git)
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
GEN="$ROOT/scripts/sigcheck/log/make-sig-log.py"
SRC_SIG="$ROOT/scripts/sigcheck/src/sig_check.c"
SRC_ENV="$ROOT/scripts/sigcheck/src/env_check.c"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0; fail=0
ok()  { echo "  ✅ $1"; pass=$((pass+1)); }
bad() { echo "  ❌ $1"; fail=$((fail+1)); }

echo "══════════════════════════════════════════════════"
echo "LSGS 检测特征串密文化 端到端验证(宿主端)"
echo "══════════════════════════════════════════════════"

# ── ① 生成 sig_log_data.h(与流水线同一命令) ──
python3 "$GEN" "$SRC_SIG" "$SRC_ENV" "$T/sig_log_data.h" >/dev/null
ok "sig_log_data.h 生成(make-sig-log.py,含 LSGS 标记)"

# ── ② ③ 防常量折叠三要素在位 ──
if grep -q "const unsigned char volatile \*data" "$T/sig_log_data.h"; then
    ok "密文表 volatile 在位(防 -O2 SIMD 明文折叠)"
else
    bad "密文表 volatile 缺失(泄漏 bug 复活风险)"
fi
if grep -q "noinline" "$T/sig_log_data.h" && grep -q "lsg_decode" "$T/sig_log_data.h"; then
    ok "lsg_decode noinline 在位(防内联折叠)"
else
    bad "lsg_decode noinline 缺失"
fi

cp "$SRC_ENV" "$T/env_check.c"
cp "$SRC_SIG" "$T/sig_check.c"
# sig_check.c 引用 sig_hash.h(构建期由 make-sig-hash.sh 生成;测试用空桩)
printf '#ifndef _SIG_HASH_H_\n#define _SIG_HASH_H_\n#define SIG_HASH_LEN 32\n#define SIG_SALT_LEN 16\nstatic const unsigned char SIG_SALT[16]={0};\nstatic const unsigned char SIG_HASH_STORED[32]={0};\n#endif\n' > "$T/sig_hash.h"

CC="$(command -v clang || command -v gcc)"

# ── ④ 解码正确性(lsgs_decode_test.c,26 条 LSGS 与明文期望逐字节比对) ──
if $CC -O2 -DSIGCHECK_HOST_TEST -I"$T" "$HERE/lsgs_decode_test.c" -o "$T/deco" 2>"$T/d.log"; then
    DR="$("$T/deco" 2>&1 || true)"
    if [[ "$DR" == *"全部 26 条 LSGS 解码逐字节正确"* ]]; then
        ok "解码对拍:26 条 LSGS 全部逐字节正确"
    else
        bad "解码不一致: $DR"
    fi
else
    bad "解码测试编译失败"; head -10 "$T/d.log"
fi

# ── ⑤ 明文不入 so(攻击者视角,严格编译模式) ──
# sig_check.c 一并编入全家桶(实际流水线组合),外围串零泄漏一体验证
if $CC -shared -fPIC -O2 -DSIGCHECK_HOST_TEST -DNCLINK_HOST_TEST -I"$T" \
      "$T/sig_check.c" "$T/env_check.c" -o "$T/libtest.so" -llog -fvisibility=hidden \
      -ffunction-sections -fdata-sections -Wl,--gc-sections 2>"$T/c.log"; then
    ok "sig_check+env_check 全家桶严格模式编译通过(-O2 --gc-sections)"
    leak=0
    for s in "frida-agent" "frida-gadget" "frida-inject" "gadget_frida" \
             ":69A2" ":69A3" "libxposed" "lspd" "lsposed" "edxposed" \
             "libriru" "libzygisk" "XposedBridge" "TracerPid" "gum-js-loop" \
             "gmain" "gdbus" "pool-frida" "linjector" "/data/adb" \
             "xixin_debug" "sigcheck_log.txt" "SIGCHECK_TEST_LOG" \
             "SIGCHECK_TEST_APK" "apk not found" "no v2/v3 signing block"; do
        if grep -a -q "$s" "$T/libtest.so"; then
            bad "so 里泄漏明文特征串: $s"
            leak=$((leak+1))
        fi
    done
    if [[ $leak -eq 0 ]]; then
        ok "明文零泄漏:26 个特征/外围串在 so 里全部零命中(strings 扫描视角)"
    fi
else
    bad "so 编译失败"; head -10 "$T/c.log"
fi

echo "══════════════════════════════════════════════════"
echo "结果: $pass 通过, $fail 失败"
echo "══════════════════════════════════════════════════"
[[ $fail -eq 0 ]] || exit 1
