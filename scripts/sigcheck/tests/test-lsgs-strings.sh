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
# 2026-10-20：两者都 include nc_guard_layout.h（so 加密契约唯一真相源），
# 必须一并拷到 -I 搜索路径，否则编译期 "file not found"。
cp "$ROOT/scripts/sigcheck/src/nc_guard_layout.h" "$T/"
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
      -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--strip-all \
      2>"$T/c.log"; then
    ok "sig_check+env_check 全家桶严格模式编译通过(-O2 --gc-sections --strip-all，与生产同款)"
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

    # ⑥ 未登记的敏感串扫描（2026-10-20 加）
    # 为什么单列：上面的断言只查【已登记】的 26 条——它保证"登记过的没漏"，
    # 但保证不了"没登记的敏感串不泄露"。实例：sig_check.c 的
    # SIG_BLOCK_MAGIC 是 16 字节【数据数组】而非字符串字面量，LSGS 扫描
    # 扫不到它，于是 "APK Sig Block 42" 在 .rodata 明文躺到本轮才被发现
    # （复测报告 §2.2 的泄底项之一）。同类风险还有：日志格式串、路径常量。
    #
    # 做法：列一批"只要出现就等于暴露防御意图"的词，命中即红。
    # ⚠️ 只收【真敏感】词：base.apk / /proc/self 这类是 Android 标准文件名，
    #    任何读 APK 的代码都有，收了会误报（已实测：6 处，全是 snprintf
    #    路径常量，不暴露意图），故不入清单。
    sens_re='APK Sig Block|Xposed|frida|Frida|magisk|Magisk|zygisk|substrate|TracerPid|memfault'
    # ⚠️ 必须加 `|| true`：本脚本 set -euo pipefail，而 grep 无命中返回 1，
    #    不加会让【赋值语句本身】失败并终止整个脚本 —— 两个分支都跑不到，
    #    这条断言变成"从不执行的死代码"（2026-10-20 实测踩过：
    #    第一次加完后整个脚本在赋值行静默退出，后面什么都不打印）。
    # ⚠️ 必须用二进制精确搜，不能用 strings：
    #   2026-10-20 实测，"APK Sig Block 42" 在 .rodata 里明明连续存在，
    #   但 strings -n 4 因相邻数据的分词边界不同而【漏报】——
    #   我用 strings 做"修复前/修复后"对比时两边都显示 0，差点误判修复无效。
    #   改为 python 按原始字节序列搜，不受分词影响。
    # ⚠️ 同样必须加 `|| true`：set -euo pipefail 下 grep 无命中返回 1，
    #    会让赋值语句本身失败并终止整个脚本，两个分支都跑不到。
    hits=$(python3 - "$T/libtest.so" <<'PYSENS' || true
import sys
pats = [b'APK Sig Block', b'Xposed', b'xposed', b'frida', b'Frida',
        b'magisk', b'Magisk', b'zygisk', b'substrate', b'TracerPid',
        b'memfault']
d = open(sys.argv[1], 'rb').read()
found = sorted({p.decode() for p in pats if p in d})
print('\n'.join(found))
PYSENS
)
    if [ -z "$hits" ]; then
        ok "未登记敏感串零命中（APK Sig Block / frida / xposed / magisk / TracerPid 等）"
    else
        bad "未登记敏感串泄露（这些词不在 LSGS 清单里，故上面的断言查不到）:"
        echo "$hits" | sed 's/^/        /' >&2
    fi
else
    bad "so 编译失败"; head -10 "$T/c.log"
fi

# ── ⑦ 字符串加密强度（2026-10-22 新增，修实测报告「字符串保护 ★☆☆☆☆」）──
# 实测报告原文："8 字节固定 key 的重复 XOR（0x14170 = 5ac3119ef037b26d），
#               10 行 Python 全解出"。
# 旧实现三个结构性弱点，本组断言逐个钉死：
#   ① key 全局固定 → 解一个包 = 解所有包；且 key 字面量能在 so 里搜到
#   ② 单字节重复 XOR（周期 8）→ 相同前缀产生相同密文
#   ③ 无消息域分离 → 已知明文泄漏的密钥流可套到其他消息
echo "── 字符串加密强度（本轮升级）──"

# ① key 必须每构建随机（不是固定常量）
# 判据：连续两次生成的 LSG_KEY 必须不同。
python3 "$GEN" "$SRC_SIG" "$SRC_ENV" "$T/k1.h" >/dev/null 2>&1
python3 "$GEN" "$SRC_SIG" "$SRC_ENV" "$T/k2.h" >/dev/null 2>&1
K1=$(grep -o 'LSG_KEY\[LSG_KEY_LEN\] = {[^}]*}' "$T/k1.h" | md5sum | cut -d' ' -f1)
K2=$(grep -o 'LSG_KEY\[LSG_KEY_LEN\] = {[^}]*}' "$T/k2.h" | md5sum | cut -d' ' -f1)
if [ "$K1" != "$K2" ]; then
    ok "① LSG_KEY 每构建随机（两次生成不同 → 跨包 diff 失效）"
else
    bad "① LSG_KEY 仍是固定常量 —— 解一个包等于解所有包"
fi

# key 长度必须是 32 字节（旧版 8 字节）
if grep -q '#define LSG_KEY_LEN 32' "$T/sig_log_data.h"; then
    ok "② LSG_KEY_LEN = 32（旧版 8 字节已废弃）"
else
    bad "② LSG_KEY_LEN 不是 32 —— 可能退回旧实现"
fi

# ③ 旧的固定 key 字面量不得再出现（防止代码/注释里残留 5ac3119ef037b26d）
if grep -rq "0x5A, 0xC3, 0x11, 0x9E" "$ROOT/scripts/sigcheck/log/make-sig-log.py" 2>/dev/null; then
    bad "③ 生成器里仍有旧的固定 key 字面量（5ac3119ef037b26d）"
else
    ok "③ 旧固定 key 字面量已消失（不再硬编码 5ac3119ef037b26d）"
fi

# ④ 域分离：不同消息的相同前缀，密文必须不同
# 这是已知明文攻击的入口（报告没提，但比"固定 key"更危险：
# 攻击者猜到 "/proc/self/maps" 就能算出密钥流，套到 "/proc/self/status" 上）
if python3 - "$T/sig_log_data.h" <<'PYDOM' ; then
import re, sys
src = open(sys.argv[1], encoding='utf-8').read()
# 数组名形如 LSG_DATA__FRIDA_AGENT（宏名去掉 "LSG_" 前缀后以 "_" 开头 → 双下划线）
def arr(name):
    m = re.search(r'LSG_DATA_%s\[\d+\]\s*=\s*\{([^}]*)\}' % re.escape(name), src)
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9a-f]{2})', m.group(1))) if m else None
# LSGS_FRIDA_AGENT="frida-agent" 与 LSGS_FRIDA_GADGET="frida-gadget" 共享前缀 "frida-"
a, b = arr('_FRIDA_AGENT'), arr('_FRIDA_GADGET')
if a is None or b is None:
    print("取不到密文数组")
    sys.exit(1)
same = sum(1 for x, y in zip(a, b) if x == y)
# 6 字节前缀全同 = 旧实现（无域分离）；期望显著不同
sys.exit(0 if same < 3 else 1)
PYDOM
    ok "④ 域分离生效（相同前缀 'frida-' 的密文不再相同 → 已知明文攻击失效）"
else
    bad "④ 无域分离 —— 已知明文泄漏的密钥流可套用到其他消息"
fi

echo "══════════════════════════════════════════════════"
echo "结果: $pass 通过, $fail 失败"
echo "══════════════════════════════════════════════════"
[[ $fail -eq 0 ]] || exit 1
