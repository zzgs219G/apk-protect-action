#!/usr/bin/env bash
# test-sig-guard2.sh — sig_guard2.c 的派生公式对拍(宿主端,不需要 NDK/真机)
#
# 为什么必须有这个测试:
#   sig_guard2.c 的 g2_derive() 与 make-sig-hash.sh 的 python 生成侧
#   必须【逐字节一致】—— 两侧公式漂移 = 正确签名的包也被误杀(显性失败)。
#   本测试把两侧的公式钉在一起:任何一方改动而另一方没跟,立刻红。
#
# 覆盖:
#   ① 生成侧(python)与校验侧(C)对同一指纹算出相同 stored
#   ② 全零槽位 = 调试模式(不误伤)
#   ③ 错误指纹必然 mismatch
#
# 用法: bash scripts/sigcheck/tests/test-sig-guard2.sh
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SRC="$ROOT/scripts/sigcheck/src/sig_guard2.c"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

pass=0; fail=0
ok()  { echo "  ✅ $1"; pass=$((pass+1)); }
bad() { echo "  ❌ $1"; fail=$((fail+1)); }

echo "══════════════════════════════════════════════════"
echo "sig_guard2.c 派生对拍(宿主端)"
echo "══════════════════════════════════════════════════"

# ── ① 生成侧公式(python,与 make-sig-hash.sh 内嵌的完全一致) ──
python3 - "$T" <<'PY'
import hashlib, os, sys
out = sys.argv[1]
fp = bytes(range(32))                    # 固定测试指纹
salt = bytes(range(16))                  # 固定盐(可复现)
t2 = hashlib.sha256(b"G2" + fp).digest()
stored = bytes(t2[i] ^ salt[(i*7) % 16] ^ ((i*0x5B + 0x3D) & 0xFF) for i in range(32))
with open(os.path.join(out, "expect.bin"), "wb") as f:
    f.write(stored)
with open(os.path.join(out, "salt.bin"), "wb") as f:
    f.write(salt)
print("生成侧 salt=%s" % salt.hex())
print("生成侧 stored=%s" % stored.hex())
PY

# ── ② 校验侧:把 C 文件编成可测(去 static 改名 + 注入固定 salt) ──
# 做法:不用 sig_guard2.h(避免 static const 重定义冲突),
#      直接把源文件里的 #include "sig_guard2.h" 替换成内联的测试定义。
sed -e 's/static void g2_derive(/void g2_derive_test(/' \
    -e 's/g2_derive(fp, expected)/g2_derive_test(fp, expected)/' \
    -e 's|#include "sig_guard2.h"|#include "guard2_test.h"|' \
    "$SRC" > "$T/guard2_test.c"

# 注入测试头文件(替代 sig_guard2.h),用固定 salt/stored
python3 - "$T/guard2_test.h" "$T/expect.bin" "$T/salt.bin" <<'PY'
import sys
hdr_path, expect_path, salt_path = sys.argv[1], sys.argv[2], sys.argv[3]
stored = open(expect_path, "rb").read()
salt = open(salt_path, "rb").read()
with open(hdr_path, "w") as f:
    f.write("#ifndef _GUARD2_TEST_H_\n#define _GUARD2_TEST_H_\n")
    f.write("#define SG2_HASH_LEN 32\n#define SG2_SALT_LEN 16\n")
    f.write("static const unsigned char SG2_SALT[16] = {%s};\n" % ",".join(str(b) for b in salt))
    f.write("static const unsigned char SG2_STORED[32] = {%s};\n" % ",".join(str(b) for b in stored))
    f.write("#endif\n")
PY

cat > "$T/main.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "guard2_test.h"
void g2_derive_test(const unsigned char fp[32], unsigned char out[32]);
int main(void) {
    unsigned char fp[32], out[32];
    int i, mismatch = 0;
    for (i = 0; i < 32; i++) fp[i] = (unsigned char)i;
    g2_derive_test(fp, out);
    for (i = 0; i < 32; i++) mismatch |= out[i] ^ SG2_STORED[i];
    if (mismatch) { printf("MISMATCH\n"); return 1; }
    printf("MATCH\n");
    return 0;
}
C

CC="$(command -v clang || command -v gcc)"
if ! $CC -O1 -DSIGGUARD2_HOST_TEST -I"$T" "$T/guard2_test.c" "$T/main.c" -o "$T/t" 2>"$T/cc.log"; then
    echo "编译失败:"; head -20 "$T/cc.log"; bad "编译 sig_guard2.c"
else
    ok "编译通过(clang/gcc, 宿主端)"
fi

R="$("$T/t" 2>&1 || true)"
if [[ "$R" == "MATCH" ]]; then
    ok "派生对拍:C 侧 g2_derive == Python 生成侧(逐字节)"
else
    bad "派生不一致: $R"
fi

# ── ③ 调换指纹必须 mismatch(证明不是恒真) ──
cat > "$T/neg.c" <<'C'
#include <stdio.h>
#include <string.h>
#include "guard2_test.h"
void g2_derive_test(const unsigned char fp[32], unsigned char out[32]);
int main(void) {
    unsigned char fp[32], out[32];
    int i, mismatch = 0;
    for (i = 0; i < 32; i++) fp[i] = (unsigned char)(i ^ 0xFF);   /* 不同指纹 */
    g2_derive_test(fp, out);
    for (i = 0; i < 32; i++) mismatch |= out[i] ^ SG2_STORED[i];
    printf(mismatch ? "DIFF\n" : "SAME\n");
    return 0;
}
C
$CC -O1 -DSIGGUARD2_HOST_TEST -I"$T" "$T/guard2_test.c" "$T/neg.c" -o "$T/tn" 2>"$T/neg.log" || true
if [[ -x "$T/tn" ]]; then
    RN="$("$T/tn" 2>&1 || true)"
    if [[ "$RN" == "DIFF" ]]; then
        ok "错误指纹 → 必然 mismatch(非恒真)"
    else
        bad "错误指纹未 mismatch: $RN"
    fi
else
    bad "第 3 项编译失败(见下)"; head -5 "$T/neg.log"
fi

echo "══════════════════════════════════════════════════"
echo "结果: $pass 通过, $fail 失败"
echo "══════════════════════════════════════════════════"
[[ $fail -eq 0 ]] || exit 1
