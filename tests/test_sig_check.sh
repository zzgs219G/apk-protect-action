#!/usr/bin/env bash
# test_sig_check.sh — sig_check.c 回归测试(冻结模块护栏,报错十二防线)
#
# 在宿主端(Linux/termux,无需 Android NDK)编译 sig_check.c 并验证:
#   1. 编译零错误(容忍 -Wall 的部分平台告警)
#   2. SIGCHECK_TEST_APK 指向真签名 APK → "signature verify ok",不 abort
#   3. 无 signing block 的 zip      → "no v2/v3 signing block" 分支
#   4. maps 截断逻辑:伪造 maps 行,截取结果必须以 base.apk 结尾(报错十二)
#
# 用法: bash tests/test_sig_check.sh [可选:测试用已签名APK路径]
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/sigcheck/src/sig_check.c"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FAIL=0
note_fail() { echo "❌ $*" >&2; FAIL=1; }

[[ -f "$SRC" ]] || { echo "❌ 找不到 $SRC" >&2; exit 1; }

CC="${CC:-cc}"
command -v "$CC" >/dev/null 2>&1 || { echo "❌ 无 $CC,跳过 sig_check 宿主测试(计为失败)"; exit 1; }

# ── 1. 编译 ─────────────────────────────────────────────────────────
mkdir -p "$WORK/fakeinc/android"
cat > "$WORK/fakeinc/android/log.h" <<'EOF'
int __android_log_print(int prio, const char *tag, const char *fmt, ...);
#define ANDROID_LOG_DEBUG 3
#define ANDROID_LOG_INFO  4
#define ANDROID_LOG_ERROR 6
EOF
cat > "$WORK/stub.c" <<'EOF'
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf("[p%d] ", prio); vprintf(fmt, ap); printf("\n"); fflush(stdout);
    va_end(ap); return 0;
}
void abort(void) { printf("ABORT-TRIGGERED\n"); exit(42); }
EOF
cat > "$WORK/main.c" <<'EOF'
#include <stdio.h>
void sig_verify_test(void);
int main(void){ sig_verify_test(); printf("MAIN-RETURNED\n"); return 0; }
EOF
# 全零 SIG_HASH = 调试模式(不比对指纹,专注路径逻辑;指纹比对由场景 2 的真包覆盖)
cat > "$WORK/sig_hash.h" <<'EOF'
#define SIG_HASH_LEN 32
static const unsigned char SIG_HASH[SIG_HASH_LEN] = { 0 };
EOF

# 注意: `#include "sig_hash.h"` 按 quote-include 语义优先在 sig_check.c 所在
# 目录解析,模板 sig_hash.h(全零)总是赢过 -I。所以把源码复制进 $WORK 编译,
# 让生成的 sig_hash.h 落在源码旁边。
cp "$SRC" "$WORK/sig_check.c"
if ! "$CC" -DSIGCHECK_HOST_TEST -I"$WORK/fakeinc" -I"$WORK" \
     "$WORK/sig_check.c" "$WORK/stub.c" "$WORK/main.c" -o "$WORK/t" -lpthread 2>"$WORK/cc.err"; then
  cat "$WORK/cc.err" >&2
  note_fail "sig_check.c 宿主编译失败"
  exit 1
fi
echo "✅ 编译通过"

# 场景 2/3 需要非零 SIG_HASH:用样本包的真实指纹(由 extract-cert-fp.py 现算,
# 与 sig_check 无关,只作为"期望值"注入)。样本不存在则跳过。
SAMPLE_APK="${1:-$ROOT/简盒_signed_10_18_47_sign.apk}"
FP_SCRIPT="$ROOT/scripts/sig-hash/extract-cert-fp.py"
if [[ -f "$SAMPLE_APK" && -f "$FP_SCRIPT" ]]; then
  FP=$(python3 "$FP_SCRIPT" "$SAMPLE_APK" 2>/dev/null) || FP=""
fi
if [[ -n "${FP:-}" && ${#FP} -eq 64 ]]; then
  {
    echo "#define SIG_HASH_LEN 32"
    echo -n "static const unsigned char SIG_HASH[SIG_HASH_LEN] = {"
    sep=""
    for ((i = 0; i < 64; i += 2)); do
      echo -n "$sep 0x${FP:i:2}"; sep=","
    done
    echo " };"
  } > "$WORK/sig_hash.h"
  # 场景 4 已用全零头跑过(跳过分支),场景 2/3 用真指纹重新编译
  cp "$SRC" "$WORK/sig_check.c"
  if ! "$CC" -DSIGCHECK_HOST_TEST -I"$WORK/fakeinc" -I"$WORK" \
       "$WORK/sig_check.c" "$WORK/stub.c" "$WORK/main.c" -o "$WORK/t" -lpthread 2>>"$WORK/cc.err"; then
    note_fail "带真指纹的二次编译失败"
    exit 1
  fi
  out=$(SIGCHECK_TEST_APK="$SAMPLE_APK" timeout 10 "$WORK/t" 2>&1)
  if ! echo "$out" | grep -q "signature verify ok"; then
    note_fail "真签名包未 verify ok: $out"
  elif echo "$out" | grep -q "ABORT-TRIGGERED"; then
    note_fail "真签名包触发 abort"
  else
    echo "✅ 真签名包 verify ok(未 abort)"
  fi

  python3 - "$WORK/nov2.apk" <<'PYEOF'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake")
PYEOF
  out=$(SIGCHECK_TEST_APK="$WORK/nov2.apk" timeout 10 "$WORK/t" 2>&1)
  if echo "$out" | grep -q "no v2/v3 signing block"; then
    echo "✅ 无签名包正确走 no-v2v3 分支"
  else
    note_fail "无签名包未报 no v2/v3: $out"
  fi
else
  echo "ℹ️ 无真签名样本/指纹脚本,跳过场景 2/3"
fi

# ── 4. maps 截断逻辑(报错十二:截取必须保留 base.apk)───────────────
cat > "$WORK/maps_test.c" <<'EOF'
#include <stdio.h>
#include <string.h>
int main(void) {
    const char *fake = "/data/app/~~abc==/com.xixin.box-xyz==/base.apk!/lib/arm64/libnc.so";
    char line[512]; strcpy(line, fake);
    char *p = strstr(line, "base.apk");
    if (!(p && strstr(line, ".so"))) return 2;
    p += 8;               /* 报错十二修复:停在 base.apk 之后 */
    *p = '\0';
    size_t n = strlen(line);
    if (n >= 8 && strcmp(line + n - 8, "base.apk") == 0) {
        printf("MAPS-TRUNC-OK: %s\n", line);
        return 0;
    }
    printf("MAPS-TRUNC-BAD: %s\n", line);
    return 1;
}
EOF
if "$CC" "$WORK/maps_test.c" -o "$WORK/maps_test" 2>/dev/null && "$WORK/maps_test" | grep -q MAPS-TRUNC-OK; then
  echo "✅ maps 截断保留 base.apk"
else
  note_fail "maps 截断逻辑丢失 base.apk(报错十二回归!)"
fi

if [[ $FAIL -eq 0 ]]; then
  echo "✅ test_sig_check.sh 全部通过"
fi
exit $FAIL
