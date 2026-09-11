#!/usr/bin/env bash
# test-keystream-crosscheck.sh — A1 验收: 构建期(Python)与运行期(Java 桩)的
# 密钥流必须逐字节一致。这是整个字符串加密方案的【正确性地基】:
# 差一个字节 → 全包字符串乱码。
#
# 【测什么】
#   第 1 层 纯算术层: 反射调用真实桩的 keyByte/mix64,与 Python 参考实现比对
#                     (覆盖 4 个种子 × 256 字节连续密钥流,锁死 >>>/&7/字节序)
#   第 2 层 全链:     用真实桩的 d(String) 解 Python 生成的 payload,断言明文还原
#                     (覆盖空串以外全部样本:ASCII/中文/emoji 代理对/全角/最长 5188B/
#                      边界码点/各类转义;offset 含非 8 对齐与跨块值)
#
# 【为什么按种子分组编译】
#   d() 里的 SEED 被 d8 内联为编译期常量 → 一条编译产物只能验证一个种子。
#   故第 2 层对 4 个种子各编译一次桩,严格复刻 build-stub.sh 的注入语义。
#
# 【依赖】javac(JDK17)、python3。不需要 android.jar(用 shims 顶替 Base64)。
# 【用法】bash scripts/string-enc/tests/test-keystream-crosscheck.sh
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_STUB_SRC="$(dirname "$_HERE")/stub-src/StrDec.java"

SEEDS="5eed000000000000 0123456789abcdef ffffffffffffffff 0000000000000001"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

[ -f "$_STUB_SRC" ] || { echo "❌ 找不到桩源码: $_STUB_SRC" >&2; exit 1; }

# 与 build-stub.sh 逐字相同的哨兵种子注入(保证对拍对象 == 将来进 APK 的桩)
build_stub() {
  local seed="$1"
  rm -rf "$WORK/build"
  mkdir -p "$WORK/build/com/nc/strdec" "$WORK/build/cls"
  sed "s|private static final long SEED = 0L;.*|private static final long SEED = 0x${seed}L;|" \
      "$_STUB_SRC" > "$WORK/build/com/nc/strdec/StrDec.java"
  sed -i '1i package com.nc.strdec;' "$WORK/build/com/nc/strdec/StrDec.java"
  grep -q "SEED = 0x${seed}L;" "$WORK/build/com/nc/strdec/StrDec.java" \
    || { echo "❌ 哨兵种子注入失败(seed=$seed): StrDec.java 的 SEED 声明行形态变了" >&2; exit 1; }
  javac -d "$WORK/build/cls" \
        "$_HERE/shims/android/util/Base64.java" \
        "$WORK/build/com/nc/strdec/StrDec.java" \
        "$_HERE/P3Check.java" "$_HERE/P3Full.java"
}

echo "══ 第 1 层: 纯算术层 keyByte/mix64 对拍 ══"
build_stub 5eed000000000000          # keyByte 显式传参,编译期种子不影响本层
python3 "$_HERE/gen_plan.py" "$WORK/plan.json"
java -cp "$WORK/build/cls" P3Check "$WORK/plan.json"
echo

echo "══ 第 2 层: 全链 d() 对拍(每种子一次编译)══"
total_pass=0
total_fail=0
for seed in $SEEDS; do
  build_stub "$seed"
  python3 "$_HERE/gen_plan.py" "$WORK/plan.json" --seed "$seed"
  out="$(java -cp "$WORK/build/cls" P3Full "$WORK/plan.json")"
  echo "$out" | tail -1 | sed "s|^|  seed=$seed |"
  p=$(echo "$out" | tail -1 | sed 's/.*pass=\([0-9]*\).*/\1/')
  f=$(echo "$out" | tail -1 | sed 's/.*fail=\([0-9]*\).*/\1/')
  total_pass=$((total_pass + p))
  total_fail=$((total_fail + f))
  echo "$out" | grep "^FAIL" | head -3 || true
done

echo
echo "══ 汇总: pass=$total_pass fail=$total_fail ══"
if [ "$total_fail" -ne 0 ]; then
  echo "❌ A1 双端对拍失败" >&2
  exit 1
fi
echo "✅ A1 双端对拍全绿(Python ↔ Java 密钥流逐字节一致)"
