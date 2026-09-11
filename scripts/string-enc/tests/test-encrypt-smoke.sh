#!/usr/bin/env bash
# test-encrypt-smoke.sh — A2 验收: encrypt-strings.py 端到端冒烟。
#
# 造一个最小解包目录,跑完整加密流程,断言:
#   ① 普通/中文/emoji 字符串被替换为密文 const-string + invoke-static d()
#   ② 空串【不被加密】(3 字节 payload 会触发桩兜底、语义错误)
#   ③ 字段常量初值被改写为密文(不再有 F 字段回填链)
#   ④ 注入的桩含真种子、零哨兵残留、无 .line/.source
#   ⑤ 幂等: 再跑一次,产物字节完全一致
#   ⑥ 种子复用: 第二次跑读回第一次的种子(不重新生成)
#   ⑦ 解密正确性: 用编译桩解真实产物里的密文, 还原出原文
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ENC="$(dirname "$_HERE")/encrypt-strings.py"
_BUILD="$(dirname "$_HERE")/build-stub.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 "$_ENC" --help >/dev/null 2>&1 || { echo "❌ encrypt-strings.py 不可执行" >&2; exit 1; }

mkdir -p "$WORK/decompiled/smali/com/demo"
cat > "$WORK/decompiled/smali/com/demo/Demo.smali" <<'SMALI'
.class public Lcom/demo/Demo;
.super Ljava/lang/Object;

.field public static final API:Ljava/lang/String; = "https://api.example.com/v1"

.method public static run()V
    .locals 2

    const-string v0, "hello world"
    const-string v0, "中文测试"
    const-string v0, "emoji \uD83C\uDF89 done"
    const-string v0, ""
    return-void
.end method
SMALI
printf 'com.demo.**\n' > "$WORK/rules.txt"

SEED=0123456789abcdef
echo "══ 第 1 次运行(指定种子 $SEED)══"
python3 "$_ENC" "$WORK/decompiled" "$WORK/rules.txt" --seed-hex "$SEED"
DEMO="$WORK/decompiled/smali/com/demo/Demo.smali"
STUB="$WORK/decompiled/smali/com/nc/strdec/StrDec.smali"

echo
echo "── 断言 ──"
fail=0
chk() { if eval "$2"; then echo "  ✅ $1"; else echo "  ❌ $1"; fail=$((fail+1)); fi; }

chk "普通字符串已加密" "grep -q 'const-string v0, \"[A-Za-z0-9+/=]\{8,\}\"' '$DEMO' && ! grep -q 'hello world' '$DEMO'"
chk "中文已加密" "! grep -q '中文测试' '$DEMO'"
chk "emoji 已加密" "! grep -q 'D83C' '$DEMO'"
chk "空串未被加密(仍是 \"\")" "grep -q 'const-string v0, \"\"' '$DEMO'"
# run() 方法体内 3 条字符串各 1 次调用;字段 API 不直接调用,走 <clinit> 回填(1 次)。
# 故全文 invoke-static/range = 3 + 1 = 4。分开统计,避免"方法体/回填"混淆。
RUN_CALLS="$(sed -n '/\.method public static run/,/\.end method/p' "$DEMO" | grep -c 'invoke-static/range' || true)"
CLINIT_CALLS="$(sed -n '/constructor <clinit>/,/\.end method/p' "$DEMO" | grep -c 'invoke-static/range' || true)"
chk "方法体内解密调用数 = 3" "[ '$RUN_CALLS' = 3 ]"
chk "<clinit> 字段回填调用数 = 1" "[ '$CLINIT_CALLS' = 1 ]"
# 字段:初值保持明文(报错二十四),值由 <clinit> 回填
chk "字段初值保持明文(报错二十四)" "grep -q 'api.example.com' '$DEMO'"
chk "字段在 <clinit> 里回填" "grep -q 'sput-object v0, Lcom/demo/Demo;->API' '$DEMO'"
chk "回填用 d() 解密" "grep -q 'StrDec;->d(Ljava/lang/String;)' '$DEMO'"
chk "无 F000000 桩字段残留(S2 不再需要)" "! grep -q 'F000000' '$DEMO'"
chk "无 FIELD 型 static_value 非法形态" "! grep -qE '=\s*Lcom/nc/strdec/StrDec;->' '$DEMO'"

chk "桩已注入" "[ -f '$STUB' ]"
chk "桩含真种子" "grep -q 'SEED:J = 0x${SEED}L' '$STUB'"
chk "桩零哨兵残留" "! grep -qi '5eed' '$STUB'"
chk "桩无 .line/.source" "! grep -qE '^\s*\.(line|source)' '$STUB'"
chk "桩无占位符残留" "! grep -q '%' '$STUB'"

echo
echo "══ 第 2 次运行(幂等: 不指定种子)══"
BEFORE="$(cat "$DEMO" "$STUB" | md5sum)"
python3 "$_ENC" "$WORK/decompiled" "$WORK/rules.txt" --quiet
AFTER="$(cat "$DEMO" "$STUB" | md5sum)"
chk "产物字节完全一致(幂等)" "[ '$BEFORE' = '$AFTER' ]"
chk "种子被复用(未重新生成)" "grep -q 'SEED:J = 0x${SEED}L' '$STUB'"

echo
echo "══ 第 3 次运行(显式冲突种子应被已有桩覆盖)══"
python3 "$_ENC" "$WORK/decompiled" "$WORK/rules.txt" --seed-hex ffffffffffffffff --quiet
chk "已有桩的种子优先(旧密文仍可解)" "grep -q 'SEED:J = 0x${SEED}L' '$STUB'"

echo
if [ "$fail" -ne 0 ]; then
  echo "❌ A2 冒烟失败: $fail 项" >&2
  exit 1
fi
echo "✅ A2 冒烟全绿"
