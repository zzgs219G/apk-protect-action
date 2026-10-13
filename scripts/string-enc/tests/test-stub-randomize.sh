#!/usr/bin/env bash
# test-stub-randomize.sh — 桩随机化验收(报错四十七式:防引擎固定签名)。
#
# 【测什么】
#   ① 不传 --stub-name(生产默认):桩落随机包/类/方法,产物零 legacy 痕迹
#      (全目录 grep 不到 com/nc/strdec 与 StrDec 字样)
#   ② 调用点三指令指向随机名,且随机名 ≠ legacy(真的换了)
#   ③ 续跑复用:同一解包目录再跑(同种子),组件标记恢复随机名 —— 桩不搬家、
#      调用点不漂移、旧密文仍指向同一桩
#   ④ --stub-name 与已有随机桩不一致 → fail-fast(换名=旧密文全乱码,必须拒绝)
#
# 【依赖】python3 + encrypt-strings.py;不需要 apktool/d8(汇编覆盖在 smoke,
#          与名字无关)。固定名路径的算法正确性由 smoke/crosscheck/resume 覆盖。
# 【用法】bash scripts/string-enc/tests/test-stub-randomize.sh
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ENC="$(dirname "$_HERE")/encrypt-strings.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

chk() { # chk <说明> <命令...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then echo "  ✅ $desc"; else
    echo "  ❌ $desc"; echo "    (命令: $*)" >&2; exit 1; fi
}

# ── 最小解包目录(与 smoke 同款 demo:4 条字符串含空串) ──
make_dec() { # $1 = 目录
  mkdir -p "$1/smali/com/demo"
  cat > "$1/smali/com/demo/Demo.smali" <<'SMALI'
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
  printf 'com.demo.**\n' > "$1/../rules.txt"
}

echo "══ ①② 首跑:不传 --stub-name,桩名必须随机 ══"
make_dec "$WORK/dec"
python3 "$_ENC" "$WORK/dec" "$WORK/rules.txt" --seed-hex 0123456789abcdef --quiet

STAMP="$WORK/dec/stringenc-components.json"
chk "组件标记存在" test -f "$STAMP"
STUB_PATH="$(python3 -c "import json,sys;print(json.load(open('$STAMP'))['classes'][0]['src'])")"
chk "标记指向的桩文件存在" test -f "$WORK/dec/$STUB_PATH"
chk "① 产物零 legacy 痕迹(全目录)" \
    bash -c "! grep -rq 'com/nc/strdec\|com\.nc\.strdec\|StrDec' '$WORK/dec'"
STUB_DESC_NEW="$(python3 -c "import json;print(json.load(open('$STAMP'))['classes'][0]['desc'])")"
chk "② 随机描述符 ≠ legacy" bash -c "[ '$STUB_DESC_NEW' != 'Lcom/nc/strdec/StrDec;' ]"
chk "② 调用点指向随机描述符" \
    grep -q "invoke-static/range {v0 .. v0}, ${STUB_DESC_NEW}->" "$WORK/dec/smali/com/demo/Demo.smali"
STUB_METHOD_NEW="$(python3 -c "
import re
c=open('$WORK/dec/$STUB_PATH').read()
print(re.search(r'^\.method public static (\S+)\(Ljava/lang/String;\)',c,re.M).group(1))")"
chk "② 随机方法名 ≠ legacy" bash -c "[ '$STUB_METHOD_NEW' != 'd' ]"

echo "══ ③ 续跑:同目录再跑,随机名必须复用 ══"
python3 "$_ENC" "$WORK/dec" "$WORK/rules.txt" --seed-hex 0123456789abcdef --quiet
STUB_PATH2="$(python3 -c "import json;print(json.load(open('$STAMP'))['classes'][0]['src'])")"
chk "③ 桩路径不变(没搬家)" bash -c "[ '$STUB_PATH2' = '$STUB_PATH' ]"
chk "③ 桩文件仍是同一份(标记同在)" grep -q "nc-strdec-gen" "$WORK/dec/$STUB_PATH2"
N_CALLS="$(grep -c "${STUB_DESC_NEW}->" "$WORK/dec/smali/com/demo/Demo.smali" || true)"
chk "③ 调用点仍指向同一随机桩(=3 条加密行)" bash -c "[ '$N_CALLS' -ge 3 ]"

echo "══ ④ --stub-name 与已有随机桩不一致 → fail-fast ══"
if python3 "$_ENC" "$WORK/dec" "$WORK/rules.txt" --seed-hex 0123456789abcdef \
     --stub-name com.nc.strdec.StrDec:d --quiet 2>/dev/null; then
  echo "  ❌ 不一致未拒绝(旧密文会全乱码,必须 fail-fast)"; exit 1
else
  echo "  ✅ 不一致被拒绝"
fi

echo
echo "✅ 桩随机化验收全绿"
