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

echo "══ ⑤ 派生物同步:随机名应用后,派生正则/分类锚点必须同源重建(报错四十八回归)══"
python3 - "$_HERE/.." <<'PY'
import importlib.util, re, sys
spec = importlib.util.spec_from_file_location('enc', sys.argv[1] + '/encrypt-strings.py')
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
m.apply_stub_identifiers('ab.cd.ef', 'Qx', 'qy')
assert m.STUB_DOT == 'ab.cd.ef.Qx', f'STUB_DOT 未随随机名重建: {m.STUB_DOT}'
sample = ('const-string v0, "AAAA"\n'
          'invoke-static/range {v0 .. v0}, Lab/cd/ef/Qx;->qy(Ljava/lang/String;)Ljava/lang/String;\n')
assert m._PAYLOAD_RE.search(sample), '水位线正则不认随机名密文(报错四十八)'
assert m._ILLEGAL_FIELD_INIT_RE.search(
    '.field public static final X:Ljava/lang/String; = Lab/cd/ef/Qx;->F000000:'), \
    '报错二十四断言不认随机名(报错四十八)'
assert m.classify('ab.cd.ef.Qx', 'Lab/cd/ef/Qx;', [re.compile('.*')], []) == 'stub', \
    '随机桩名被误分类为业务类(报错四十八)'
viol = ('.method public static d(Ljava/lang/String;)Ljava/lang/String;\n'
        '    .locals 2\n    const/4 p0, 0x0\n    return-object p0\n.end method\n')
try:
    m._check_stub_registers(viol, 'd')
    raise SystemExit('报错二十二守卫在随机方法名下失效(报错四十八)')
except SystemExit as e:
    if '参数寄存器' not in str(e):
        raise
print('  ✅ ⑤ 派生物同步断言全部通过(STUB_DOT/水位线正则/二十四断言/classify/二十二锚点)')
PY

echo "══ ⑥ ** 规则两轮:续跑水位线 + 桩自身零污染(报错四十八回归)══"
DEC2="$WORK/dec2"
mkdir -p "$DEC2/smali/com/demo"
cat > "$DEC2/smali/com/demo/A.smali" <<'SMALI'
.class public Lcom/demo/A;
.super Ljava/lang/Object;

.method public static run()V
    .locals 1

    const-string v0, "alpha string one"
    const-string v0, "beta string two"
    return-void
.end method
SMALI
printf '**\n' > "$WORK/rules2.txt"
python3 "$_ENC" "$DEC2" "$WORK/rules2.txt" --seed-hex 0123456789abcdef --quiet
cat > "$DEC2/smali/com/demo/B.smali" <<'SMALI'
.class public Lcom/demo/B;
.super Ljava/lang/Object;

.method public static run()V
    .locals 1

    const-string v0, "gamma string three"
    return-void
.end method
SMALI
python3 "$_ENC" "$DEC2" "$WORK/rules2.txt" --seed-hex 0123456789abcdef --quiet
STUB2="$(python3 -c "import json;print(json.load(open('$DEC2/stringenc-components.json'))['classes'][0]['src'])")"
chk "⑥ 桩自身未被二次加密(无类标记)" \
    bash -c "! grep -q 'nc-strdec-encrypted' '$DEC2/$STUB2'"
chk "⑥ 桩内 UTF-8 仍为明文" \
    grep -q 'const-string v1, "UTF-8"' "$DEC2/$STUB2"
python3 - "$DEC2" <<'PY'
import base64, json, os, re, sys
root = sys.argv[1]
stamp = json.load(open(os.path.join(root, 'stringenc-components.json')))['classes'][0]
stub = open(os.path.join(root, stamp['src']), encoding='utf-8').read()
meth = re.search(r'^\.method public static (\S+)\(Ljava/lang/String;\)', stub, re.M).group(1)
pat = re.compile(
    r'const-string(?:/jumbo)?\s+(?:v\d+|p\d+)\s*,\s*"([^"\n]*)"\n'
    r'\s*invoke-static(?:/range)? \{[^}\n]*\}, '
    + re.escape(stamp['desc']) + r'->' + re.escape(meth) + r'\(')
spans = []
for dp, _d, fs in os.walk(root):
    for f in fs:
        if not f.endswith('.smali'):
            continue
        c = open(os.path.join(dp, f), encoding='utf-8').read()
        for mm in pat.finditer(c):
            raw = base64.b64decode(mm.group(1), validate=True)
            off = int.from_bytes(raw[:3], 'big')
            spans.append((off, off + len(raw) - 3))
spans.sort()
olap = sum(1 for (s1, e1), (s2, e2) in zip(spans, spans[1:]) if s2 < e1)
assert len(spans) == 3, f'密文条数异常: {spans}'
assert olap == 0, f'续跑水位线失效,重叠区段: {spans}'
print('  ✅ ⑥ 两轮密文区段零重叠(水位线在随机名下正确)')
PY

echo
echo "✅ 桩随机化验收全绿"
