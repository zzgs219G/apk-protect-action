#!/usr/bin/env bash
# test-structure-resume.sh — A3(续跑 offset 不重叠)+ A4(结构合法性)验收。
#
# 【为什么单独立一个(与 test-encrypt-smoke.sh 的分工)】
# 冒烟测的是"单次运行产物形态对不对";本测试测两个冒烟覆盖不到的**跨运行/结构**
# 性质:
#   A3 续跑: 第二轮只加密【新增类】时,offset 必须从既有水位线之后继续分配。
#            同一 offset 若配两把密钥 → 区段复用 → 密文互解,是静默正确性事故。
#            验证方式是**真闭环**:把两轮产物里的密文全抽出来,用同一份编译桩
#            逐条解密回原文(不是"看着像对",而是真解出来)。
#   A4 结构: 产物不得出现 FIELD 型(0x19) static_value 的任何形态;桩里密钥材料
#            只能有 SEED 一个,且无哨兵残留/无占位符/无 .line/.source。
#
# 【依赖】javac(JDK17)、python3。不需要 android.jar(用 shims 顶替 Base64)。
# 【用法】bash scripts/string-enc/tests/test-structure-resume.sh
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_SENC="$(dirname "$_HERE")/encrypt-strings.py"
_STUB_SRC="$(dirname "$_HERE")/stub-src/StrDec.java"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DEC="$WORK/decompiled"
SEED=0123456789abcdef

mkdir -p "$DEC/smali/com/demo"
# 第一轮:两个类,含中英混合与空串
cat > "$DEC/smali/com/demo/A1.smali" <<'SMALI'
.class public Lcom/demo/A1;
.super Ljava/lang/Object;

.method public static run()V
    .locals 2

    const-string v0, "first class ascii"
    const-string v0, "第一类中文"
    const-string v0, ""
    return-void
.end method
SMALI
cat > "$DEC/smali/com/demo/A2.smali" <<'SMALI'
.class public Lcom/demo/A2;
.super Ljava/lang/Object;

.field public static final TAG:Ljava/lang/String; = "tag-value-plain"

.method public static run()V
    .locals 2

    const-string v0, "second class emoji \uD83C\uDF89"
    return-void
.end method
SMALI
printf 'com.demo.**\n' > "$WORK/rules.txt"

fail=0
chk() { if eval "$2"; then echo "  ✅ $1"; else echo "  ❌ $1"; fail=$((fail+1)); fi; }

echo "══ 第一轮(2 个类,固定种子 $SEED)══"
python3 "$_SENC" "$DEC" "$WORK/rules.txt" --seed-hex "$SEED" --quiet
STUB="$DEC/smali/com/nc/strdec/StrDec.smali"
[ -f "$STUB" ] || { echo "❌ 桩未注入" >&2; exit 1; }

# ── 辅助:从解包目录收集全部密文 payload / 检查 offset 区段重叠 ──────
collect_ciphers() {   # collect_ciphers <out.txt>  → stdout: 密文条数
  python3 - "$DEC" "$1" <<'PYEOF'
import os, re, sys
root, out = sys.argv[1], sys.argv[2]
pat = re.compile(
    r'const-string(?:/jumbo)?\s+(?:v\d+|p\d+)\s*,\s*"([^"\n]*)"\n'
    r'\s*invoke-static(?:/range)? \{[^}\n]*\}, Lcom/nc/strdec/StrDec;->d\(')
seen = []
for dirpath, _d, files in os.walk(root):
    for f in files:
        if not f.endswith('.smali'):
            continue
        src = open(os.path.join(dirpath, f), encoding='utf-8').read()
        for m in pat.finditer(src):
            seen.append(m.group(1))
with open(out, 'w', encoding='utf-8') as fp:
    fp.write('\n'.join(seen) + ('\n' if seen else ''))
print(len(seen))
PYEOF
}

check_offsets() {     # check_offsets <cipher.txt>  → stdout: 重叠区段数
  python3 - "$1" <<'PYEOF'
import base64, sys
spans = []
for line in open(sys.argv[1], encoding='utf-8'):
    line = line.strip()
    if not line:
        continue
    raw = base64.b64decode(line, validate=True)
    off = int.from_bytes(raw[:3], 'big')
    spans.append((off, off + len(raw) - 3))
spans.sort()
print(sum(1 for (s1, e1), (s2, e2) in zip(spans, spans[1:]) if s2 < e1))
PYEOF
}

collect_ciphers "$WORK/c1.txt" > /dev/null
N1="$(grep -c . "$WORK/c1.txt" || true)"
echo "  第一轮密文条数: $N1"
chk "第一轮 offset 区段无重叠" "[ \"\$(check_offsets '$WORK/c1.txt')\" = 0 ]"

# 真闭环:编译桩,解第一轮每条密文,比对期望明文
build_stub() {
  rm -rf "$WORK/build"
  mkdir -p "$WORK/build/com/nc/strdec" "$WORK/build/cls"
  sed "s|private static final long SEED = 0L;.*|private static final long SEED = 0x$1L;|" \
      "$_STUB_SRC" > "$WORK/build/com/nc/strdec/StrDec.java"
  sed -i '1i package com.nc.strdec;' "$WORK/build/com/nc/strdec/StrDec.java"
  grep -q "SEED = 0x$1L;" "$WORK/build/com/nc/strdec/StrDec.java" \
    || { echo "❌ SEED 注入失败(seed=$1)" >&2; exit 1; }
  javac -d "$WORK/build/cls" \
        "$_HERE/shims/android/util/Base64.java" \
        "$WORK/build/com/nc/strdec/StrDec.java" "$_HERE/P5Decode.java"
}
build_stub "$SEED"

# 期望明文清单(与上面 cipher 收集顺序一致: A1 → A2,类内按出现顺序;
# 空串不加密所以不出现在密文里,故期望清单也不含它)
python3 - "$WORK/expect.txt" <<'PYEOF'
import sys
plains = ["first class ascii", "第一类中文",
          "second class emoji \U0001F389", "tag-value-plain"]
with open(sys.argv[1], 'w', encoding='utf-8') as fp:
    for p in plains:
        fp.write(p + '\n')
PYEOF

# 把 密文 与 明文 配对成 TSV(明文字面量做 Java 转义)
python3 - "$WORK/c1.txt" "$WORK/expect.txt" "$WORK/pairs1.tsv" <<'PY'
import sys
ciphers = [l.strip() for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
plains = [l.rstrip('\n') for l in open(sys.argv[2], encoding='utf-8') if l != '']
def esc(s):
    # 非 BMP 字符(emoji)必须先按 UTF-16 拆成代理对,再逐 unit 转义 ——
    # Java 的 \uXXXX 是 UTF-16 code unit 语义,直接写 \u1f389 是非法写法。
    o = []
    data = s.encode('utf-16-be')
    for i in range(0, len(data), 2):
        u = int.from_bytes(data[i:i + 2], 'big')
        ch = chr(u)
        if ch == '\\': o.append('\\\\')
        elif ch == '\t': o.append('\\t')
        elif ch == '\n': o.append('\\n')
        elif ch == '\r': o.append('\\r')
        elif u > 0x7E: o.append('\\u%04x' % u)
        else: o.append(ch)
    return ''.join(o)
assert len(ciphers) == len(plains), f"密文 {len(ciphers)} 条 / 明文 {len(plains)} 条,数量不匹配"
with open(sys.argv[3], 'w', encoding='utf-8') as fp:
    for c, p in zip(ciphers, plains):
        fp.write(esc(p) + '\t' + c + '\n')
PY
echo "  ── A3 真闭环:用编译桩解第一轮产物密文 ──"
if java -cp "$WORK/build/cls" P5Decode "$WORK/pairs1.tsv"; then
  echo "  ✅ 第一轮产物密文全部解回原文"
else
  echo "  ❌ 第一轮产物密文解密失败"; fail=$((fail+1))
fi

echo
echo "══ 第二轮(只加密新增类 A3,复用种子)══"
cat > "$DEC/smali/com/demo/A3.smali" <<'SMALI'
.class public Lcom/demo/A3;
.super Ljava/lang/Object;

.method public static run()V
    .locals 2

    const-string v0, "third class new string"
    return-void
.end method
SMALI
python3 "$_SENC" "$DEC" "$WORK/rules.txt" --quiet

# 旧类必须字节不变(幂等:不重复加密)
collect_ciphers "$WORK/c2.txt" > /dev/null
N2=$(grep -c . "$WORK/c2.txt" || true)
echo "  第二轮密文条数: $N2 (应 = $((N1 + 1)))"
chk "第二轮新增 1 条密文" "[ '$N2' = '$((N1 + 1))' ]"
chk "种子未被重生成" "grep -q \"SEED:J = 0x${SEED}L\" '$STUB'"

echo "  ── A3 关键:两轮密文合并后仍无 offset 重叠 ──"
OLAP=$(python3 -c "
import base64,sys
spans=[]
for l in open('$WORK/c2.txt'):
    l=l.strip()
    if not l: continue
    raw=base64.b64decode(l,validate=True)
    o=int.from_bytes(raw[:3],'big'); spans.append((o,o+len(raw)-3))
spans.sort()
print(sum(1 for a,b in zip(spans,spans[1:]) if b[0]<a[1]))
")
echo "    重叠区段数 = $OLAP"
chk "两轮密文 offset 零重叠(A3)" "[ '$OLAP' = 0 ]"

echo "  ── A3 真闭环:合并后每条密文都能解回原文 ──"
python3 - "$WORK/c2.txt" "$WORK/expect2.txt" <<'PY'
import sys
# 遍历顺序: A1, A2, A3(字典序), 类内按出现顺序
plains = ["first class ascii", "第一类中文",
          "second class emoji \U0001F389", "tag-value-plain",
          "third class new string"]
def esc(s):
    # 非 BMP 字符(emoji)必须先按 UTF-16 拆成代理对,再逐 unit 转义 ——
    # Java 的 \uXXXX 是 UTF-16 code unit 语义,直接写 \u1f389 是非法写法。
    o = []
    data = s.encode('utf-16-be')
    for i in range(0, len(data), 2):
        u = int.from_bytes(data[i:i + 2], 'big')
        ch = chr(u)
        if ch == '\\': o.append('\\\\')
        elif ch == '\t': o.append('\\t')
        elif ch == '\n': o.append('\\n')
        elif ch == '\r': o.append('\\r')
        elif u > 0x7E: o.append('\\u%04x' % u)
        else: o.append(ch)
    return ''.join(o)
ciphers = [l.strip() for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
with open(sys.argv[2], 'w', encoding='utf-8') as fp:
    for c, p in zip(ciphers, plains):
        fp.write(esc(p) + '\t' + c + '\n')
PY
if java -cp "$WORK/build/cls" P5Decode "$WORK/expect2.txt"; then
  echo "  ✅ 续跑后全部密文(含旧密文)解回原文"
else
  echo "  ❌ 续跑后解密失败"; fail=$((fail+1))
fi

echo
echo "══ A4 结构断言 ══"
ALL="$WORK/all.smali"
cat "$DEC"/smali/com/demo/*.smali > "$ALL"
chk "无 FIELD 型 static_value(非法形态)" "! grep -qE '\.field[^\n]*=[ \t]*Lcom/nc/strdec/StrDec;->F' '$ALL'"
chk "无 F000000 桩字段残留" "! grep -q 'F000000' '$ALL'"
chk "桩密钥材料只有 SEED(其余字段均为算法常量)" \
    "[ \"\$(grep -E '^[ \t]*\.field' '$STUB' | grep -c 'SEED:J')\" = 1 ] && \
     [ \"\$(grep -E '^[ \t]*\.field' '$STUB' | grep -cvE '(SEED|GAMMA):J')\" = 0 ]"
chk "桩 SEED 为非 0 真种子" "grep -q \"SEED:J = 0x${SEED}L\" '$STUB'"
chk "桩零哨兵残留" "! grep -qi '5eed' '$STUB'"
chk "桩无占位符残留" "! grep -q '%' '$STUB'"
chk "桩无 .line/.source" "! grep -qE '^\s*\.(line|source)' '$STUB'"
chk "桩无 KEYS 表(S2 零表)" "! grep -qE 'KEYS|short\[\]|\[S\b' '$STUB'"

echo
if [ "$fail" -ne 0 ]; then
  echo "❌ A3/A4 验收失败: $fail 项" >&2
  exit 1
fi
echo "✅ A3 续跑 + A4 结构 全绿"
