#!/usr/bin/env bash
# build-stub.sh — 解密桩编译链: StrDec.java → javac → d8 → baksmali → StrDec.smali
#
# 【为什么这条链存在】
# 手写 smali 桩的可维护性已被历史报错(二十一/二十二/二十五)反复证伪。本链把
# smali 降级为自动生成的中间产物:算法只改 StrDec.java,重跑本脚本即得新 smali,
# 人永远不碰 StrDec.smali。
#
# 【用法】build-stub.sh [输出目录]
# 【产物】
#   <输出目录>/StrDec.smali  — 解密桩骨架(无占位符,可直接汇编),
#                              含一个哨兵种子常量,由 encrypt-strings.py 结构性
#                              替换为真种子(见下"SEED 注入契约")。
#   默认输出目录 = 本脚本所在目录 stub-src/(仓库内的骨架缓存),
#   与 encrypt-strings.py 的读取路径 stub-src/StrDec.smali 一致 —— 勿改此语义。
#   注:产物文件名固定为 StrDec.smali(不带包路径),因为它只是"类体片段"的载体,
#   真正的类名/包名已在 smali 内的 .class 行里写死为 Lcom/nc/strdec/StrDec;。
#
# 【SEED 注入契约(与 encrypt-strings.py 共同维护,勿单方面改)】
# 本脚本用哨兵种子 0x5EED000000000000 编译。d8 的行为(已实测):
#   * SEED 初值非 0 → 保留 `.field private static final SEED:J = 0x...L`
#   * 同时把种子【内联】到每个使用点(const-wide vX, 0x...L)
# 所以 encrypt-strings.py 必须做【双锚点一致性注入】:`.field` 初值与所有内联
# 常量同时改写为真种子,且改写数量守恒(错一个 → 运行期与构建期密钥流不一致,
# 全包字符串乱码)。本脚本产出后自检这两个锚点都存在,缺失即 fail-fast。
#
# 【依赖】
#   javac        — JDK(本机已有)
#   tools/d8.jar — 仓库内固定版本 D8(r8 9.3.16,与 apktool.jar 同待遇)
#   android-all.jar — $STUB_ANDROID_JAR 或 robolectric 默认路径(编译期 classpath,
#                     提供 android.util.Base64)
#   apktool.jar  — 仓库内 tools/dcc/tools/apktool.jar(dcc.zip 解压产物,提供 baksmali)
set -euo pipefail

_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_ROOT="$(dirname "$(dirname "$_HERE")")"                      # scripts/string-enc → 仓库根
APKTOOL="${_ROOT}/tools/dcc/tools/apktool.jar"

SRC="$_HERE/stub-src/StrDec.java"
OUT_DIR="${1:-$_HERE/stub-src}"

D8_JAR="${STUB_D8:-$_HERE/tools/d8.jar}"
ANDROID_JAR="${STUB_ANDROID_JAR:-$HOME/tmp/toolchain/android-all.jar}"

# 哨兵种子:非 0,使 d8 保留 SEED 字段初值并内联(见"SEED 注入契约")
SENTINEL_SEED="0x5eed000000000000L"

for f in "$SRC" "$APKTOOL" "$D8_JAR" "$ANDROID_JAR"; do
  [ -f "$f" ] || { echo "❌ 缺依赖: $f (见脚本头部注释)" >&2; exit 1; }
done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 1) javac。源码里的 SEED 初值是占位形态(0L + /*%SEED_LITERAL%*/),
#    编译前先在临时副本里换成哨兵种子 —— 绝不回写仓库里的 StrDec.java。
mkdir -p "$WORK/src" "$WORK/classes"
sed "s|private static final long SEED = 0L;.*|private static final long SEED = ${SENTINEL_SEED};|" \
    "$SRC" > "$WORK/src/StrDec.java"
grep -q "SEED = ${SENTINEL_SEED};" "$WORK/src/StrDec.java" \
  || { echo "❌ 哨兵种子替换失败: StrDec.java 的 SEED 声明行形态变了(见 build-stub.sh 契约)" >&2; exit 1; }

javac -cp "$ANDROID_JAR" -d "$WORK/classes" "$WORK/src/StrDec.java"

# 2) d8 → dex
mkdir -p "$WORK/dex"
find "$WORK/classes" -name '*.class' -print0 | xargs -0 \
  java -cp "$D8_JAR" com.android.tools.r8.D8 --release --min-api 26 --output "$WORK/dex"

# 3) dex → apk zip → baksmali(apktool 只吃 apk/dex 容器,不吃裸 dex 文件)
python3 - "$WORK" <<'PY'
import sys, zipfile
work = sys.argv[1]
with zipfile.ZipFile(f"{work}/stub.apk", "w") as z:
    z.write(f"{work}/dex/classes.dex", "classes.dex")
PY
java -jar "$APKTOOL" d -f -r --no-res -o "$WORK/smali_out" "$WORK/stub.apk" >/dev/null 2>&1

SMALI="$WORK/smali_out/smali/StrDec.smali"
[ -f "$SMALI" ] || { echo "❌ baksmali 未产出 StrDec.smali" >&2; exit 1; }

# 4) 修整 smali: StrDec → Lcom/nc/strdec/StrDec,并去掉 .line/.source 调试信息。
#    产物直接落在 <OUT_DIR>/StrDec.smali(与 encrypt-strings.py 的读取路径一致)
OUT_SMALI="$OUT_DIR/StrDec.smali"
mkdir -p "$OUT_DIR"
python3 - "$SMALI" "$OUT_SMALI" "$SENTINEL_SEED" <<'PY'
import re, sys
src, dst, sentinel = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(src, encoding='utf-8').read()

# 自引用改全名(<init> 的 invoke-direct 等)
text = text.replace('LStrDec;', 'Lcom/nc/strdec/StrDec;')
text = text.replace('.class public final Lcom/nc/strdec/StrDec;',
                    '.class public final Lcom/nc/strdec/StrDec;')

# 去掉调试信息行(.line N)——产物是加固桩,不需要,且能缩小体积
text = '\n'.join(l for l in text.split('\n')
                 if not re.match(r'^[ \t]*\.line[ \t]+\d+[ \t]*$', l))

# 自检 1: SEED 字段初值锚点必须存在(d8 保留初值的前提是种子非 0)
field_re = re.compile(
    r'^[ \t]*\.field[ \t]+[^\n]*?\bSEED:J[ \t]*=[ \t]*(\S+)[ \t]*$', re.M)
m = field_re.search(text)
if not m:
    raise SystemExit(
        '❌ 桩骨架缺少 `.field ... SEED:J = <初值>` 锚点。\n'
        '   d8 在种子为 0 时会把它优化掉 → encrypt-strings.py 无法注入种子。\n'
        '   检查 build-stub.sh 的哨兵种子是否为非 0 常量。')
# d8 用十六进制小写输出(0x5eed...),同时容忍带注释尾缀的形态
sval = m.group(1)
if int(sval.split('L')[0], 16) != int(sentinel.rstrip('Ll'), 16):
    raise SystemExit(f'❌ 桩骨架 SEED 初值不是哨兵种子: {sval}(期望 {sentinel})')

# 自检 2: 哨兵种子必须至少内联出现在一处(否则说明 d8 没内联,契约变了)。
# d8 视种子大小选变体: const-wide / const-wide/high16(高位非零常见) / const-wide/16。
inline = re.findall(r'const-wide(?:/\w+)?[ \t]+[vp]\d+,[ \t]*'
                    + re.escape(sval.split('L')[0]) + r'L?', text)
if not inline:
    raise SystemExit(
        '❌ 桩骨架里找不到内联的哨兵种子常量(预期 const-wide vX, 0x5eed...L)。\n'
        '   d8 的常量内联行为变了 → encrypt-strings.py 的双锚点注入契约需要重审。')

# 自检 3: 不允许残留 .source(原始 Java 文件名会泄露实现语言)
text = re.sub(r'^[ \t]*\.source[ \t]+.*\n', '', text, flags=re.M)

open(dst, 'w', encoding='utf-8').write(text)
print(f'✅ 桩编译完成: {dst}')
print(f'   SEED 字段锚点 1 处 + 内联锚点 {len(inline)} 处(哨兵 {sentinel})')
PY
