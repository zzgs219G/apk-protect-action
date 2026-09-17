#!/usr/bin/env bash
# test-probes.sh — light-obf 阶段 0 可行性探针(开发文档-light-obf.md §6 阶段 0)
# 探针结果(含 jadx/apktool 版本)写进开发文档附录,作为 --charset 默认值的依据。
# 可重跑。
#
# 用法: bash test-probes.sh [--skip-p1]
#   --skip-p1  跳过 P1 往返(无 java/apktool 环境时;P2 仍执行)
#
# 通过标准(开发文档 §6):
#   P1  合成含 U+06DB 方法名/字段名的 smali → apktool b → apktool d →
#       往返后标识符逐字节一致,回编 exit 0
#   P2  encrypt-strings.py 的 _FIELD_RE / _FIELD_STRING_LITERAL_RE 对
#       Unicode 字段名命中 → unicode 路线可直接启用;不命中 → 启用前提是
#       同批更新两正则(§5.2 消费者清单),否则选 ascii 路线
#   P3  jadx 显示:仅记录现象(无 jadx 环境时记 SKIPPED),不作为否决项
#   P4  ART 运行期:冷启动不崩、被改名方法可调用(无真机时记 SKIPPED)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
APKTOOL="$ROOT/tools/dcc/tools/apktool.jar"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0; SKIP=0
record() {  # record <name> <PASS|FAIL|SKIPPED> <detail>
    printf '[%s] %s: %s\n' "$2" "$1" "$3"
    case "$2" in
        PASS) PASS=$((PASS+1));;
        FAIL) FAIL=$((FAIL+1));;
        *)    SKIP=$((SKIP+1));;
    esac
}

# ── P1: baksmali→smali 往返(unicode 标识符经 apktool 回编再反编译) ──
probe_p1() {
    # U+06DB ۛ 阿拉伯区分音符(NP 样本同源字符集)
    local M='ۛ۟ۗ' F='ۛۗۨ'
    mkdir -p "$WORK/prj/smali/com/demo"
    # 最小 apktool 工程(string-enc test-encrypt-smoke.sh ⑨ 先例):
    # 只需 apktool.yml(version 一行)即可汇编纯 smali 目录,无需 Manifest/资源
    printf 'version: 2.9.3\n' > "$WORK/prj/apktool.yml"
    cat > "$WORK/prj/smali/com/demo/P.smali" <<EOF
.class public Lcom/demo/P;
.super Ljava/lang/Object;

.field private $F:I

.method public constructor <init>()V
    .locals 0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method private $M(I)I
    .locals 1
    add-int/2addr p1, p1
    return p1
.end method

.method public callIt(I)I
    .locals 1
    invoke-direct {p0, p1}, Lcom/demo/P;->$M(I)I
    move-result p1
    return p1
.end method
EOF
    if ! java -jar "$APKTOOL" b -o "$WORK/p1.apk" "$WORK/prj" >"$WORK/p1_b.log" 2>&1; then
        record P1 FAIL "apktool b 失败: $(grep -vE '^I:' "$WORK/p1_b.log" | tail -2 | tr '\n' ' ')"
        return
    fi
    if ! java -jar "$APKTOOL" d -f -o "$WORK/p1_back" "$WORK/p1.apk" >"$WORK/p1_d.log" 2>&1; then
        record P1 FAIL "apktool d 失败: $(grep -vE '^I:' "$WORK/p1_d.log" | tail -2 | tr '\n' ' ')"
        return
    fi
    local BACK="$WORK/p1_back/smali/com/demo/P.smali"
    # 逐字节对比:方法名/字段名必须在二次产物中原样出现
    if grep -q "$M" "$BACK" && grep -q "$F" "$BACK"; then
        record P1 PASS "U+06DB 标识符往返逐字节一致(方法名+字段名+invoke 引用), apktool $(java -jar "$APKTOOL" --version 2>/dev/null | tail -1)"
    else
        record P1 FAIL "往返后 U+06DB 标识符丢失/被改写"
    fi
}

# ── P2: stringenc 正则兼容(_FIELD_RE / _FIELD_STRING_LITERAL_RE) ──
probe_p2() {
    UNI='ۛۗۨ' ASCII_SUFFIX='field~ab12cd'
    python3 - "$ROOT" "$UNI" "$ASCII_SUFFIX" <<'EOF'
import importlib.util, os, sys
root, UNI, ASCII_SUFFIX = sys.argv[1], sys.argv[2], sys.argv[3]
spec = importlib.util.spec_from_file_location('es', os.path.join(root, 'scripts/string-enc/encrypt-strings.py'))
es = importlib.util.module_from_spec(spec)
spec.loader.exec_module(es)

fails = []
for label, fname in (('U+06DB', UNI), ('ascii-suffix', ASCII_SUFFIX)):
    field_line = f'.field private {fname}:Ljava/lang/String; = "v"'
    lit_line   = f'.field private static final {fname}:Ljava/lang/String; = "s"'
    ok_f = bool(es._FIELD_RE.search(field_line))
    ok_l = bool(es._FIELD_STRING_LITERAL_RE.search(lit_line))
    print(f'    {label}: _FIELD_RE={"HIT" if ok_f else "MISS"}  _FIELD_STRING_LITERAL_RE={"HIT" if ok_l else "MISS"}')
    if label == 'U+06DB':
        uni = (ok_f, ok_l)
    else:
        asc = (ok_f, ok_l)

uni_f, uni_l = uni
asc_f, asc_l = asc
verdict = []
if uni_f and uni_l:
    verdict.append('unicode 路线可直接启用(P2 通过)')
else:
    verdict.append('unicode 路线启用前提 = 同批更新 _FIELD_RE/_FIELD_STRING_LITERAL_RE(§5.2),否则选 ascii')
if asc_f and asc_l:
    verdict.append('ascii 路线 P2 通过')
else:
    verdict.append('ascii 路线 P2 不通过(须同批评估正则)')
print('    P2 结论: ' + '; '.join(verdict))
sys.exit(0 if (asc_f and asc_l) else 1)
EOF
    local rc=$?
    if [ $rc -eq 0 ]; then
        record P2 PASS "见上方逐项 HIT/MISS 与结论(ascii 命中为门控必达;unicode 按结论决定路线)"
    else
        record P2 FAIL "ascii 路线正则未命中 —— ascii 后缀名会逃过 stringenc 字段扫描,须先同批更新正则"
    fi
}

# ── P3: jadx 显示现象(仅记录,不否决) ──
probe_p3() {
    if command -v jadx >/dev/null 2>&1; then
        if jadx -d "$WORK/p3" "$WORK/p1.apk" >"$WORK/p3.log" 2>&1; then
            record P3 PASS "jadx 反编译完成,显示现象留待人工查看(正式启用 unicode 前需留档记录 jadx 版本)"
        else
            record P3 FAIL "jadx 反编译崩溃(unicode 标识符触发解析异常)"
        fi
    else
        record P3 SKIPPED "jadx 不可用(仅记录项,不否决;GitHub Actions 或桌面端重跑可补)"
    fi
}

# ── P4: ART 运行期(需真机) ──
probe_p4() {
    if command -v adb >/dev/null 2>&1 && adb devices 2>/dev/null | grep -qw 'device$'; then
        record P4 SKIPPED "adb 可用但真机安装验证属阶段 1 验收范围(实现 light-obf 后补测)"
    else
        record P4 SKIPPED "adb/真机不可用(宿主环境;GitHub Actions 真机阶段补测)"
    fi
}

echo "=== light-obf 阶段 0 探针 ==="
echo "apktool: $(java -jar "$APKTOOL" --version 2>/dev/null | tail -1), java: $(java -version 2>&1 | head -1)"
echo "探针工作目录: $WORK"

if [ "${1:-}" = "--skip-p1" ]; then
    record P1 SKIPPED "(--skip-p1)"
else
    probe_p1
fi
probe_p2
probe_p3
probe_p4

echo "=== 汇总: PASS=$PASS FAIL=$FAIL SKIPPED=$SKIP ==="
# 探针门控:FAIL > 0 → 阶段 1 不得进入(P2 FAIL 意味着两条路线都被堵)
[ $FAIL -eq 0 ]
