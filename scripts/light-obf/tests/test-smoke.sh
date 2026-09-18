#!/usr/bin/env bash
# test-smoke.sh — light-obf 阶段 1+2(变换 D/B/A)冒烟测试(合成 smali,无需 apktool)
# 开发文档-light-obf.md §8 断言点(v3 语义):
#   ① 变换生效计数(private 方法/字段确实改名) ② 幂等(重跑零 diff)
#   ③ 确定性(同 seed 双跑输出一致;不同 seed 输出不同)
#   ④ 零膨胀断言(变换 D 不增删指令行;方法体行数守恒)
#   ⑤ 硬排除名单零触碰(Manifest 组件/R$/access$/annotation 成员/native 类/
#      com.nc. 桩/反射类/序列化注解类)
#   ⑥ 引用计数守恒(跨文件引用全部同步改名,构建期断言兜底)
#   ⑦ --clean 撤销变换 D(--map 反查)并清标记;无 map fail-fast(v3 §5.1)
#   ⑧ 字符集路线打印断言(ascii,防静默降级)
#   ⑨ fail-fast:--charset unicode / 未实现变换 / B/A 孤儿标记 → 拒绝并报错
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
LIGHT_OBF="$ROOT/scripts/light-obf/light-obf.py"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

die() { echo "❌ $*" >&2; exit 1; }

mkdir -p "$WORK/dec/smali/com/demo" "$WORK/dec/smali/com/nc/strdec"

# Manifest(apktool 解包后为文本 AXML):声明 MainActivity 为组件 → 硬排除
cat > "$WORK/dec/AndroidManifest.xml" <<'MF'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.demo">
    <application android:name="com.demo.MainActivity">
        <activity android:name="com.demo.MainActivity"/>
    </application>
</manifest>
MF

# ── 合成类:覆盖全部断言形态 ─────────────────────────────────────────
# A: private 方法+字段(改名对象) / public 成员(不改) / annotation 成员(不改)
#    / access$ 桥(桥名不改,桥体内引用要改) / 字符串字面量含引用形态(不碰)
# B: 跨类引用 A 的 private 成员(②类位置,必须同步改)
# C: Manifest 组件类(硬排除)
# StrDec: com.nc. 桩(硬排除,EXTRA_SKIP_PREFIXES 🔴1)
# Reflect: 反射 API 使用类(硬排除)
# Ser: 序列化注解类(硬排除)
# Ntv: native 方法类(硬排除)
# R$: 生成类(硬排除)
cat > "$WORK/dec/smali/com/demo/A.smali" <<'EOF'
.class public Lcom/demo/A;
.super Ljava/lang/Object;
.source "A.java"

.field private secret:Ljava/lang/String;
.field private cache:I
.field public open:I

.method public constructor <init>()V
    .locals 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method private compute(I)I
    .locals 2
    mul-int/lit8 v0, p1, 0x3
    iget v1, p0, Lcom/demo/A;->cache:I
    add-int/2addr v0, v1
    return v0
.end method

.method private fetch()Ljava/lang/String;
    .locals 1
    iget-object v0, p0, Lcom/demo/A;->secret:Ljava/lang/String;
    return-object v0
.end method

.method private annotated()V
    .locals 0
    .annotation runtime Landroidx/annotation/VisibleForTesting;
    .end annotation
    return-void
.end method

.method public synthetic access$100(Lcom/demo/A;)Ljava/lang/String;
    .locals 1
    invoke-direct {p0}, Lcom/demo/A;->fetch()Ljava/lang/String;
    move-result-object v0
    return-object v0
.end method

.method public call(I)I
    .locals 1
    invoke-virtual {p0, p1}, Lcom/demo/A;->compute(I)I
    move-result v0
    const-string v0, "ref like Lcom/demo/A;->secret:Ljava/lang/String; in a string"
    return v0
.end method
EOF

cat > "$WORK/dec/smali/com/demo/B.smali" <<'EOF'
.class public Lcom/demo/B;
.super Ljava/lang/Object;

.method public peek(Lcom/demo/A;I)I
    .locals 1
    invoke-virtual {p1, p2}, Lcom/demo/A;->compute(I)I
    move-result v0
    iget v0, p1, Lcom/demo/A;->cache:I
    add-int/2addr v0, v0
    return v0
.end method
EOF

cat > "$WORK/dec/smali/com/demo/MainActivity.smali" <<'EOF'
.class public Lcom/demo/MainActivity;
.super Ljava/lang/Object;

.field private state:I

.method private onStart()V
    .locals 0
    return-void
.end method
EOF

cat > "$WORK/dec/smali/com/demo/R\$id.smali" <<'EOF'
.class public final Lcom/demo/R$id;
.super Ljava/lang/Object;

.field private hidden:I
EOF

cat > "$WORK/dec/smali/com/nc/strdec/StrDec.smali" <<'EOF'
.class public Lcom/nc/strdec/StrDec;
.super Ljava/lang/Object;

.field private static final GAMMA:J = 0x1234L
.field private seed:J

.method private mix(J)J
    .locals 4
    return-wide p1
.end method
EOF

cat > "$WORK/dec/smali/com/demo/Reflect.smali" <<'EOF'
.class public Lcom/demo/Reflect;
.super Ljava/lang/Object;

.field private hidden:Ljava/lang/String;

.method private cfg()Ljava/lang/String;
    .locals 2
    const-string v0, "hidden"
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I
    move-result v1
    return-object v0
.end method

.method public boom()Ljava/lang/Object;
    .locals 1
    const-class v0, Lcom/demo/Reflect;
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;
    move-result-object v0
    check-cast v0, Ljava/lang/Object;
    return-object v0
.end method
EOF

cat > "$WORK/dec/smali/com/demo/Ser.smali" <<'EOF'
.class public Lcom/demo/Ser;
.super Ljava/lang/Object;

.field private state:I

.annotation system Lkotlinx/serialization/Serializable;
.end annotation

.method private stash()I
    .locals 1
    iget v0, p0, Lcom/demo/Ser;->state:I
    return v0
.end method
EOF

cat > "$WORK/dec/smali/com/demo/Ntv.smali" <<'EOF'
.class public Lcom/demo/Ntv;
.super Ljava/lang/Object;

.method public static native nat()V
.end method

.method private hidden()V
    .locals 0
    return-void
.end method
EOF

echo "com.demo.**" > "$WORK/rules.txt"

# ── 第 1 次运行(固定 seed) ──────────────────────────────────────────
run() { python3 "$LIGHT_OBF" "$@"; }
SEED="0011223344556677"
run "$WORK/dec" "$WORK/rules.txt" --seed "$SEED" --map "$WORK/map1.json" > "$WORK/run1.log"
cat "$WORK/run1.log"

# ⑧ 字符集路线打印断言(防静默降级)
grep -q '字符集: ascii' "$WORK/run1.log" || die '⑧ 未打印实际生效字符集'

# ① 变换生效计数:A 的 compute/fetch/secret/cache 全部改名
#   (代码形态断言;字符串字面量里的 `->secret:` 按红线 5 保留明文,不在此列)
for n in '->compute(' '->fetch(' '->cache:' \
         '.method private compute' '.method private fetch' \
         '.field private secret' '.field private cache'; do
  grep -rqFe "$n" "$WORK/dec/smali/com/demo/" && die "① private 成员未改名: $n"
done
grep -q '.method private.*~' "$WORK/dec/smali/com/demo/A.smali" || die '① 未生成 ascii 后缀新名'

# ①b: public 成员 / annotation 成员 / access$ 桥名 / <init> 不改
for n in '.field public open:I' '.method private annotated' \
         'access$100(' '.method public constructor <init>'; do
  grep -qFe "$n" "$WORK/dec/smali/com/demo/A.smali" || die "①b 不该改的被改了: $n"
done

# ⑥ 引用计数守恒(跨文件):B 里的引用必须跟着改;字符串字面量里的引用形态不碰
grep -qF 'invoke-virtual {p1, p2}, Lcom/demo/A;->' "$WORK/dec/smali/com/demo/B.smali" \
  || die '⑥ B 的 invoke 引用未同步改名'
b=$(grep -oF 'Lcom/demo/A;->' "$WORK/dec/smali/com/demo/B.smali" | wc -l)
[ "$b" -eq 2 ] || die "⑥ B 引用计数异常: $b != 2"
grep -qF '"ref like Lcom/demo/A;->secret:Ljava/lang/String; in a string"' \
  "$WORK/dec/smali/com/demo/A.smali" || die '⑥ 字符串字面量被误改'

# ⑤ 硬排除名单零触碰
grep -qF '.field private state:I' "$WORK/dec/smali/com/demo/MainActivity.smali" \
  || die '⑤ Manifest 组件类被改'
grep -qF '.field private hidden:I' "$WORK/dec/smali/com/demo/R\$id.smali" \
  || die '⑤ R$ 类被改'
grep -qF '.field private static final GAMMA:J' "$WORK/dec/smali/com/nc/strdec/StrDec.smali" \
  || die '⑤ com.nc. 桩类被改(🔴1)'
grep -qF '.method private mix(J)J' "$WORK/dec/smali/com/nc/strdec/StrDec.smali" \
  || die '⑤ com.nc. 桩方法被改'
grep -qF '.field private hidden:Ljava/lang/String;' "$WORK/dec/smali/com/demo/Reflect.smali" \
  || die '⑤ 反射类被改'
grep -qF '.field private state:I' "$WORK/dec/smali/com/demo/Ser.smali" \
  || die '⑤ 序列化注解类被改'
grep -qF '.method private hidden()V' "$WORK/dec/smali/com/demo/Ntv.smali" \
  || die '⑤ native 方法类被改'

# ④ 零膨胀:变换 D 只改名,不增删指令行(A 仅 +1 标记行)
a_lines=$(grep -c '' "$WORK/dec/smali/com/demo/A.smali")
b_lines=$(grep -c '' "$WORK/dec/smali/com/demo/B.smali")
# A: 原始 49 行 + 标记行 = 50;B: 原始 11 行 + 标记行 = 12(行数守恒)
[ "$a_lines" -eq 50 ] || die "④ 零膨胀破坏: A.smali $a_lines != 50 行"
[ "$b_lines" -eq 12 ] || die "④ 零膨胀破坏: B.smali $b_lines != 12 行"

# ② 幂等:重跑(同 seed)零 diff
cp -r "$WORK/dec" "$WORK/dec.snap1"
run "$WORK/dec" "$WORK/rules.txt" --seed "$SEED" --map "$WORK/map2.json" > /dev/null  # 幂等跑:map 不应被写
diff -r "$WORK/dec" "$WORK/dec.snap1" > /dev/null || die '② 幂等破坏(重跑产生 diff)'

# ③ 确定性:同 seed 两次首跑产物一致(用 clean 还原后重放验证)
python3 "$LIGHT_OBF" "$WORK/dec" --clean --map "$WORK/map1.json" > /dev/null
cp -r "$WORK/dec" "$WORK/dec.orig"
python3 "$LIGHT_OBF" "$WORK/dec" "$WORK/rules.txt" --seed "$SEED" --map "$WORK/map3.json" > /dev/null
diff -r "$WORK/dec" "$WORK/dec.snap1" > /dev/null || die '③ 确定性破坏(同 seed 不同输出)'

# ③b: 不同 seed → 新名不同(随机性存在,而非固定名表)
python3 "$LIGHT_OBF" "$WORK/dec" --clean --map "$WORK/map3.json" > /dev/null
python3 "$LIGHT_OBF" "$WORK/dec" "$WORK/rules.txt" --seed "fedcba9876543210" --map "$WORK/map4.json" > /dev/null
if cmp -s "$WORK/dec/smali/com/demo/A.smali" "$WORK/dec.snap1/smali/com/demo/A.smali"; then
  die '③b 不同 seed 产出相同(确定性语义错误)'
fi

# ⑦ --clean 撤销变换 D:还原到干净原版(标记移除 + 名字还原)
python3 "$LIGHT_OBF" "$WORK/dec" --clean --map "$WORK/map4.json" > /dev/null
diff -r "$WORK/dec" "$WORK/dec.orig" > /dev/null || die '⑦ clean 未完整撤销变换 D'
grep -q 'nc-lightobf-applied' "$WORK/dec/smali/com/demo/A.smali" \
  && die '⑦ clean 未移除标记'

# ⑦b: clean 无 map → fail-fast
if python3 "$LIGHT_OBF" "$WORK/dec" --clean 2> "$WORK/err7b.log"; then
  die '⑦b clean 无 map 未 fail-fast'
fi
grep -q '必须提供' "$WORK/err7b.log" || die "⑦b 报错文案缺失: $(cat "$WORK/err7b.log")"

# ⑩ 变换 B(数字混淆)/A(指令替换) — 新增独立工作区重放(fresh unpack 语义)
WORK2="$WORK/dec_ba"
cp -r "$WORK/dec.orig" "$WORK2"
echo "com.demo.**" > "$WORK/rules2.txt"

# B/A 目标方法:>16 units、无循环、无 try、小参数槽、含 const/16 大常量与
# mul-int/lit8 #2^k;wide 大参数槽方法(JJ...→slots=6,4+6-1=9≤15 可过红线 7
# 但 old_locals+slots>15 拒 B)/反向 goto 循环方法用作拒判对照
cat > "$WORK2/smali/com/demo/Calc.smali" <<'EOF'
.class public Lcom/demo/Calc;
.super Ljava/lang/Object;

.method public calc(I)I
    .locals 8
    const/16 v0, 0x2BC
    const/16 v1, 0x3E8
    add-int/lit8 v2, p1, 0x5
    mul-int/lit8 v3, v2, 0x8
    add-int v4, v0, v3
    add-int/lit8 v5, p1, 0x2
    add-int/lit8 v6, v5, -0x3
    add-int v4, v4, v6
    add-int/lit8 v2, p1, 0x7
    mul-int/lit8 v3, v2, 0x10
    add-int v4, v4, v3
    add-int/lit8 v5, p1, 0x1
    add-int/lit8 v6, v5, -0x2
    add-int v4, v4, v6
    add-int/lit8 v2, p1, 0x9
    mul-int/lit8 v3, v2, 0x20
    add-int v4, v4, v3
    add-int v4, v4, v1
    add-int/lit8 v5, p1, 0x4
    add-int/lit8 v6, v5, -0x6
    add-int v4, v4, v6
    add-int/lit8 v5, p1, 0x6
    mul-int/lit8 v3, v5, 0x80
    add-int v4, v4, v3
    add-int/lit8 v5, p1, 0xa
    add-int/lit8 v6, v5, -0x9
    add-int v4, v4, v6
    add-int/lit8 v5, p1, 0xb
    add-int/lit8 v6, v5, -0x8
    add-int v4, v4, v6
    add-int/lit8 v5, p1, 0xc
    add-int/lit8 v6, v5, -0x7
    add-int v4, v4, v6
    return v4
.end method

.method public loopless(I)I
    .locals 9
    const/16 v0, 0x2BC
    add-int/lit8 v1, p1, 0x3
    mul-int/lit8 v2, v1, 0x40
    add-int v3, v0, v2
    add-int/lit8 v4, p1, 0x8
    add-int/lit8 v5, v4, -0x1
    add-int v6, v3, v5
    add-int v6, v6, v0
    return v6
.end method

.method public wideSkip(JJ)I
    .locals 6
    const/16 v0, 0x2BC
    const/16 v1, 0x3E8
    add-int v2, v0, v1
    long-to-int v3, p1
    add-int v4, v2, v3
    return v4
.end method

.method public loopSkip(I)I
    .locals 3
    const/16 v0, 0x2BC
    move v1, p1
    goto :chk
    :body
    add-int/lit8 v1, v1, 0x1
    :chk
    if-lt v1, v0, :body
    return v1
.end method
EOF

cp "$WORK2/smali/com/demo/Calc.smali" "$WORK/Calc.orig.smali"   # 未变换基线(⑩g 重放用)

run "$WORK2" "$WORK/rules2.txt" --seed "$SEED" --flags "d,b,a" --map "$WORK/map_ba.json" > "$WORK/run_ba.log"
grep -q '变换B [1-9]' "$WORK/run_ba.log" || die "⑩ 变换 B 未生效: $(grep 'light-obf 完成' "$WORK/run_ba.log")"
grep -q '变换A [1-9]' "$WORK/run_ba.log" || die "⑩ 变换 A 未生效: $(grep 'light-obf 完成' "$WORK/run_ba.log")"

# ⑩a B 拆解形态:calc 的 0x2BC(700) 必须变成 const/16(非700值) + const/4 + add-int 链
#    且 jadx 折叠面:深链跨语句存在即达标(值域/数学守恒由 _split_int 值域约束保证)
grep -qE 'const/16 v[0-9]+, 0x2c9' "$WORK2/smali/com/demo/Calc.smali" \
  || die '⑩a B 拆解链(const/16 rest)未出现在 Calc.smali'
grep -qE 'add-int v[0-9]+, v[0-9]+, v[0-9]+' "$WORK2/smali/com/demo/Calc.smali" \
  || die '⑩a B 拆解链(add-int 合并)未出现'
# ⑩a 原魔法数字在 calc 方法内必须消失(0x2BC 拆解;门槛拒判方法保留,见 ⑩d)
calc_seg=$(sed -n '/^.method public calc/,/^.end method/p' "$WORK2/smali/com/demo/Calc.smali")
if echo "$calc_seg" | grep -qE 'const/16 v[0-9]+, 0x2BC'; then
  die '⑩a calc 内原常量 0x2BC 未被拆解'
fi
# ⑩b A 形态:mul-int/lit8 #2^k → shl-int/lit8 #k
grep -qE 'shl-int/lit8 v[0-9]+, v[0-9]+, (0x[0-9a-fA-F]+|[0-9]+)' \
  "$WORK2/smali/com/demo/Calc.smali" || die '⑩b 变换 A(mul→shl)未生效'
mul_left=$(echo "$calc_seg" | grep -cE 'mul-int/lit8' || true)
[ "$mul_left" -le 1 ] || die "⑩b calc 内 mul 保留数超配额(_A_MAX_SITES=3): 剩 $mul_left"
# ⑩c .locals 提升:calc 原为 8,必须变 9(红线 7 临时寄存器 = 原 .locals 号)
grep -q '.locals 9' "$WORK2/smali/com/demo/Calc.smali" || die '⑩c .locals 未提升(红线 7 路线失效)'
# ⑩d 门槛拒判:loopSkip(反向 goto)/wideSkip(old_locals+slots>15) 的 0x2BC 必须原样保留
grep -q 'const/16 v0, 0x2BC' "$WORK2/smali/com/demo/Calc.smali" \
  || die '⑩d 门槛拒判失效(循环/wide 方法被误变换)'
# ⑩e B/A 特征标记存在(不可逆提示,clean 不移除)
grep -q '# nc-lightobf-ba' "$WORK2/smali/com/demo/Calc.smali" \
  || die '⑩e B/A 特征标记缺失'
# ⑩f 幂等:带 --flags 重跑零 diff
cp -r "$WORK2" "$WORK2.snap"
run "$WORK2" "$WORK/rules2.txt" --seed "$SEED" --flags "d,b,a" --map "$WORK/map_ba2.json" > /dev/null
diff -r "$WORK2" "$WORK2.snap" > /dev/null || die '⑩f B/A 幂等破坏(重跑产生 diff)'
# ⑩g 确定性:同 seed 对两个独立 fresh 副本首跑,B/A 产物一致
rm -rf "$WORK/dec_ba2"
mkdir -p "$WORK/dec_ba2/smali/com/demo"
cp "$WORK/dec.orig/smali/com/demo/A.smali" "$WORK/dec_ba2/smali/com/demo/A.smali"
cp "$WORK/Calc.orig.smali" "$WORK/dec_ba2/smali/com/demo/Calc.smali"
run "$WORK/dec_ba2" "$WORK/rules2.txt" --seed "$SEED" --flags "d,b,a" --map "$WORK/map_ba3.json" >/dev/null
diff "$WORK/dec_ba2/smali/com/demo/Calc.smali" "$WORK2.snap/smali/com/demo/Calc.smali" >/dev/null \
  || die '⑩g 同 seed 重放产物不一致(确定性破坏)'
# ⑩h 每方法 B 处数 ≤2、新增指令行 ≤ 预算(24 cap):粗断言 = 拆解链最多 2 条
b_chains=$(grep -cE 'const/4 v[0-9]+, -?0x?[0-9a-f]*' "$WORK2/smali/com/demo/Calc.smali" || true)
[ "$b_chains" -le 4 ] || die "⑩h B 处数超配额: $b_chains/2 方法"

# ⑨ fail-fast: unicode / 未实现变换 / B/A 孤儿标记
if run "$WORK/dec" "$WORK/rules.txt" --charset unicode 2> "$WORK/err9a.log"; then
  die '⑨ unicode 未被拒'
fi
if run "$WORK/dec" "$WORK/rules.txt" --flags c 2> "$WORK/err9b.log"; then
  die '⑨ 未实现变换未被拒'
fi
if run "$WORK/dec" "$WORK/rules.txt" --flags dabx 2> "$WORK/err9b.log"; then
  die '⑨ 未知变换字母未被拒'
fi
printf '# nc-lightobf-ba\n.class public Lcom/demo/Orphan;\n' > "$WORK/dec/smali/com/demo/Orphan.smali"
if run "$WORK/dec" "$WORK/rules.txt" 2> "$WORK/err9c.log"; then
  die '⑨ B/A 孤儿标记未 fail-fast'
fi
grep -q 'fresh unpack' "$WORK/err9c.log" || die "⑨ fail-fast 文案缺失: $(cat "$WORK/err9c.log")"

echo ""
echo "✅ light-obf 阶段 1+2 冒烟测试全部通过(①~⑩: D/B/A)"
