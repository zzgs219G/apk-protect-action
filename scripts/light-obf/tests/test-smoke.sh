#!/usr/bin/env bash
# test-smoke.sh — light-obf 阶段 1(变换 D)冒烟测试(合成 smali,无需 apktool)
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

# ⑨ fail-fast: unicode / 未实现变换 / B/A 孤儿标记
if run "$WORK/dec" "$WORK/rules.txt" --charset unicode 2> "$WORK/err9a.log"; then
  die '⑨ unicode 未被拒'
fi
if run "$WORK/dec" "$WORK/rules.txt" --flags a 2> "$WORK/err9b.log"; then
  die '⑨ 未实现变换未被拒'
fi
printf '# nc-lightobf-ba\n.class public Lcom/demo/Orphan;\n' > "$WORK/dec/smali/com/demo/Orphan.smali"
if run "$WORK/dec" "$WORK/rules.txt" 2> "$WORK/err9c.log"; then
  die '⑨ B/A 孤儿标记未 fail-fast'
fi
grep -q 'fresh unpack' "$WORK/err9c.log" || die "⑨ fail-fast 文案缺失: $(cat "$WORK/err9c.log")"

echo ""
echo "✅ light-obf 阶段 1 冒烟测试全部通过(①~⑨)"
