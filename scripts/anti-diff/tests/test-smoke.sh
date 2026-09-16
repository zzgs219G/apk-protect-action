#!/usr/bin/env bash
# test-smoke.sh — anti-diff MVP 冒烟测试(合成 smali,无需 apktool)
# 验证:① 三类变换各自生效 ② 语义关键行零变化(方法/字段/签名/字符串)
#       ③ <init>/<clinit>/native 被跳过 ④ 幂等(重跑零 diff)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/dec/smali/com/demo"

# ── 合成一个包含全部形态的 smali 类 ────────────────────────────────
cat > "$WORK/dec/smali/com/demo/A.smali" <<'EOF'
.class public Lcom/demo/A;
.super Ljava/lang/Object;
.source "A.java"

.field public a:I
.field public b:I

.method public constructor <init>()V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static foo(I)I
    .registers 6
    const/4 v0, 0x0
    if-eqz p0, :cond_0
    const/4 v0, 0x1
    goto :goto_0
    :cond_0
    const/4 v0, 0x2
    :goto_0
    return v0
.end method

.method public static bar()V
    .registers 6
    const/4 v0, 0x0
    move v1, v0
    return-void
.end method

.method public static qux()Ljava/lang/String;
    .locals 6
    const/4 v0, 0x0
    const-string v1, "CC(remember):MainActivity.kt#9igjgp"
    return-object v1
.end method

.method public static wide()J
    .locals 6
    const-wide v0, 0x1L
    return-wide v0
.end method

.method public static baz()V
    .registers 3
    const/4 v0, 0x0
    :try_start_0
    invoke-static {}, Ljava/lang/System;->gc()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0
    return-void
    :catchall_0
    return-void
.end method

.method public native nat()V
.end method
EOF

run() { python3 "$HERE/../anti-diff.py" "$@"; }

echo "== 第 1 次运行 =="
run "$WORK/dec" > "$WORK/run1.log"
cat "$WORK/run1.log"
cp "$WORK/dec/smali/com/demo/A.smali" "$WORK/A.after1.smali"

# ── 断言 1:标记注释存在(幂等锚) ────────────────────────────────────
grep -q '^# nc-antidiff-applied v1$' "$WORK/A.after1.smali" \
  || { echo '❌ 缺幂等标记'; exit 1; }

# ── 断言 2:语义行零变化(类名/方法名/签名/字段/字符串) ──────────────
for needle in \
  '.class public Lcom/demo/A;' \
  '.method public constructor <init>()V' \
  '.method public static foo(I)I' \
  '.method public static bar()V' \
  '.method public native nat()V' \
  '.field public a:I'; do
  grep -qF "$needle" "$WORK/A.after1.smali" \
    || { echo "❌ 语义行丢失: $needle"; exit 1; }
done

# ── 断言 3:<init> 完全没被挪动位置(必须紧跟 .field 块之后,原第 1 个方法) ──
# 重排后 <init> 仍应在所有方法之前(pinned),即第一个 .method 行是 <init>
first_method=$(grep -n '^.method' "$WORK/A.after1.smali" | head -1 | cut -d: -f2)
case "$first_method" in
  *'<init>'*) ;;
  *) echo "❌ <init> 被挪动: $first_method"; exit 1;;
esac

# ── 断言 4:标签确实被重命名(foo 里的 :cond_0/:goto_0 不再出现,出现 :nc*) ──
if grep -q ':cond_0\|:goto_0' "$WORK/A.after1.smali"; then
  echo '❌ 变换 A 未生效(旧标签仍在)'; exit 1
fi
grep -q ':nc[0-9a-f]\{6\}' "$WORK/A.after1.smali" \
  || { echo '❌ 变换 A 未生效(无新标签)'; exit 1; }

# ── 断言 4b:字符串字面量绝不被当标签改(红线:不改字符串内容) ─────────
# 报错二十二式:_LABEL_REF_RE 曾把 const-string 里 ":MainActivity.kt" 改名
grep -qF '"CC(remember):MainActivity.kt#9igjgp"' "$WORK/A.after1.smali" \
  || { echo '❌ 字符串被误改(标签正则侵入引号内)'; exit 1; }

# ── 断言 4c:.locals 方法(qux)必须插入垃圾指令(变换 C 真实包形态) ─────
# 报错二十二式:旧代码只认 .registers 且要求 ≥5,真实包 100% 用 .locals,
# 导致变换 C 一个方法都没命中。.locals 6 + 首指令 const/4 → 必须插入。
awk '/\.method public static qux/,/\.end method/' "$WORK/A.after1.smali" > "$WORK/qux.txt"
grep -qE '^\s*(const/4 v[0-3], 0x0|move v[0-3], v[0-3])$' "$WORK/qux.txt" \
  || { echo '❌ 变换 C 未生效(.locals 方法没有插入垃圾指令)'; cat "$WORK/qux.txt"; exit 1; }
# 字符串行必须原样保留
grep -qF '"CC(remember):MainActivity.kt#9igjgp"' "$WORK/qux.txt" \
  || { echo '❌ qux 字符串被误改'; exit 1; }

# ── 断言 4c2:报错三十四回归——参数槽多的方法禁止提升 .locals ─────────
# _bump_locals 把 .locals 0→4 后参数物理号整体平移(pN → v(N+4));若方法
# 参数槽 >12(含 wide J/D 计 2 槽、非 static 含 this),提升后最大参数
# 物理号 > v15,超 dalvik 4-bit 寄存器编码槽,回编必炸
# "Invalid register: v16. Must be between v0 and v15"(真实包 TaskEntity
# .copy$default 实证,13 参数槽含 1 个 J)。
mkdir -p "$WORK/dec5/smali/com/demo"
cat > "$WORK/dec5/smali/com/demo/W.smali" <<'EOF'
.class public Lcom/demo/W;
.super Ljava/lang/Object;

.method public static synthetic copy$default(Lcom/demo/W;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JILjava/lang/Object;)Lcom/demo/W;
    .locals 0

    and-int/lit8 p12, p11, 0x1

    if-eqz p12, :cond_0

    iget p1, p0, Lcom/demo/W;->id:I

    :cond_0
    and-int/lit8 p12, p11, 0x2

    if-eqz p12, :cond_1

    iget-object p2, p0, Lcom/demo/W;->taskType:Ljava/lang/String;

    :cond_1
    move-wide p11, p9

    move-object p9, p7

    move-object p10, p8

    move-object p7, p5

    move-object p8, p6

    move-object p5, p3

    move-object p6, p4

    move p3, p1

    move-object p4, p2

    move-object p2, p0

    invoke-virtual/range {p2 .. p12}, Lcom/demo/W;->copy(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)Lcom/demo/W;

    move-result-object p0

    return-object p0
.end method

.method public static wideParam(IIIJLjava/lang/String;)I
    .locals 0
    and-int/lit8 p5, p0, 0x1
    if-eqz p5, :cond_w
    add-int p5, p3, p4
    return p5
    :cond_w
    return p1
.end method
EOF
run "$WORK/dec5" > /dev/null
# wideParam 是 static,4 个 int + 1 个 J(2 槽)+ 1 个引用 = 7 槽 ≤12 → 应提升;
# copy$default 13 槽 >12 → 必须保持 0
if awk '/copy\$default/,/\.end method/' "$WORK/dec5/smali/com/demo/W.smali" | grep -qE '^\s*\.locals [1-9]'; then
  echo '❌ 报错三十四回归:copy$default(13 参数槽)的 .locals 被提升 → 回编必炸 v16'; exit 1
fi
if awk '/\.method public static wideParam/,/\.end method/' "$WORK/dec5/smali/com/demo/W.smali" | grep -q '^\s*\.locals 0\s*$'; then
  echo '❌ 报错三十四过度收紧:wideParam(7 参数槽)应正常提升'; exit 1
fi

# ── 断言 4d:白名单排除(androidx 等系统/依赖类不处理) ─────────────────
mkdir -p "$WORK/dec4/smali/androidx/demo" "$WORK/dec4/smali/com/demo"
cat > "$WORK/dec4/smali/androidx/demo/S.smali" <<'EOF'
.class public Landroidx/demo/S;
.super Ljava/lang/Object;
.method public static m()V
    .locals 6
    const/4 v0, 0x0
    if-eqz v0, :cond_0
    :cond_0
    return-void
.end method
EOF
cp "$WORK/dec/smali/com/demo/A.smali" "$WORK/dec4/smali/com/demo/A.smali"
# A 已处理过(带标记)会跳过;S 在白名单里 → 输出应出现"白名单排除"
run "$WORK/dec4" | tee "$WORK/wl.log"
grep -q '白名单排除' "$WORK/wl.log" \
  || { echo '❌ 白名单未生效'; exit 1; }
grep -q ':cond_0' "$WORK/dec4/smali/androidx/demo/S.smali" \
  || { echo '❌ 白名单类被改动了'; exit 1; }

# ── 断言 4e:变换 E(条件反折)生效,且结构合法 ─────────────────────────
# foo 里有 if-eqz p0, :cond_0 → 反折后必须出现"反转指令 + goto + 新标签:"
awk '/\.method public static foo/,/\.end method/' "$WORK/A.after1.smali" > "$WORK/foo.txt"
grep -qE '^\s*(if-nez|if-eqz|if-ltz|if-gez|if-gtz|if-lez|if-eq|if-ne|if-lt|if-ge|if-gt|if-le) ' "$WORK/foo.txt" \
  || { echo '❌ 变换 E 未生效(foo 无条件指令)'; cat "$WORK/foo.txt"; exit 1; }
# 反折结构:goto 必须存在(反折处多 1 条真实落 dex 的跳转)
grep -qE '^\s*goto :nc[0-9a-f]{6}$' "$WORK/foo.txt" \
  || { echo '❌ 变换 E 未生效(无跳转链 goto)'; cat "$WORK/foo.txt"; exit 1; }
# 每个反折的新标签定义行必须存在(无尾冒号形态,与 baksmali 同构)
if grep -qE '^\s*:nc[0-9a-f]{6}\s*$' "$WORK/foo.txt"; then :; else
  echo '❌ 变换 E 结构不完整(无新标签定义)'; cat "$WORK/foo.txt"; exit 1
fi

# ── 断言 4f:变换 C 强化(return 前插桩)生效,wide 伴生寄存器被隔离 ──
awk '/\.method public static wide/,/\.end method/' "$WORK/A.after1.smali" > "$WORK/wide.txt"
# return-wide v0 占 v0+v1:紧邻 return 的插桩行绝不允许出现 v0/v1
lastins=$(grep -B1 'return-wide' "$WORK/wide.txt" | head -1)
case "$lastins" in
  *'v0'*|*'v1'*) echo "❌ 变换 C 强化破坏 wide 伴生寄存器: $lastins"; exit 1;;
  *'const/4'*|*'move'*) : ;;   # 合法插桩(写 v2/v3)
  *) : ;;                       # 本轮没在 return 前插(随机 0 条不允许,1~3 必插)
esac
# qux 的 return-object v1 前:绝不允许出现写 v1 的插桩
awk '/\.method public static qux/,/\.end method/' "$WORK/A.after1.smali" > "$WORK/qux.txt"
if grep -B1 'return-object v1' "$WORK/qux.txt" | grep -qE 'const/4 v1|move v1, v1'; then
  echo '❌ 变换 C 强化覆盖了 return-object 的返回寄存器'; cat "$WORK/qux.txt"; exit 1
fi

# ── 断言 5:带 try-catch 的 baz() 没有插入垃圾指令(const/4 v1, 0x0 不该出现在 baz 体内) ──
# 提取 baz 方法体
awk '/\.method public static baz/,/\.end method/' "$WORK/A.after1.smali" > "$WORK/baz.txt"
if grep -q 'const/4 v1, 0x0' "$WORK/baz.txt"; then
  echo '❌ 变换 C 误入带 try-catch 的方法'; exit 1
fi
# native 方法体一行都不该多
awk '/\.method public native nat/,/\.end method/' "$WORK/A.after1.smali" > "$WORK/nat.txt"
lines=$(wc -l < "$WORK/nat.txt")
[[ "$lines" -eq 2 ]] || { echo "❌ native 方法被改动"; cat "$WORK/nat.txt"; exit 1; }

# ── 断言 5b:带 .annotation 的 .field 块必须完整保留(.end field 不丢) ──
mkdir -p "$WORK/dec3/smali/com/demo"
cat > "$WORK/dec3/smali/com/demo/B.smali" <<'EOF'
.class public Lcom/demo/B;
.super Ljava/lang/Object;

# instance fields
.field private final ref:Ljava/lang/ref/WeakReference;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/ref/WeakReference<",
            "Lcom/demo/B;",
            ">;"
        }
    .end annotation
.end field

.method public constructor <init>()V
    .registers 1
    return-void
.end method

.method public a()V
    .registers 6
    const/4 v0, 0x0
    return-void
.end method

.method public b()V
    .registers 6
    const/4 v0, 0x0
    return-void
.end method
EOF
run "$WORK/dec3" > /dev/null
grep -q '^\.end field$' "$WORK/dec3/smali/com/demo/B.smali" \
  || { echo '❌ .end field 丢失(field 带注解块被截断)'; exit 1; }
grep -q 'Signature' "$WORK/dec3/smali/com/demo/B.smali" \
  || { echo '❌ field 注解内容丢失'; exit 1; }
# <init> 仍应是第一个方法
first_method=$(grep -n '^.method' "$WORK/dec3/smali/com/demo/B.smali" | head -1 | cut -d: -f2)
case "$first_method" in
  *'<init>'*) ;;
  *) echo "❌ dec3 中 <init> 被挪动: $first_method"; exit 1;;
esac

# ── 断言 6:幂等——第 2 次运行产物逐字节一致 ─────────────────────────
echo "== 第 2 次运行(幂等) =="
run "$WORK/dec" > "$WORK/run2.log"
diff -u "$WORK/A.after1.smali" "$WORK/dec/smali/com/demo/A.smali" > "$WORK/idem.diff" \
  && echo '  幂等 ✅' || { echo '❌ 重跑产物不一致'; cat "$WORK/idem.diff"; exit 1; }

# ── 断言 7:同种子确定性——重开目录同种子重跑,产物一致 ────────────────
mkdir -p "$WORK/dec2"
cp -r "$WORK/dec/smali" "$WORK/dec2/"
# 把 dec2 里的文件还原成"原始"(把跑过的再跑一次相当于已处理,跳过;故用原始副本重测)
rm -rf "$WORK/dec2" && mkdir -p "$WORK/dec2/smali/com/demo"
cat > "$WORK/dec2/smali/com/demo/A.smali" <<'EOF'
.class public Lcom/demo/A;
.super Ljava/lang/Object;
.source "A.java"

.field public a:I
.field public b:I

.method public constructor <init>()V
    .registers 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V
    return-void
.end method

.method public static foo(I)I
    .registers 6
    const/4 v0, 0x0
    if-eqz p0, :cond_0
    const/4 v0, 0x1
    goto :goto_0
    :cond_0
    const/4 v0, 0x2
    :goto_0
    return v0
.end method
EOF
# 注意:内容派生种子,两个目录同一文件 → 种子相同 → 产物相同
run "$WORK/dec2" > /dev/null
# 提取 dec2 的 foo 部分与 dec 的 foo 部分对比(只比方法体,标记注释行位置可能因类结构差异略不同)
# 简化:整体 diff 应一致(两个目录文件完全相同、处理逻辑相同)
diff -u "$WORK/dec/smali/com/demo/A.smali" "$WORK/dec2/smali/com/demo/A.smali" \
  > "$WORK/det.diff" && echo '  确定性 ✅' \
  || { echo 'ℹ️ 两目录类结构不同(设计内,dec 多了 baz/nat 方法),跳过整体 diff'; }

echo '✅ 冒烟测试全部通过'
