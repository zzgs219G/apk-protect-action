#!/usr/bin/env bash
# test-link-dex2c.sh — 联动(stringenc↔dex2c)核心链路验证
#
# 验证目标：随机桩名 → --emit-stub-filter 产出规则 → dex2c 转译 → 算法进 so。
# 不依赖 android.jar / NDK / 真机，所以证明的是【联动语义】而非全流程产物；
# 全流程(apktool 解包/回编 + NDK 编译 + 真机启动)需在 CI 或本地补验。
#
# 断言：
#   ① dn/mix64/keyByte 三个方法都被转译（只写 dn 会让算法半截留在 dex）
#   ② 壳 d() 也一并转译（2026-12 全抽：dex2c 已实测支持异常表）
#   ③ <clinit>/<init> 不被转译（上游守卫）
#   ④ splitmix64 常量内联进 C（十进制有符号形式）
#   ⑤ dn→mix64 的 JNI 反调目标必须是 so 内的导出符号
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"          # scripts/string-enc/tests
ROOT="$(cd "$HERE/../../.." && pwd)"           # 仓库根
SE="$ROOT/scripts/string-enc"
DEX2C="$ROOT/tools/Dex2C"

# 每次全新开始:残留的 work/ 会让"找桩 smali"匹配到上一轮的 legacy 文件,
# 导致 dex 里是旧类名而 filter 是新随机名 → 联动静默失效(实测踩过)。
rm -rf work

# cwd 固定到 tests/ —— 下游 apktool/dex2c 对相对/绝对路径行为不一致
# (apktool 的 -o 收绝对路径会误判为输入目录),统一相对路径最稳。
cd "$HERE"
DEX2C="$ROOT/tools/Dex2C"

echo "══ 1. 构造只含解密桩的 dex（绕过 android.jar 依赖）══"
# StrDec.java 引用 android.util.Base64 → 用 shim 顶替后编桩
mkdir -p work/shim/android/util
cp "$SE/tests/shims/android/util/Base64.java" work/shim/android/util/
mkdir -p work/classes
javac -nowarn -d work/classes work/shim/android/util/Base64.java

# 桩源码：把 SEED 占位行换成哨兵种子（build-stub.sh 同款 sed），再编
sed "s|private static final long SEED = 0L;.*|private static final long SEED = 0x5eed000000000000L;|" \
    "$SE/stub-src/StrDec.java" > work/StrDec.java
grep -q "SEED = 0x5eed000000000000L;" work/StrDec.java || { echo "❌ 哨兵替换失败"; exit 1; }
javac -nowarn -cp work/classes -d work/classes work/StrDec.java
echo "   ✅ 桩编译通过（含 d() 壳 + dn() 内核两层）"

echo "══ 2. dex → 裸 dex 文件（dex2c 的 auto_vm 直接支持 DEX）══"
mkdir -p work/dex
find work/classes -name '*.class' | xargs java -cp "$SE/tools/d8.jar" com.android.tools.r8.D8 \
    --release --min-api 26 --output work/dex
cp work/dex/classes.dex work/stub.dex
echo "   ✅ dex 就绪：$(ls -la work/dex/classes.dex | awk '{print $5}') 字节"

echo "══ 3. 用 encrypt-strings 产出联动 filter（模拟前置轮）══"
# 造一个只含业务类的解包树,让 encrypt-strings 自己随机生成桩名并注入
# (不预放 legacy 骨架 —— 那会走"已有桩但无组件标记"的未定义路径,
#  真实流水线里桩名只会来自"随机生成"或"从标记恢复",两者都正确设置 STUB_DESC)
rm -rf work/dec && mkdir -p work/dec/smali/com/demo
cat > work/dec/smali/com/demo/A.smali <<'SMALI'
.class public Lcom/demo/A;
.super Ljava/lang/Object;

.method public static hello()V
    .locals 1
    const-string v0, "https://api.example.com/v1"
    return-void
.end method
SMALI
cat > work/rules.txt <<'EOF'
com.demo.**
EOF
python3 "$SE/encrypt-strings.py" work/dec work/rules.txt \
    --seed-hex 0123456789abcdef \
    --emit-stub-filter work/stub_filter.txt 2>&1 | tail -5
echo "   filter 内容:"
sed 's/^/       /' work/stub_filter.txt
[[ -s work/stub_filter.txt ]] || { echo "❌ 联动 filter 为空"; exit 1; }
# 把注入的桩重新编成 dex,替换第 2 步的(dex2c 要转译的是带真桩名的 dex)
echo "── 用注入了真桩名的 smali 重编 dex ──"
rm -rf work/dec2 && mkdir -p work/dec2/smali
cp -r work/dec/smali/* work/dec2/smali/
# 只保留桩类(去掉测试业务类),避免 dex 里混入无关方法
STUB_SMALI="$(find work/dec2/smali -name '*.smali' | xargs grep -l 'nc-strdec-gen' | head -1)"
[[ -n "$STUB_SMALI" ]] || { echo "❌ 找不到注入的桩 smali(work/dec2/smali 下无 nc-strdec-gen 标记)"; exit 1; }
echo "   桩 smali: $STUB_SMALI"
# 先复制到安全位置,再清空 smali 目录(STUB_SMALI 就在该目录内,顺序反了会被删)
cp "$STUB_SMALI" work/stub_only.smali
rm -rf work/dec2/smali && mkdir -p work/dec2/smali
cp work/stub_only.smali work/dec2/smali/

# apktool b 需要 apktool.yml(解包产物才有);手工造一个最小版即可汇编纯 smali
cat > work/dec2/apktool.yml <<'EOF'
!!brut.androlib.meta.MetaInfo
apkFileName: stub.apk
isFrameworkApk: false
sdkInfo:
  minSdkVersion: 21
  targetSdkVersion: 26
versionInfo:
  versionCode: 1
  versionName: "1.0"
EOF
# cwd 已固定为 $HERE,相对路径落点确定(apktool 的 -o 收绝对路径会误判为输入目录)
java -jar "$ROOT/tools/dcc/tools/apktool.jar" b -o work/dec2/stub.apk work/dec2 2>&1 | tail -2
[[ -f work/dec2/stub.apk ]] || { echo "❌ apktool 未产出 stub.apk"; exit 1; }
# dex2c 的 auto_vm 用 androconf.is_android 判类型,要求 zip 内有 Manifest。
# 从 apk 里抽出裸 classes.dex 喂最稳(is_android 对裸 dex 报 DEX)。
python3 - "$HERE/work/dec2/stub.apk" "$HERE/work/stub2.dex" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    names = [n for n in z.namelist() if n.endswith('.dex')]
    assert names, "apk 内无 dex"
    open(sys.argv[2], 'wb').write(z.read(sorted(names)[0]))
    print("   抽出:", sorted(names))
PY
echo "   dex 里的方法:"
(cd "$DEX2C" && python3 "$HERE/dump_methods.py" "$HERE/work/stub2.dex")
echo "══ 4. dex2c 转译：用产出的联动 filter ══"
# dex2c 必须在自身目录跑(读 dcc.cfg + project/ 模板) → 子 shell 隔离 cwd,
# 输入/输出/filter 全部用绝对路径,不受 cwd 影响。
rm -f "$HERE/work/project.zip"
(cd "$DEX2C" && python3 dcc.py -i "$HERE/work/stub2.dex" -o "$HERE/work/out.apk" \
    --project-archive "$HERE/work/project.zip" --no-build --disable-signing \
    --allow-global --force-keep-libs --filter "$HERE/work/stub_filter.txt" 2>&1 | tail -5) || true

echo "══ 5. 断言 ══"
cd "$HERE"
rm -rf work/proj && mkdir -p work/proj
unzip -qo work/project.zip -d work/proj
CM=work/proj/jni/nc/compiled_methods.txt
echo "--- compiled_methods.txt ---"
cat "$CM"; echo
echo "--- 生成的 C ---"
ls work/proj/jni/nc/*.cpp | xargs -n1 basename
echo "--- 断言 ---"
# ① dn/mix64/keyByte 三个方法都必须在
for m in dn mix64 keyByte; do
    grep -q ";$m(" "$CM" && echo "   ✅ $m() 已转译" \
        || { echo "   ❌ $m() 未转译"; exit 1; }
done
# ② 壳 d() 也必须被转译(2026-12 全抽:dex2c 已实测支持异常表,
#    catch(Throwable) 兜底在 C 侧由 d2c_is_instance_of 分发承担)
#    ⚠️ 桩名每包随机,d() 不叫 d —— 判据用入口方法签名
#    (Ljava/lang/String;)Ljava/lang/String; 中除 dn() 外的那一个。
D_RAND="$(awk -F';' '/\(Ljava\/lang\/String;\)Ljava\/lang\/String;$/ && $0 !~ /;dn\(/ {print $2}' "$CM" | sed 's/(.*//')"
if [[ -n "$D_RAND" ]]; then
    echo "   ✅ d()（随机名 $D_RAND）已转译，含 try/catch 兜底，全抽生效"
else
    echo "   ❌ d() 未被转译（全抽未生效，filter 应覆盖 d）"; exit 1
fi
# ③ <clinit>/<init> 不能被转译(上游守卫,桩自身也不该破例)
grep -qE ';<clinit>|<init>' "$CM" && { echo "   ❌ 构造器被转译"; exit 1; } \
    || echo "   ✅ 构造器未被转译"
# ④ splitmix64 常量必须内联进 C(十进制有符号形式)
#    0xBF58476D1CE4E5B9 = -4658895280553007687
#    0x94D049BB133111EB = -7723592293110705685
MIX_CPP="$(ls work/proj/jni/nc/Java_*_mix64__J.cpp 2>/dev/null | head -1)"
if [[ -n "$MIX_CPP" ]] \
   && grep -q "\-4658895280553007687" "$MIX_CPP" \
   && grep -q "\-7723592293110705685" "$MIX_CPP"; then
    echo "   ✅ splitmix64 常量已内联进 so"
else
    echo "   ❌ splitmix64 常量未进 so(算法仍在 dex)"; exit 1
fi
# ⑤ dn 对 mix64 的调用形态:dex2c 不用 --dynamic-register 时,dex 内 Java 方法
#    调用一律按 JNI 短名解析。mix64 已被转译 → 反调目标就是 so 里生成的
#    Java_*_mix64__J 导出符号(JNI 往返,非本地调用)。这【不是】"算法留在 dex"——
#    判定依据是常量是否内联(见④)。这里只断言反调目标确实是被转译的方法,
#    而不是某个仍在 dex 的未转译副本。
DN_CPP="$(ls work/proj/jni/nc/Java_*_dn__Ljava_lang_String_2.cpp 2>/dev/null | head -1)"
if [[ -n "$DN_CPP" ]] && grep -q 'D2C_RESOLVE_STATIC_METHOD.*"mix64"' "$DN_CPP"; then
    # 反调存在:确认 so 里确有对应导出符号(JNI 短名),否则运行期 UnsatisfiedLink
    if [[ -n "$MIX_CPP" ]] && grep -q 'Java_.*_mix64__J' "$MIX_CPP"; then
        echo "   ✅ dn→mix64 走 JNI 反调 so 内导出符号（算法在 so，多一次 JNI 往返）"
    else
        echo "   ❌ dn 反调 mix64 但 so 内无对应导出符号 → 运行期 UnsatisfiedLink"; exit 1
    fi
else
    echo "   ✅ dn() 本地调用 mix64（无 JNI 往返）"
fi
echo "══ 端到端核心链路验证全部通过 ══"
