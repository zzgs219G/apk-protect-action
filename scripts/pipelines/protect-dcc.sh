#!/usr/bin/env bash
# protect-dcc.sh — 单独的 Dex2C 加固脚本（不掺签名校验，纯 dcc 流程）
#
# 与 protect-sigcheck.sh（联合方案）的区别：
#   - 不注入 sig_check.c / 签名校验
#   - 类名由调用方手动指定（一行一个,支持通配符,详见 rules-to-filter.py）
#
# 用法:
#   protect-dcc.sh <输入.apk> <输出_unsigned.apk> <规则文件>
#
# 规则文件格式（一行一个类,支持 ! 排除、# 注释、空行）:
#   com.test.**           com.test 包下所有类(含子包)
#   com.test.*            com.test 包下所有类(不含子包)
#   com.test**            等价 com.test.**
#   com.test*             com 下 test 开头的所有类
#   com.app.MainActivity  精确类名
#   activity*             所有 Activity 子类(从 Manifest 提取)
#   !com.test.libs.**     排除(优先于其它规则)
#
# 前置依赖（流水线安装）: JDK 17、Android NDK(ANDROID_NDK_HOME)、apktool、python3
set -euo pipefail

IN_APK="$1"
OUT_APK="$2"
RULES="$3"
# dcc.py 需要切换到自身目录运行，输入路径必须先转为绝对路径（防 cd 后相对路径失效）
IN_APK="$(cd "$(dirname "$IN_APK")" && pwd)/$(basename "$IN_APK")"
RULES="$(cd "$(dirname "$RULES")" && pwd)/$(basename "$RULES")"
OUT_APK="$(pwd)/$(basename "$OUT_APK")"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DCC_DIR="$ROOT/sigcheck/dex2c/dcc"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { echo "━━━ [dcc-protect] $* ━━━"; }

[[ -f "$IN_APK" ]] || { echo "❌ 输入 APK 不存在: $IN_APK"; exit 1; }
[[ -f "$RULES" ]] || { echo "❌ 规则文件不存在: $RULES"; exit 1; }
[[ -d "$DCC_DIR" ]] || { echo "❌ dcc 工具缺失: $DCC_DIR"; exit 1; }
grep -q '[^[:space:]#]' "$RULES" || { echo "❌ 规则文件为空（至少一行类名）: $RULES"; exit 1; }

# ── 步骤 1: 通配符规则 → dcc filter ─────────────────────────────────
log "步骤 1/4 解析类名规则"
python3 "$ROOT/scripts/filter/rules-to-filter.py" "$RULES" "$WORK/dcc_filter.txt" \
  --classes "$WORK/activity_classes.txt"

# activity* 需要 Activity 类列表 → 从 Manifest 动态提取
if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$RULES"; then
  log "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
  python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
    "$WORK/.placeholder_filter.txt" --classes "$WORK/activity_classes.txt" \
    --on-fail skip || true
fi

# ── 步骤 2: dcc 转译（--no-build 只产出工程包） ─────────────────────
log "步骤 2/4 Dex2C 转译"
cd "$DCC_DIR"
python3 dcc.py "$IN_APK" \
  --project-archive "$WORK/dcc-project.zip" \
  --no-build \
  --filter "$WORK/dcc_filter.txt"

[[ -f "$WORK/dcc-project.zip" ]] || { echo "❌ dcc 未产出工程包（规则可能未命中任何方法）"; exit 1; }

# ── 步骤 3: NDK 编译 libnc.so ───────────────────────────────────────
log "步骤 3/4 NDK 编译"
mkdir -p "$WORK/project"
unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
: "${ANDROID_NDK_HOME:?需要设置 ANDROID_NDK_HOME 环境变量指向 NDK 根目录}"
PATH="$ANDROID_NDK_HOME:$PATH" ndk-build -j"$(nproc)" -C "$WORK/project"

# ── 步骤 4: 解包 → native 化 → 放 so → 重打包（不签名） ────────────
log "步骤 4/4 解包注入重打包"
APKTOOL_JAR="$ROOT/sigcheck/tools/apktool.jar"
java -jar "$APKTOOL_JAR" d -r -f -o "$WORK/decompiled" "$IN_APK"

# native 壳替换 + System.loadLibrary("nc") 插桩
python3 "$ROOT/scripts/repack/mark-native.py" \
  "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"

for abi_dir in "$WORK/project/libs"/*; do
  abi=$(basename "$abi_dir")
  mkdir -p "$WORK/decompiled/lib/$abi"
  cp "$abi_dir/libnc.so" "$WORK/decompiled/lib/$abi/"
done

# 强制解压 so 加载（extractNativeLibs=true）
sed -i 's/android:extractNativeLibs="false"/android:extractNativeLibs="true"/' \
  "$WORK/decompiled/AndroidManifest.xml" || true
grep -q 'extractNativeLibs="true"' "$WORK/decompiled/AndroidManifest.xml" || \
  sed -i '0,/<application/s//<application android:extractNativeLibs="true"/' \
    "$WORK/decompiled/AndroidManifest.xml"

java -jar "$APKTOOL_JAR" b -o "$WORK/unsigned.apk" "$WORK/decompiled"

if command -v zipalign >/dev/null 2>&1; then
  zipalign -f 4 "$WORK/unsigned.apk" "$OUT_APK"
else
  cp "$WORK/unsigned.apk" "$OUT_APK"
  echo "⚠️ 未找到 zipalign，跳过对齐"
fi

log "完成 ✅ 产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
