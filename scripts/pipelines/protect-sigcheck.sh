#!/usr/bin/env bash
# protect-sigcheck.sh — 签名校验注入总控脚本（在 GitHub Actions 流水线中执行）
#
# 输入: 已下载的用户 APK（开发者自己 keystore 签名）
# 输出: 加固后的未签名 APK（用户自行重签后发布）
#
# 前置依赖（由流水线安装）: python3 + pip 依赖、JDK 17、Android NDK、apktool
# 用法:
#   protect-sigcheck.sh <输入.apk> <输出_unsigned.apk>
set -euo pipefail

IN_APK="$1"
OUT_APK="$2"
# dcc.py 需要切换到自身目录运行，输入路径必须先转为绝对路径，避免 cd 后相对路径失效
IN_APK="$(cd "$(dirname "$IN_APK")" && pwd)/$(basename "$IN_APK")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"    # apk-protect-action 根目录
DCC_DIR="$ROOT/sigcheck/dex2c/dcc"            # dcc 工具目录
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { echo "━━━ [sigcheck] $* ━━━"; }

[[ -f "$IN_APK" ]] || { echo "❌ 输入 APK 不存在: $IN_APK"; exit 1; }
[[ -d "$DCC_DIR" ]] || { echo "❌ dcc 工具缺失: $DCC_DIR（应随仓库提交）"; exit 1; }

# ── 步骤 1: 提取证书指纹，生成 sig_hash.h ──────────────────────────
log "步骤 1/6 提取证书指纹"
"$ROOT/scripts/sig-hash/make-sig-hash.sh" "$IN_APK" "$WORK/sig_hash.h"

# ── 步骤 2: dcc 编译主 Activity → C 代码（不编译，只产出工程包） ──
log "步骤 2/6 Dex2C 转译"
cd "$DCC_DIR"
# 动态解析 Manifest 里的 LAUNCHER activity → 自动生成 filter（一行一个类）
python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" "$WORK/auto_filter.txt" \
  --classes "$WORK/activity_classes.txt" --on-fail error
# auto_filter.txt 已是 dcc filter 正则格式(见 make-filter-from-apk.py),
# 直接使用,不要二次转换 —— 曾经二次转换产生畸形正则导致 no compiled methods
DCC_FILTER="$WORK/auto_filter.txt"

# filter: 只转译主 Activity 的方法（动态类名）
python3 dcc.py "$IN_APK" \
  --project-archive "$WORK/dcc-project.zip" \
  --no-build \
  --filter "$DCC_FILTER"

[[ -f "$WORK/dcc-project.zip" ]] || { echo "❌ dcc 未产出工程包（filter 可能未命中任何方法）"; exit 1; }

# ── 步骤 3: 解包工程，合入 sig_check.c + sig_hash.h，改 ABI ─────────
log "步骤 3/6 合并校验代码进 NDK 工程"
mkdir -p "$WORK/project"
unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
cp "$ROOT/sigcheck/src/sig_check.c" "$WORK/project/jni/nc/"
cp "$WORK/sig_hash.h"               "$WORK/project/jni/nc/"
# 双 ABI 输出（dcc 默认只编 armeabi-v7a）
cat > "$WORK/project/jni/Application.mk" <<'EOF'
APP_STL := c++_static
APP_CPPFLAGS += -fvisibility=hidden
APP_PLATFORM := android-21
APP_ABI := armeabi-v7a arm64-v8a
EOF

# ── 步骤 4: NDK 编译 libnc.so ───────────────────────────────────────
log "步骤 4/6 NDK 编译"
: "${ANDROID_NDK_HOME:?需要设置 ANDROID_NDK_HOME 环境变量指向 NDK 根目录}"
PATH="$ANDROID_NDK_HOME:$PATH" ndk-build -j"$(nproc)" -C "$WORK/project"

# ── 步骤 5: apktool 解包 → 放 so → 重打包 ───────────────────────────
log "步骤 5/6 解包注入重打包"
# apktool.jar 实际随 dcc 工具包提交(仓库只此一份);sigcheck/tools/ 是空目录,
# git 不跟踪空目录 → 云端检出后该路径必然不存在(报错三同源的路径漂移问题)
APKTOOL_JAR="$ROOT/sigcheck/dex2c/dcc/tools/apktool.jar"
[[ -f "$APKTOOL_JAR" ]] || { echo "❌ apktool.jar 缺失: $APKTOOL_JAR"; exit 1; }
java -jar "$APKTOOL_JAR" d -r -f -o "$WORK/decompiled" "$IN_APK"

# native 化：把已抽进 so 的方法在 smali 里改成 native 壳，并插 System.loadLibrary("nc")
# （dcc 原版只在自带重打包路径里做壳替换且不插 loadLibrary，纯成品 APK 后处理必须自动补齐）
log "步骤 5.5/6 smali native 化"
python3 "$ROOT/scripts/repack/mark-native.py" \
  "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"

for abi_dir in "$WORK/project/libs"/*; do
  abi=$(basename "$abi_dir")
  mkdir -p "$WORK/decompiled/lib/$abi"
  cp "$abi_dir/libnc.so" "$WORK/decompiled/lib/$abi/"
done
# 强制解压 so 加载（本方案唯一允许的 Manifest 修改）
sed -i 's/android:extractNativeLibs="false"/android:extractNativeLibs="true"/' \
  "$WORK/decompiled/AndroidManifest.xml" || true
grep -q 'extractNativeLibs="true"' "$WORK/decompiled/AndroidManifest.xml" || \
  sed -i '0,/<application/s//<application android:extractNativeLibs="true"/' \
    "$WORK/decompiled/AndroidManifest.xml"

java -jar "$APKTOOL_JAR" b -o "$WORK/unsigned.apk" "$WORK/decompiled"

# ── 步骤 6: zipalign（不签名！签名由开发者自行完成） ─────────────────
log "步骤 6/6 对齐输出"
if command -v zipalign >/dev/null 2>&1; then
  zipalign -f 4 "$WORK/unsigned.apk" "$OUT_APK"
else
  cp "$WORK/unsigned.apk" "$OUT_APK"
  echo "⚠️ 未找到 zipalign，跳过对齐（apksigner 重签前建议自行 zipalign）"
fi

log "完成 ✅ 产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
