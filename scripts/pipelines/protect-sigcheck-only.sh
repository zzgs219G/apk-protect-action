#!/usr/bin/env bash
# protect-sigcheck-only.sh — 【独立】签名校验注入总控(模块化流水线之一)
#
# 与联合方案(protect-sigcheck.sh)的区别:不跑 dex2c 转译,只注入签名校验。
# 便于单独测试签名校验模块、单独定位问题;也是未来卡片式模块化(勾选功能
# → 按序执行 → 兼容性检查)的第一个独立模块。
#
# 模块化约定(与 dex2c 模块的兼容性设计):
#   - so 名固定为 "nc"(libnc.so)。两模块都勾选时共享同一个 so:
#     dex2c 产出 native 方法壳,sig_check.c 以 __attribute__((constructor))
#     方式并入同一 jni 工程,constructor 先于 JNI_OnLoad 执行,天然兼容。
#   - loadLibrary 插桩统一走 scripts/inject/inject-loadlib.py(幂等)。
#
# 输入: 已下载的用户 APK(开发者自己 keystore 签名)
# 输出: 注入校验后的未签名 APK(用户自行重签后发布)
#
# 前置依赖(由流水线安装): JDK 17、Android NDK、python3
# 用法: protect-sigcheck-only.sh <输入.apk> <输出_unsigned.apk>
set -euo pipefail

IN_APK="$1"
OUT_APK="$2"
# apktool 需要 cd 自身目录?不需要,但统一做绝对路径规范化(防 cd 后失效的历史坑)
IN_APK="$(cd "$(dirname "$IN_APK")" && pwd)/$(basename "$IN_APK")"
OUT_APK="$(cd "$(dirname "$OUT_APK")" && pwd)/$(basename "$OUT_APK")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"    # apk-protect-action 根目录
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

log() { echo "━━━ [sigcheck-only] $* ━━━"; }

[[ -f "$IN_APK" ]] || { echo "❌ 输入 APK 不存在: $IN_APK"; exit 1; }
APKTOOL_JAR="$ROOT/sigcheck/dex2c/dcc/tools/apktool.jar"
[[ -f "$APKTOOL_JAR" ]] || { echo "❌ apktool.jar 缺失: $APKTOOL_JAR"; exit 1; }

# ── 步骤 1: 提取证书指纹，生成 sig_hash.h ──────────────────────────
log "步骤 1/5 提取证书指纹"
"$ROOT/scripts/sig-hash/make-sig-hash.sh" "$IN_APK" "$WORK/sig_hash.h"

# ── 步骤 2: 组装最小 NDK 工程(只含 sig_check.c,无 dex2c 产物) ──────
log "步骤 2/5 组装 NDK 工程"
mkdir -p "$WORK/project/jni/nc"
cp "$ROOT/sigcheck/src/sig_check.c" "$WORK/project/jni/nc/"
cp "$WORK/sig_hash.h"               "$WORK/project/jni/nc/"
# 复用 dcc 工程的 mk 模板逻辑:模块名 nc(模块化约定),wildcard 收源文件。
# 注意 dcc 的 Android.mk 只 wildcard *.cpp,这里写自包含的 mk(含 *.c)。
cat > "$WORK/project/jni/Android.mk" <<'EOF'
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := nc
LOCAL_LDLIBS    := -llog

SOURCES := $(wildcard $(LOCAL_PATH)/nc/*.cpp) $(wildcard $(LOCAL_PATH)/nc/*.c)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/nc

LOCAL_SRC_FILES := $(SOURCES:$(LOCAL_PATH)/%=%)

include $(BUILD_SHARED_LIBRARY)
EOF
# 双 ABI 输出(与联合方案一致;APP_PLATFORM 21 保证 constructor+pthread 可用)
cat > "$WORK/project/jni/Application.mk" <<'EOF'
APP_STL := c++_static
APP_CPPFLAGS += -fvisibility=hidden
APP_PLATFORM := android-21
APP_ABI := armeabi-v7a arm64-v8a
EOF

# ── 步骤 3: NDK 编译 libnc.so ───────────────────────────────────────
log "步骤 3/5 NDK 编译"
: "${ANDROID_NDK_HOME:?需要设置 ANDROID_NDK_HOME 环境变量指向 NDK 根目录}"
PATH="$ANDROID_NDK_HOME:$PATH" ndk-build -j"$(nproc)" -C "$WORK/project"

# ── 步骤 4: apktool 解包 → loadLibrary 插桩 → 放 so → 重打包 ───────
# 注意:解包命令不带 --force-manifest(报错五)。
# 带 --force-manifest 时顶层 manifest 被解码成文本 XML,而 apktool b 在 -r
# 模式下会把文本 manifest 原样拷回 APK、不重编成 AXML → 产物是系统/MT 都
# 不认的"灰包"。不带它时顶层保持二进制 AXML,回编原样带走,产物合法。
log "步骤 4/5 解包注入重打包"
java -jar "$APKTOOL_JAR" d -r -f --no-debug-info -o "$WORK/decompiled" "$IN_APK"
# ↑ 不带 --force-manifest(报错五)。--no-debug-info(报错八):baksmali 丢弃
#   .line/.local 等调试指令,回编后 dex 不再重建 debug_info 区块(实测简盒包
#   dex 缩小约 1.8MB)。debug_info 仅用于断点调试/崩溃行号,无运行时作用。

# loadLibrary("nc") 双保险插桩:<clinit> + onCreate 各一份
# —— 单独方案没有 dex2c 的 native 壳保护,攻击者删掉 <clinit> 即可绕过校验;
#    onCreate 里再插一份,要删两处才失效(联合方案 protect-sigcheck.sh 不需要:
#    onCreate 已抽进 so,删 <clinit> 的 loadLibrary 会让 native 壳直接自爆)。
# 幂等:按方法体分别检查,两处互不影响
# manifest 是二进制 AXML → inject-loadlib 内部走 androguard AXMLPrinter 解析
log "步骤 4.5/5 主 Activity loadLibrary 双保险插桩"
python3 "$ROOT/scripts/inject/inject-loadlib.py" "$WORK/decompiled" --launcher --entrypoints --so-name nc

for abi_dir in "$WORK/project/libs"/*; do
  abi=$(basename "$abi_dir")
  mkdir -p "$WORK/decompiled/lib/$abi"
  cp "$abi_dir/libnc.so" "$WORK/decompiled/lib/$abi/"
done
# 强制解压 so 加载(本方案唯一允许的 Manifest 修改)
# 二进制 AXML 无法 sed → 用 patch-extractnativelibs.py 原位等尺寸改写
log "步骤 4.6/5 extractNativeLibs=true(二进制 AXML 原位补丁)"
python3 "$ROOT/scripts/repack/patch-extractnativelibs.py" "$WORK/decompiled/AndroidManifest.xml"

java -jar "$APKTOOL_JAR" b -o "$WORK/unsigned.apk" "$WORK/decompiled"

# ── 步骤 5: zipalign(不签名!签名由开发者自行完成) ─────────────────
log "步骤 5/5 对齐输出"
if command -v zipalign >/dev/null 2>&1; then
  zipalign -f 4 "$WORK/unsigned.apk" "$OUT_APK"
else
  cp "$WORK/unsigned.apk" "$OUT_APK"
  echo "⚠️ 未找到 zipalign，跳过对齐（apksigner 重签前建议自行 zipalign）"
fi

log "完成 ✅ 产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
