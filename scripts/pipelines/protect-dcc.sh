#!/usr/bin/env bash
# protect-dcc.sh — 【独立】Dex2C 加固总控（模块化流水线之一，不掺签名校验）
#
# 与 protect-sigcheck.sh（联合方案）的区别：
#   - 不注入 sig_check.c / 签名校验
#   - 类名由调用方手动指定（一行一个,支持通配符,详见 rules-to-filter.py）
#
# 模块契约：<脚本> <输入.apk> <输出_unsigned.apk> <规则文件>
#   - 输入/输出/规则路径 normalize 成绝对路径；主进程 cwd 全程不漂移
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
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODULE_TAG="dcc"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=../lib/lib-repack.sh
source "$ROOT/scripts/lib/lib-repack.sh"
# shellcheck source=../lib/lib-ndk.sh
source "$ROOT/scripts/lib/lib-ndk.sh"

DCC_DIR="$ROOT/sigcheck/dex2c/dcc"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── 入口契约校验 ────────────────────────────────────────────────────
IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
RULES="$(normalize_path "$RULES")"
require_file "$IN_APK" "输入 APK"
require_nonempty_file "$RULES" "规则文件"
require_dir "$DCC_DIR" "dcc 工具目录"
repack_require_tools

# ── 步骤 1: 通配符规则 → dcc filter ─────────────────────────────────
log_step 1 4 "解析类名规则"
python3 "$ROOT/scripts/filter/rules-to-filter.py" "$RULES" "$WORK/dcc_filter.txt" \
  --classes "$WORK/activity_classes.txt"

# activity* 需要 Activity 类列表 → 从 Manifest 动态提取
if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$RULES"; then
  log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
  python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
    "$WORK/.placeholder_filter.txt" --classes "$WORK/activity_classes.txt" \
    --on-fail skip || true
fi

# ── 步骤 2: dcc 转译（--no-build 只产出工程包） ─────────────────────
log_step 2 4 "Dex2C 转译"
# dcc.py 需要在自身目录运行 → 子 shell 隔离，主进程 cwd 不漂移
module_cd_run "$DCC_DIR" python3 dcc.py "$IN_APK" \
  --project-archive "$WORK/dcc-project.zip" \
  --no-build \
  --filter "$WORK/dcc_filter.txt"

require_file "$WORK/dcc-project.zip" "dcc 工程包（规则可能未命中任何方法）"

# ── 步骤 3: NDK 编译 libnc.so ───────────────────────────────────────
log_step 3 4 "NDK 编译"
mkdir -p "$WORK/project"
unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
# dcc 工程自带 jni/Android.mk；覆盖为统一模板（双 ABI，与其它模块一致）
ndk_write_mk "$WORK/project/jni" nc
ndk_build "$WORK/project"

# ── 步骤 4: 解包 → native 化 → 放 so → 重打包（不签名） ────────────
log_step 4 4 "解包注入重打包"
repack_unpack "$WORK/decompiled" "$IN_APK"

# native 壳替换 + System.loadLibrary("nc") 插桩
python3 "$ROOT/scripts/repack/mark-native.py" \
  "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"

repack_install_so "$WORK/decompiled" "$WORK/project/libs"
# 强制解压 so 加载（extractNativeLibs=true，二进制 AXML 原位改写）
repack_force_extractnativelibs "$WORK/decompiled"

repack_build "$WORK/decompiled" "$WORK/unsigned.apk"

finish_apk "$WORK/unsigned.apk" "$OUT_APK"

log_done "完成 ✅ 产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
