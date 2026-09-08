#!/usr/bin/env bash
# protect-sigcheck.sh — 【联合方案】签名校验 + Dex2C 注入总控（模块化流水线之一）
#
# 模块契约：<脚本> <输入.apk> <输出_unsigned.apk>
#   - 输入/输出路径一律 normalize 成绝对路径（报错三/本次 R2 报错的教训：
#     dcc 运行时要切目录，相对输出路径会被写进 dcc 目录）
#   - 主进程 cwd 全程不漂移：dcc.py 在子 shell 里运行（module_cd_run）
#
# 输入: 已下载的用户 APK（开发者自己 keystore 签名）
# 输出: 加固后的未签名 APK（用户自行重签后发布）
#
# 前置依赖（由流水线安装）: python3 + pip 依赖、JDK 17、Android NDK、apktool
set -euo pipefail

IN_APK="$1"
OUT_APK="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"    # apk-protect-action 根目录
MODULE_TAG="sigcheck"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=../lib/lib-repack.sh
source "$ROOT/scripts/lib/lib-repack.sh"
# shellcheck source=../lib/lib-ndk.sh
source "$ROOT/scripts/lib/lib-ndk.sh"

DCC_DIR="$ROOT/sigcheck/dex2c/dcc"            # dcc 工具目录
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── 入口契约校验：所有环境假设在开工前 fail-fast ────────────────────
IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"
require_dir "$DCC_DIR" "dcc 工具目录"
repack_require_tools

# ── 步骤 1: 提取证书指纹，生成 sig_hash.h ──────────────────────────
log_step 1 6 "提取证书指纹"
"$ROOT/scripts/sig-hash/make-sig-hash.sh" "$IN_APK" "$WORK/sig_hash.h"

# ── 步骤 2: dcc 编译主 Activity → C 代码（不编译，只产出工程包） ──
log_step 2 6 "Dex2C 转译"
# 动态解析 Manifest 里的 LAUNCHER activity → 自动生成 filter（一行一个类）
python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" "$WORK/auto_filter.txt" \
  --classes "$WORK/activity_classes.txt" --on-fail error
# auto_filter.txt 已是 dcc filter 正则格式(见 make-filter-from-apk.py),
# 直接使用,不要二次转换 —— 曾经二次转换产生畸形正则导致 no compiled methods
DCC_FILTER="$WORK/auto_filter.txt"

# filter: 只转译主 Activity 的方法（动态类名）
# dcc.py 需要在自身目录运行 → 子 shell 隔离，主进程 cwd 不漂移
module_cd_run "$DCC_DIR" python3 dcc.py "$IN_APK" \
  --project-archive "$WORK/dcc-project.zip" \
  --no-build \
  --filter "$DCC_FILTER"

require_file "$WORK/dcc-project.zip" "dcc 工程包（filter 可能未命中任何方法）"

# ── 步骤 3: 解包工程，合入 sig_check.c + sig_hash.h，改 ABI ─────────
log_step 3 6 "合并校验代码进 NDK 工程"
mkdir -p "$WORK/project/jni/nc"
unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
# dcc 工程自带 jni/Android.mk（wildcard 收 *.cpp）；补上 sig_check.c 与指纹头
cp "$ROOT/sigcheck/src/sig_check.c" "$WORK/project/jni/nc/"
cp "$WORK/sig_hash.h"               "$WORK/project/jni/nc/"
ndk_write_mk "$WORK/project/jni" nc

# ── 步骤 4: NDK 编译 libnc.so ───────────────────────────────────────
log_step 4 6 "NDK 编译"
ndk_build "$WORK/project"

# ── 步骤 5: apktool 解包 → 放 so → 重打包 ───────────────────────────
log_step 5 6 "解包注入重打包"
repack_unpack "$WORK/decompiled" "$IN_APK"

# native 化：把已抽进 so 的方法在 smali 里改成 native 壳，并插 System.loadLibrary("nc")
# （dcc 原版只在自带重打包路径里做壳替换且不插 loadLibrary，纯成品 APK 后处理必须自动补齐）
log_step 5.5 6 "smali native 化"
python3 "$ROOT/scripts/repack/mark-native.py" \
  "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"

repack_install_so "$WORK/decompiled" "$WORK/project/libs"
# 强制解压 so 加载（本方案唯一允许的 Manifest 修改）
repack_force_extractnativelibs "$WORK/decompiled"

repack_build "$WORK/decompiled" "$WORK/unsigned.apk"

# ── 步骤 6: zipalign（不签名！签名由开发者自行完成） ─────────────────
log_step 6 6 "对齐输出"
finish_apk "$WORK/unsigned.apk" "$OUT_APK"

log_done "完成 ✅ 产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
