#!/usr/bin/env bash
# protect-sigcheck-only.sh — 【独立】签名校验注入总控（模块化流水线之一）
#
# 与联合方案(protect-sigcheck.sh)的区别:不跑 dex2c 转译,只注入签名校验。
# 便于单独测试签名校验模块、单独定位问题;也是勾选式编排(run-modules.sh)的
# 独立模块之一。
#
# 模块契约：<脚本> <输入.apk> <输出_unsigned.apk>
#   - 输入/输出路径 normalize 成绝对路径；主进程 cwd 全程不漂移
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
set -euo pipefail

IN_APK="$1"
OUT_APK="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODULE_TAG="sigcheck-only"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=../lib/lib-repack.sh
source "$ROOT/scripts/lib/lib-repack.sh"
# shellcheck source=../lib/lib-ndk.sh
source "$ROOT/scripts/lib/lib-ndk.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── 入口契约校验 ────────────────────────────────────────────────────
IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"
repack_require_tools

# ── 步骤 1: 提取证书指纹，生成 sig_hash.h ──────────────────────────
log_step 1 5 "提取证书指纹"
"$ROOT/scripts/sig-hash/make-sig-hash.sh" "$IN_APK" "$WORK/sig_hash.h"

# ── 步骤 2: 组装最小 NDK 工程(只含 sig_check.c,无 dex2c 产物) ──────
log_step 2 5 "组装 NDK 工程"
mkdir -p "$WORK/project/jni"
cp "$ROOT/sigcheck/src/sig_check.c" "$WORK/project/jni/"
cp "$WORK/sig_hash.h"               "$WORK/project/jni/"
# 复用 lib-ndk 的统一 mk 模板:模块名 nc(模块化约定),wildcard 收 *.cpp/*.c
ndk_write_mk "$WORK/project/jni" nc

# ── 步骤 3: NDK 编译 libnc.so ───────────────────────────────────────
log_step 3 5 "NDK 编译"
ndk_build "$WORK/project"

# ── 步骤 4: apktool 解包 → loadLibrary 插桩 → 放 so → 重打包 ───────
log_step 4 5 "解包注入重打包"
repack_unpack "$WORK/decompiled" "$IN_APK"

# loadLibrary("nc") 双保险插桩:<clinit> + onCreate 各一份
# —— 单独方案没有 dex2c 的 native 壳保护,攻击者删掉 <clinit> 即可绕过校验;
#    onCreate 里再插一份,要删两处才失效(联合方案 protect-sigcheck.sh 不需要:
#    onCreate 已抽进 so,删 <clinit> 的 loadLibrary 会让 native 壳直接自爆)。
# 幂等:按方法体分别检查,两处互不影响
# manifest 是二进制 AXML → inject-loadlib 内部走 androguard AXMLPrinter 解析
log_step 4.5 5 "主 Activity loadLibrary 双保险插桩"
python3 "$ROOT/scripts/inject/inject-loadlib.py" "$WORK/decompiled" --launcher --entrypoints --so-name nc

repack_install_so "$WORK/decompiled" "$WORK/project/libs"
# 强制解压 so 加载(本方案唯一允许的 Manifest 修改)
repack_force_extractnativelibs "$WORK/decompiled"

repack_build "$WORK/decompiled" "$WORK/unsigned.apk"

# ── 步骤 5: zipalign(不签名!签名由开发者自行完成) ─────────────────
log_step 5 5 "对齐输出"
finish_apk "$WORK/unsigned.apk" "$OUT_APK"

log_done "完成 ✅ 产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
