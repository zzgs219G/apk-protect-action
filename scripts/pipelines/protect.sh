#!/usr/bin/env bash
# protect.sh — 唯一加固总控（勾选式合并版，取代旧三个 pipeline 总控 + run-modules.sh）
#
# 模块契约：<输入.apk> <输出_unsigned.apk> [--sigcheck] [--dex2c <规则文件>] [--packer]
#   - 输入/输出/规则路径一律 normalize 成绝对路径（报错三教训：dcc 运行时要切目录，
#     相对输出路径会被写进 dcc 目录）
#   - 主进程 cwd 全程不漂移：dcc.py 在子 shell 里运行（module_cd_run）
#   - 无论勾选多少模块，apktool 解包/回编只做一次（旧联合方案要两次，这是本次合并
#     的额外收益，对产物无行为差异——sig_check.c 以 constructor 方式并入同一 so）。
#
# 行为对齐（与旧脚本逐一等价）：
#   只 --sigcheck        → 提取指纹 → sig_check.c 单独成 so → inject-loadlib.py
#                          双保险插桩（<clinit> + onCreate）→ 回编
#   只 --dex2c <规则>    → 规则转 filter → dcc 转译 → mark-native.py 壳替换 → 回编
#   --sigcheck --dex2c   → 提取指纹 → dcc 转译 → sig_check.c 合入同一 NDK 工程 →
#                          mark-native.py 壳替换（不插 loadLibrary：onCreate 已抽进 so，
#                          删 <clinit> 的 loadLibrary 会让 native 壳直接自爆）→ 回编
#   --packer             → 占位报错（dpt-shell 流程迁移中，与旧 packer.sh 一致）
#
# 固定执行顺序（与勾选顺序无关）：sigcheck → dex2c → packer
#
# 前置依赖（由 workflow 安装）: python3 + dcc requirements、JDK 17、Android NDK、apktool
set -euo pipefail

# ── 解析勾选（勾选顺序无关，执行顺序由下面 STEP 区硬编码） ────────────
usage() {
  sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[[ $# -ge 2 ]] || usage
IN_APK="$1"
OUT_APK="$2"
shift 2
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"    # apk-protect-action 根目录
MODULE_TAG="protect"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=../lib/lib-repack.sh
source "$ROOT/scripts/lib/lib-repack.sh"
# shellcheck source=../lib/lib-ndk.sh
source "$ROOT/scripts/lib/lib-ndk.sh"

DCC_DIR=""                                    # dcc 工具目录(dex2c 勾选时经 ensure_dcc 解压填充)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

WANT_SIGCHECK=0; WANT_DEX2C=0; WANT_PACKER=0; DEX2C_RULES=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sigcheck) WANT_SIGCHECK=1; shift ;;
    --dex2c)    WANT_DEX2C=1; shift
                [[ $# -ge 1 ]] || { log_err "--dex2c 需要规则文件参数"; exit 1; }
                DEX2C_RULES="$(normalize_path "$1")"; shift ;;
    --packer)   WANT_PACKER=1; shift ;;
    *)          log_err "未知参数: $1"; usage ;;
  esac
done

TOTAL=$((WANT_SIGCHECK + WANT_DEX2C + WANT_PACKER))
if [[ $TOTAL -eq 0 ]]; then
  log_err "未勾选任何模块（--sigcheck / --dex2c <规则> / --packer）"
  exit 1
fi

# ── 入口契约校验：所有环境假设在开工前 fail-fast ────────────────────
IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"
repack_require_tools
if [[ $WANT_DEX2C -eq 1 ]]; then
  require_nonempty_file "$DEX2C_RULES" "dex2c 规则文件"
  DCC_DIR="$(ensure_dcc)"                   # 从 tools/dcc.zip 解压(幂等)并取得 dcc 目录
  require_dir "$DCC_DIR" "dcc 工具目录"
fi
if [[ $WANT_PACKER -eq 1 ]]; then
  log_err "packer 模块尚未接入（dpt-shell 流程迁移中）；请先去掉 --packer 重试"
  exit 1
fi

log "勾选 $TOTAL 个模块，按固定顺序执行: sigcheck → dex2c → packer"

# ── STEP 1: 提取证书指纹，生成 sig_hash.h（仅 --sigcheck） ──────────
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  log_step 1 5 "提取证书指纹"
  "$ROOT/scripts/sig-hash/make-sig-hash.sh" "$IN_APK" "$WORK/sig_hash.h"
fi

# ── STEP 2: dcc 转译（仅 --dex2c，--no-build 只产出工程包） ─────────
if [[ $WANT_DEX2C -eq 1 ]]; then
  log_step 2 5 "Dex2C 转译"
  # 类名来源二选一：显式规则文件，或（联合勾选 sigcheck 时旧联合方案的行为）
  # 由 Manifest 动态解析 LAUNCHER activity 自动生成 filter
  if [[ $WANT_SIGCHECK -eq 1 ]]; then
    # 动态解析 Manifest 里的 LAUNCHER activity → 自动生成 filter（一行一个类）
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
      "$WORK/auto_filter.txt" --classes "$WORK/activity_classes.txt" --on-fail error
    # auto_filter.txt 已是 dcc filter 正则格式(见 make-filter-from-apk.py),
    # 直接使用,不要二次转换 —— 曾经二次转换产生畸形正则导致 no compiled methods
    DCC_FILTER="$WORK/auto_filter.txt"
  else
    python3 "$ROOT/scripts/filter/rules-to-filter.py" "$DEX2C_RULES" \
      "$WORK/dcc_filter.txt" --classes "$WORK/activity_classes.txt"
    # activity* 需要 Activity 类列表 → 从 Manifest 动态提取
    if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$DEX2C_RULES"; then
      log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
      python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
        "$WORK/.placeholder_filter.txt" --classes "$WORK/activity_classes.txt" \
        --on-fail skip || true
    fi
    DCC_FILTER="$WORK/dcc_filter.txt"
  fi

  # dcc.py 需要在自身目录运行 → 子 shell 隔离，主进程 cwd 不漂移
  module_cd_run "$DCC_DIR" python3 dcc.py "$IN_APK" \
    --project-archive "$WORK/dcc-project.zip" \
    --no-build \
    --filter "$DCC_FILTER"

  require_file "$WORK/dcc-project.zip" "dcc 工程包（filter 可能未命中任何方法）"
fi

# ── STEP 3: 组装 NDK 工程 → 编译 libnc.so ───────────────────────────
log_step 3 5 "组装 NDK 工程"
mkdir -p "$WORK/project"
if [[ $WANT_DEX2C -eq 1 ]]; then
  unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
fi
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  # 联合时并入 dcc 工程 jni/nc/；单独时放 jni/ 根 —— ndk_write_mk 的两级
  # wildcard 都收（报错十一/十三教训），两种布局等价
  if [[ $WANT_DEX2C -eq 1 ]]; then
    mkdir -p "$WORK/project/jni/nc"
    cp "$ROOT/sigcheck/src/sig_check.c" "$WORK/project/jni/nc/"
    cp "$WORK/sig_hash.h"               "$WORK/project/jni/nc/"
  else
    mkdir -p "$WORK/project/jni"
    cp "$ROOT/sigcheck/src/sig_check.c" "$WORK/project/jni/"
    cp "$WORK/sig_hash.h"               "$WORK/project/jni/"
  fi
fi
ndk_write_mk "$WORK/project/jni" nc   # mk 模板唯一来源（报错十一），模块名固定 nc

log_step 4 5 "NDK 编译"
ndk_build "$WORK/project"

# ── STEP 5: 解包 → smali 处理 → 放 so → 回编（全组合只做这一次） ────
log_step 5 5 "解包注入重打包"
repack_unpack "$WORK/decompiled" "$IN_APK"

if [[ $WANT_DEX2C -eq 1 ]]; then
  # native 化：把已抽进 so 的方法在 smali 里改成 native 壳，并插 System.loadLibrary("nc")
  # （dcc 原版只在自带重打包路径里做壳替换且不插 loadLibrary，纯成品 APK 后处理必须自动补齐）
  python3 "$ROOT/scripts/repack/mark-native.py" \
    "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"
elif [[ $WANT_SIGCHECK -eq 1 ]]; then
  # 单独签名校验：loadLibrary("nc") 双保险插桩:<clinit> + onCreate 各一份
  # —— 没有 dex2c 的 native 壳保护,攻击者删掉 <clinit> 即可绕过校验;
  #    onCreate 里再插一份,要删两处才失效（联合方案不插：onCreate 已抽进 so,
  #    删 <clinit> 的 loadLibrary 会让 native 壳直接自爆）。幂等:按方法体分别检查。
  # manifest 是二进制 AXML → inject-loadlib 内部走 androguard AXMLPrinter 解析
  python3 "$ROOT/scripts/inject/inject-loadlib.py" "$WORK/decompiled" \
    --launcher --entrypoints --so-name nc
fi

repack_install_so "$WORK/decompiled" "$WORK/project/libs"
# 强制解压 so 加载（本方案唯一允许的 Manifest 修改）
repack_force_extractnativelibs "$WORK/decompiled"
repack_build "$WORK/decompiled" "$WORK/unsigned.apk"

# ── 输出: zipalign（不签名！签名由开发者自行完成） ───────────────────
finish_apk "$WORK/unsigned.apk" "$OUT_APK"

log_done "完成 ✅ 共 $TOTAL 个模块，产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
