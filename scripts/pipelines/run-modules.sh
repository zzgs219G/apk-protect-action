#!/usr/bin/env bash
# run-modules.sh — 勾选式模块编排器（未来卡片式勾选的执行核心）
#
# 业务规则：
#   - 模块可任意组合勾选，但【执行顺序固定】，与勾选顺序无关：
#       1. sigcheck  签名校验（需在壳/转译前注入，依赖原包证书指纹）
#       2. dex2c     Dex2C 转译（native 化后 smali 不可再改）
#       3. packer    基础加壳/壳保护（必须最后：加了壳其它模块都改不动了）
#   - 每个模块对外契约统一：scripts/modules/<模块>.sh <输入.apk> <输出.apk> [模块参数]
#   - 模块之间只传递一个中间 APK 文件，串行 pipeline，失败即停（fail-fast）
#
# 现有模块映射（scripts/modules/ 下是指向真实实现的薄包装，保持模块名稳定）：
#   sigcheck.sh → ../pipelines/protect-sigcheck-only.sh（纯签名校验注入）
#   dex2c.sh    → ../pipelines/protect-dcc.sh（需规则文件参数）
#   packer.sh   → 暂未接入（旧 protect.yml 的 dpt-shell 流程；加了壳必须放最后）
#
# 用法:
#   run-modules.sh <输入.apk> <输出_unsigned.apk> [--sigcheck] [--dex2c <规则文件>] [--packer]
#
# 示例:
#   # 签名校验 + dex2c 组合
#   run-modules.sh app.apk out.apk --sigcheck --dex2c rules.txt
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MODULE_TAG="orchestrator"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"

usage() {
  sed -n '3,30p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

[[ $# -ge 2 ]] || usage

IN_APK="$(normalize_path "$1")"
OUT_APK="$(normalize_path "$2")"
shift 2

require_file "$IN_APK" "输入 APK"

# ── 解析勾选（勾选顺序无关，执行顺序由下面 ORCHESTRATION 区硬编码） ──
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

log "勾选 $TOTAL 个模块，按固定顺序执行: sigcheck → dex2c → packer"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# 模块名 → 模块包装脚本
MODULES_DIR="$ROOT/scripts/modules"

# ── ORCHESTRATION：顺序硬编码在此，勿按勾选顺序执行 ──────────────────
CURRENT="$IN_APK"
IDX=0

run_module() {
  IDX=$((IDX + 1))
  local script="$1"; shift
  local out="$1"; shift
  log "▶ [$IDX/$TOTAL] 执行模块: $(basename "$script")"
  "$script" "$CURRENT" "$out" "$@"
  CURRENT="$out"
}

# 1. 签名校验（最先：依赖原包证书指纹，且必须在 smali/壳被改动前注入）
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  require_file "$MODULES_DIR/sigcheck.sh" "sigcheck 模块"
  run_module "$MODULES_DIR/sigcheck.sh" "$WORK/step_sigcheck.apk"
fi

# 2. Dex2C（native 化后 smali 不可再改，故在加壳之前）
if [[ $WANT_DEX2C -eq 1 ]]; then
  require_file "$MODULES_DIR/dex2c.sh" "dex2c 模块"
  require_nonempty_file "$DEX2C_RULES" "dex2c 规则文件"
  run_module "$MODULES_DIR/dex2c.sh" "$WORK/step_dex2c.apk" "$DEX2C_RULES"
fi

# 3. 基础加壳（必须最后：壳一旦加上，dex/manifest 都不可再改）
if [[ $WANT_PACKER -eq 1 ]]; then
  require_file "$MODULES_DIR/packer.sh" "packer 模块"
  run_module "$MODULES_DIR/packer.sh" "$WORK/step_packer.apk"
fi

# ── 输出 ────────────────────────────────────────────────────────────
finish_apk "$CURRENT" "$OUT_APK"
log_done "编排完成 ✅ 共 $TOTAL 个模块，产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
