#!/usr/bin/env bash
# packer.sh — 基础加壳模块（dpt-shell 路线）
#
# 模块契约：<输入.apk> <输出.apk>
#   - 输入/输出路径一律 normalize 成绝对路径（与 protect.sh 同一约定，报错三教训）
#   - 主进程 cwd 全程不漂移：dpt.jar 需要在自身目录运行（shell-files/ 与
#     build-key 必须与 jar 同级，见下方契约），一律走 module_cd_run 子 shell
#   - 产物不签名（-x），沿用本仓库"未签名包、开发者自行重签"契约
#
# dpt CLI 契约（由 dpt-shell v2.17.0 字节码 + --help 实测钉死，勿凭猜测改）：
#   java -jar dpt.jar -f <in.apk> -o <outdir> [-x] [-r <rules>] [-c <config>]
#   - getExecutablePath() = jar 所在目录 → executable/shell-files/ 与
#     executable/build-key 必须与 executable/dpt.jar 同级，解压布局不能改
#   - 产物文件名 getNewFileName(x, "unsign") 模板为 `_<suffix>.<ext>`
#     → <包名>_unsign.apk，落在 -o 指定的输出目录下
#   - -x / --no-sign：不签名（Builder 默认 sign=1，不传 -x 会用包内
#     assets/dpt.jks 重新签名，与本仓库"产出未签名包"契约冲突）
#   - -r / --rules-file：**不加固**的类名正则名单（注意与 dex2c/stringenc 的
#     规则语义相反，见下方"规则语义警告"），故本模块只吃 dpt 包内自带模板
#
# 规则语义警告（本模块刻意不暴露自定义规则的原因）：
#   dex2c / stringenc：`!com.x.**` = 排除处理（不转译/不加密）
#   dpt -r：           命中的类 = 排除加固（保持明文）
#   两者方向相反，且 dpt 用斜杠正则（Lafzkl/development/.*）、另两者用点号
#   通配符（com.test.**）。共用一份规则必然静默语义反转 → 本模块只提供
#   leaf 开关，规则固定取包内模板，不接受用户输入。
set -euo pipefail

usage() {
  awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
  exit 1
}

[[ $# -eq 2 ]] || usage
IN_APK="$1"
OUT_APK="$2"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"   # apk-protect-action 根目录
MODULE_TAG="packer"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"

IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"

# ── 解压 dpt 分发包（幂等，仿 ensure_dcc 的形态）────────────────────
# tools/dpt-shell.zip 内顶层即 executable/，解压到 <仓库根>/tools/ 得单层
# tools/executable/（与 dcc.zip 的"顶层即 dcc/"形态一致，报错十五：unzip 不
# 自建多级父目录 → 目标父目录必须已存在，tools/ 必然存在）。
# 解压产物不进版本库，由 .gitignore 的 /tools/dcc/ 同类规则忽略（见下方备注）。
DPT_ZIP="$ROOT/tools/dpt-shell.zip"
DPT_EXE_DIR="$ROOT/tools/executable"

ensure_dpt() {
  if [[ -f "$DPT_EXE_DIR/dpt.jar" ]]; then
    return 0
  fi
  require_file "$DPT_ZIP" "dpt-shell 分发包"
  log_info "解压 $DPT_ZIP → $DPT_EXE_DIR"
  unzip -qo "$DPT_ZIP" -d "$ROOT/tools"
  [[ -f "$DPT_EXE_DIR/dpt.jar" ]] \
    || { log_err "dpt-shell.zip 解压后缺 executable/dpt.jar"; exit 1; }
}

ensure_dpt
DPT_JAR="$DPT_EXE_DIR/dpt.jar"
DPT_RULES="$DPT_EXE_DIR/dpt-exclude-classes-template.rules"
require_file "$DPT_JAR" "dpt.jar"
# dpt 的 getExecutablePath() = jar 所在目录，shell-files/ 与 build-key 必须与
# dpt.jar 同级。解压布局一旦错位（多套一层 executable/）dpt 会在运行时报
# 一句难懂的缺文件错误；这里提前钉死，比在 dpt 日志里翻找快得多。
if [[ ! -d "$DPT_EXE_DIR/shell-files" ]]; then
  log_err "解压布局错位：$DPT_EXE_DIR/shell-files 不存在"
  log_err "     dpt 要求 dpt.jar / shell-files/ / build-key 三者同级"
  exit 1
fi
# 规则表随包分发；缺失不静默降级（裸跑会把 android./java./kotlin. 等系统类
# 也塞进壳，加壳后启动失败面显著变大 —— 宁漏勿误伤，故 fail-fast）
require_nonempty_file "$DPT_RULES" "dpt 不加固规则表"

# ── 执行加壳 ────────────────────────────────────────────────────────
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
DPT_OUT="$WORK/dpt-out"
# 预建输出目录：不依赖 dpt 自己去建（不同版本行为不一致，且缺失时报错会指到
# 无关的地方）。建好后再取产物，find 语义也更确定。
mkdir -p "$DPT_OUT"

log_info "加壳: $(basename "$IN_APK") （规则: 包内 dpt-exclude-classes-template.rules）"

# dpt.jar 需在 executable/ 下运行才能找到 shell-files/ 与 build-key
module_cd_run "$DPT_EXE_DIR" java -jar "$DPT_JAR" \
  -f "$IN_APK" \
  -o "$DPT_OUT" \
  -x \
  -r "$DPT_RULES"

# ── 取产物 ──────────────────────────────────────────────────────────
# 不硬编码 <包名>_unsign.apk（包名含点、转文件名易错，且 dpt 版本换名会炸）：
# 只认「_unsign.apk 后缀」这一个契约，扫描命中多个即 fail-fast。
produced="$(find "$DPT_OUT" -maxdepth 1 -name '*_unsign.apk' -type f 2>/dev/null || true)"
if [[ -z "$produced" ]]; then
  log_err "dpt 未产出 *_unsign.apk（输出目录: $DPT_OUT）"
  log_err "     检查：dpt 日志有无异常；或该 APK 是否已是加固壳包"
  exit 1
fi
count="$(printf '%s\n' "$produced" | grep -c . || true)"
if [[ "$count" -ne 1 ]]; then
  log_err "dpt 产出多个 *_unsign.apk（$count 个），无法判定取哪个："
  printf '%s\n' "$produced" >&2
  exit 1
fi
require_file "$produced" "dpt 加壳产物"

mkdir -p "$(dirname "$OUT_APK")"
cp "$produced" "$OUT_APK"
log_done "加壳完成: $OUT_APK"