#!/usr/bin/env bash
# common.sh — 加固流水线公共库（被 pipeline/模块脚本 source，不直接执行）
#
# 设计目标（对应历次报错教训）：
#   1. 状态永不依赖 cwd：所有路径在入口处 normalize 成绝对路径（报错三/这次 R2 报错），
#      需要切换目录运行的工具一律放子 shell：module_cd_run <dir> <cmd...>
#   2. 前置条件 fail-fast：require_file / require_dir 在开工前把环境假设全部验掉
#      （apktool.jar 缺失、规则文件为空等）。
#   3. 重复逻辑只写一份：zipalign 输出、日志格式统一在这里。
#
# 约定：调用方 source 本文件后必须已设置 MODULE_TAG（日志前缀），例如 "sigcheck"。

# 防止直接执行（只能 source）
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "❌ common.sh 是公共库，请用 source 引入，不要直接执行" >&2
  exit 1
fi

MODULE_TAG="${MODULE_TAG:-pipeline}"

log()      { echo "━━━ [$MODULE_TAG] $* ━━━"; }
log_step() { echo "━━━ [$MODULE_TAG] $1/$2 $3 ━━━"; }
log_info() { echo "ℹ️ [$MODULE_TAG] $*"; }
log_warn() { echo "⚠️ [$MODULE_TAG] $*"; }
log_err()  { echo "❌ [$MODULE_TAG] $*" >&2; }
log_done() { echo "✅ [$MODULE_TAG] $*"; }

# normalize_path <路径> → 绝对路径（stdout）
# 入口处统一调用；目录必须存在（mkdir_prepare 可先行建好父目录）
normalize_path() {
  local p="$1"
  if [[ -d "$p" ]]; then
    (cd "$p" && pwd)
  else
    local dir base abs
    dir="$(dirname "$p")"; base="$(basename "$p")"
    mkdir -p "$dir"
    abs="$(cd "$dir" && pwd)"
    echo "$abs/$base"
  fi
}

# require_file <文件> [描述] — 不存在即退出
require_file() {
  [[ -f "$1" ]] || { log_err "$2 缺失: $1"; exit 1; }
}

# require_dir <目录> [描述] — 不存在即退出
require_dir() {
  [[ -d "$1" ]] || { log_err "$2 缺失: $1"; exit 1; }
}

# require_nonempty_file <文件> [描述] — 不存在或没有任何有效行（空行/纯空白/
# 以 # 开头的注释行不算）即退出
require_nonempty_file() {
  require_file "$1" "${2:-文件}"
  # 剥注释行再找非空行：'#注释' 是注释(整行 # 开头)，'foo#bar' 是有效内容
  if ! sed 's/^[[:space:]]*#.*//' "$1" | grep -q '[^[:space:]]'; then
    log_err "文件没有任何有效内容（只有空行/注释）: $1"; exit 1
  fi
}

# require_env <变量名> [描述] — 环境变量未设置/为空即退出
require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || { log_err "环境变量 $name 未设置${2:+（$2）}"; exit 1; }
}

# ensure_dcc [解压根目录，默认 "$ROOT/build/dcc"] → 解压后 dcc 目录路径(stdout)
# dcc 已从 sigcheck/dex2c/dcc/ 摊开目录改为 tools/dcc.zip 分发(单文件制品,
# 与 dpt-shell 形态一致)。zip 内顶层是 dcc/,解压到 <根>/ 即得 <根>/dcc。
# 幂等:目标已存在(dcc.py 可见)则跳过解压,重复调用零开销。
DCC_ZIP="$ROOT/tools/dcc.zip"    # dcc 分发包(唯一真源,严禁与解压产物混改)
ensure_dcc() {
  local dest="${1:-$ROOT/build/dcc}"
  if [[ -f "$dest/dcc/dcc.py" ]]; then
    echo "$dest/dcc"
    return 0
  fi
  require_file "$DCC_ZIP" "dcc 分发包"
  mkdir -p "$dest"
  unzip -qo "$DCC_ZIP" -d "$dest"
  [[ -f "$dest/dcc/dcc.py" ]] || { log_err "dcc.zip 解压后缺 dcc/dcc.py: $dest"; exit 1; }
  echo "$dest/dcc"
}

# module_cd_run <目录> <命令...> — 在子 shell 里切目录执行，主进程 cwd 永不漂移
module_cd_run() {
  local dir="$1"; shift
  (cd "$dir" && "$@")
}

# finish_apk <中间产物.apk> <最终输出.apk> — zipalign（有则对齐，无则拷贝）
finish_apk() {
  local src="$1" dst="$2"
  if command -v zipalign >/dev/null 2>&1; then
    zipalign -f 4 "$src" "$dst"
  else
    cp "$src" "$dst"
    log_warn "未找到 zipalign，跳过对齐（apksigner 重签前建议自行 zipalign）"
  fi
}
