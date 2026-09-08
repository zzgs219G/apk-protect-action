#!/usr/bin/env bash
# scripts/modules/dex2c.sh — dex2c 模块包装（薄转发到 protect-dcc.sh）
# 模块契约：<输入.apk> <输出.apk> <规则文件>
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/../pipelines/protect-dcc.sh" "$@"
