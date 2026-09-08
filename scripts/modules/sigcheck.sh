#!/usr/bin/env bash
# scripts/modules/sigcheck.sh — sigcheck 模块包装（薄转发到 protect-sigcheck-only.sh）
# 模块契约：<输入.apk> <输出.apk>
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
exec "$DIR/../pipelines/protect-sigcheck-only.sh" "$@"
