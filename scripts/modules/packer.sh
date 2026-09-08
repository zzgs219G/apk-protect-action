#!/usr/bin/env bash
# scripts/modules/packer.sh — 基础加壳模块（占位，暂未接入）
#
# 未来接入口：旧 protect.yml 的 dpt-shell 流程（tools/dpt-shell-v2.19.0.zip，
# java -jar dpt.jar -f app.apk）。编排器保证本模块永远最后执行。
# 模块契约：<输入.apk> <输出.apk>
set -euo pipefail
echo "❌ packer 模块尚未接入（dpt-shell 流程迁移中）；如需加壳请暂用旧的 APK加固 workflow" >&2
exit 1
