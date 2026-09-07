#!/usr/bin/env bash
# gen_sig_hash.sh — 从 APK 提取证书指纹，生成 sig_hash.h
# 用法: gen_sig_hash.sh <apk路径> <输出sig_hash.h路径>
# 依赖: apksigner(build-tools) 或 keytool(JDK)
set -euo pipefail

APK="$1"
OUT="$2"

if [[ $# -ne 2 ]]; then
  echo "用法: $0 <apk> <输出.h>" >&2
  exit 1
fi
if [[ ! -f "$APK" ]]; then
  echo "❌ APK 不存在: $APK" >&2
  exit 1
fi

HASH_HEX=""

# 方案 A: apksigner（build-tools 自带，优先）
if command -v apksigner >/dev/null 2>&1; then
  # --print-certs 输出形如:
  # Signer #1 certificate SHA-256 digest: abcd1234...
  HASH_HEX=$(apksigner verify --print-certs "$APK" 2>/dev/null \
    | grep -m1 "SHA-256 digest" \
    | grep -oE '[0-9a-fA-F]{64}' || true)
fi

# 方案 B: keytool（JDK 自带，兜底）
if [[ -z "$HASH_HEX" ]] && command -v keytool >/dev/null 2>&1; then
  HASH_HEX=$(keytool -printcert -jarfile "$APK" 2>/dev/null \
    | grep -A1 -m1 "SHA256:" \
    | grep -oE '([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}' \
    | head -1 | tr -d ':' || true)
fi

if [[ -z "$HASH_HEX" ]]; then
  echo "❌ 无法提取证书指纹：APK 可能无 v2/v3 签名，且 keytool 也未找到 v1 证书" >&2
  exit 1
fi

# 归一为小写 64 位十六进制
HASH_HEX=$(echo "$HASH_HEX" | tr 'A-F' 'a-f')
if [[ ! "$HASH_HEX" =~ ^[0-9a-f]{64}$ ]]; then
  echo "❌ 指纹格式异常: $HASH_HEX" >&2
  exit 1
fi

# 生成 C 头文件（每行 8 字节）
{
  echo "/* 由流水线自动生成：$(basename "$APK") 的证书 SHA-256 指纹 */"
  echo "#ifndef _SIG_HASH_H_"
  echo "#define _SIG_HASH_H_"
  echo "#define SIG_HASH_LEN 32"
  echo "static const unsigned char SIG_HASH[SIG_HASH_LEN] = {"
  for ((i = 0; i < 64; i += 16)); do
    row=""
    for ((j = 0; j < 16; j += 2)); do
      row+="0x${HASH_HEX:i+j:2}, "
    done
    echo "    ${row%, },"
  done
  echo "};"
  echo "#endif"
} > "$OUT"

echo "✅ sig_hash.h 已生成，指纹: $HASH_HEX"
