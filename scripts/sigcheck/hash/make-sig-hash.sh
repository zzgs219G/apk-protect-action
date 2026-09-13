#!/usr/bin/env bash
# make-sig-hash.sh — 从 APK 提取证书指纹，生成 sig_hash.h
# 用法: make-sig-hash.sh <apk路径> <输出sig_hash.h路径>
# 依赖（按优先级）:
#   1. apksigner (build-tools) — v1/v2/v3 全支持
#   2. scripts/extract-cert-fp.py (纯 python3 标准库) — 解析 v2/v3 Signing Block
#   3. keytool (JDK) — 仅 v1 (JAR) 签名兜底
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
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
# GitHub runner 预装了 Android SDK 但 build-tools 不在 PATH，逐个探测
SDK_ROOT="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-/usr/local/lib/android/sdk}}"
for bt in "$SDK_ROOT"/build-tools/*/apksigner "$SDK_ROOT"/cmdline-tools/latest/bin/apksigner; do
  [[ -x "$bt" ]] || continue
  # --print-certs 输出形如: Signer #1 certificate SHA-256 digest: abcd1234...
  if HASH_HEX=$("$bt" verify --print-certs "$APK" 2>/dev/null \
      | grep -m1 "SHA-256 digest" | grep -oE '[0-9a-fA-F]{64}') && [[ -n "$HASH_HEX" ]]; then
    echo "ℹ️ 指纹提取自 apksigner: $bt"
    break
  fi
  HASH_HEX=""
done

# 方案 B: 纯 Python 解析 APK Signing Block（v2/v3），零外部依赖兜底
if [[ -z "$HASH_HEX" ]] && command -v python3 >/dev/null 2>&1; then
  HASH_HEX=$(python3 "$SCRIPT_DIR/extract-cert-fp.py" "$APK" 2>&1 | tail -1 || true)
  if [[ ! "$HASH_HEX" =~ ^[0-9a-f]{64}$ ]]; then
    echo "⚠️ Python Signing Block 解析失败: $HASH_HEX" >&2
    HASH_HEX=""
  else
    echo "ℹ️ 指纹提取自 extract-cert-fp.py (v2/v3 Signing Block)"
  fi
fi

# 方案 C: keytool（JDK 自带，最后兜底，仅 v1 签名有效）
if [[ -z "$HASH_HEX" ]] && command -v keytool >/dev/null 2>&1; then
  HASH_HEX=$(keytool -printcert -jarfile "$APK" 2>/dev/null \
    | grep -A1 -m1 "SHA256:" \
    | grep -oE '([0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}' \
    | head -1 | tr -d ':' || true)
  [[ -n "$HASH_HEX" ]] && echo "ℹ️ 指纹提取自 keytool (v1 签名)"
fi

if [[ -z "$HASH_HEX" ]]; then
  echo "❌ 无法提取证书指纹：apksigner / Signing Block 解析 / keytool 三种方式均失败" >&2
  echo "   排查: 1) APK 是否完整下载  2) 是否至少有 v1/v2/v3 之一签名  3) 手动运行:" >&2
  echo "         python3 $SCRIPT_DIR/extract-cert-fp.py \"$APK\"" >&2
  exit 1
fi

# 归一为小写 64 位十六进制
HASH_HEX=$(echo "$HASH_HEX" | tr 'A-F' 'a-f')
if [[ ! "$HASH_HEX" =~ ^[0-9a-f]{64}$ ]]; then
  echo "❌ 指纹格式异常: $HASH_HEX" >&2
  exit 1
fi

# ── 双轮派生:so 内不存明文指纹(防十六进制搜索替换攻击) ──────────────
# 生成侧(python)与校验侧(sig_check.c derive_expected)必须逐字节一致:
#   salt   = os.urandom(16)                        每次构建随机 → 旧包攻击偏移全部失效
#   t1     = SHA256(fp)                            轮1: 吸收(只对指纹,不含 salt)
#   stored = t1[i] ^ salt[i%16] ^ (i*0x9E & 0xFF)  轮2: 位置依赖 XOR 扩散
# 攻击者拿不到派生逻辑就不知道"换成自己的证书该写什么";明文指纹不再出现于 so。
DERIVED_JSON=$(python3 - "$HASH_HEX" <<'PYEOF'
import hashlib, os, sys, json
fp = bytes.fromhex(sys.argv[1])
salt = os.urandom(16)
t1 = hashlib.sha256(fp).digest()
stored = bytes(t1[i] ^ salt[i % 16] ^ ((i * 0x9E) & 0xFF) for i in range(32))
print(json.dumps({"salt": salt.hex(), "stored": stored.hex()}))
PYEOF
)
SALT_HEX=$(printf '%s' "$DERIVED_JSON" | grep -o '"salt": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{32\}')
STORED_HEX=$(printf '%s' "$DERIVED_JSON" | grep -o '"stored": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{64\}')
if [[ ${#SALT_HEX} -ne 32 || ${#STORED_HEX} -ne 64 ]]; then
  echo "❌ 双轮派生失败(python 输出异常): $DERIVED_JSON" >&2
  exit 1
fi

# 生成 C 头文件（每行 8 字节;SIG_SALT 随机、SIG_HASH_STORED 为派生形态,均非明文指纹）
{
  echo "/* 由流水线自动生成: $(basename "$APK") 证书指纹的双轮派生形态 */"
  echo "/* 攻防说明: 明文指纹不落盘。攻击面分析见 docs/流程文档.md §9(2026-10 存储混淆) */"
  echo "#ifndef _SIG_HASH_H_"
  echo "#define _SIG_HASH_H_"
  echo "#define SIG_HASH_LEN 32"
  echo "#define SIG_SALT_LEN 16"
  echo "static const unsigned char SIG_SALT[SIG_SALT_LEN] = {"
  for ((i = 0; i < 32; i += 16)); do
    row=""
    for ((j = 0; j < 16; j += 2)); do
      row+="0x${SALT_HEX:i+j:2}, "
    done
    echo "    ${row%, },"
  done
  echo "};"
  echo "static const unsigned char SIG_HASH_STORED[SIG_HASH_LEN] = {"
  for ((i = 0; i < 64; i += 16)); do
    row=""
    for ((j = 0; j < 16; j += 2)); do
      row+="0x${STORED_HEX:i+j:2}, "
    done
    echo "    ${row%, },"
  done
  echo "};"
  echo "#endif"
} > "$OUT"

echo "✅ sig_hash.h 已生成(双轮派生形态,明文指纹未写入): 指纹=$HASH_HEX salt=$SALT_HEX"
