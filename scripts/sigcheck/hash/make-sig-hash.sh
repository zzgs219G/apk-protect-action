#!/usr/bin/env bash
# make-sig-hash.sh — 从 APK 提取证书指纹，生成 sig_hash.h + sig_guard2.h
# 用法: make-sig-hash.sh <apk路径> <输出sig_hash.h路径> [输出sig_guard2.h路径]
#
# 2026-10 独立双线:除原有 sig_hash.h 外,再生成一份【独立答案】sig_guard2.h,
#   供独立模块 sig_guard2.c 使用。两线的关系:
#     - 各自的 salt 独立随机、派生公式不同(见下方两处 python)
#     - 攻击者改掉一条线的标准值,另一条线的判定不受影响
#     - 不共用头文件是刻意的:共享 = 单点(改一处两线同废)
#   第 3 个参数缺省时只生成 sig_hash.h(向后兼容旧调用)。
# 依赖（按优先级）:
#   1. apksigner (build-tools) — v1/v2/v3 全支持
#   2. scripts/extract-cert-fp.py (纯 python3 标准库) — 解析 v2/v3 Signing Block
#   3. keytool (JDK) — 仅 v1 (JAR) 签名兜底
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APK="$1"
OUT="$2"
OUT2="${3:-}"   # 可选:第二份独立答案(sig_guard2.h)

if [[ $# -lt 2 ]]; then
  echo "用法: $0 <apk> <输出sig_hash.h> [输出sig_guard2.h]" >&2
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
#
# 2026-10-19 段标记：两张表在生产构建下进 .ncxr 加密段（段名已中性化）。
#   实测报告 §3.6/§8.1 指出：判定算法与这两张表原先全在 .rodata，
#   攻击者 `od` 一条命令读出 salt + stored，5 分钟反推出 32 字节通过凭据。
#   加了段属性后，未解锁时 od 读到的是随机密文。
# ⚠️ 条件化理由（三条）：
#   ① 宿主测试（NCLINK_HOST_TEST）没有解锁设施，标段 = 读到密文 = 假红
#   ② sig_check.c（冻结模块）也用这张表，但它自己的 constructor 在 unlock
#      之后才跑（50 < 65535），所以标段对它是安全的、且同样受益
#   ③ 段名与 lib-ndk.sh 的 retain 纪律一致，必须带 used 防 gc-sections 回收
{
  echo "/* 由流水线自动生成: $(basename "$APK") 证书指纹的双轮派生形态 */"
  echo "/* 攻防说明: 明文指纹不落盘。攻击面分析见 docs/流程文档.md §9(2026-10 存储混淆) */"
  echo "/* 2026-10-19: 生产构建下两张表进 .ncxr 加密段(NC_GUARD_SECTIONED)。 */"
  echo "#ifndef _SIG_HASH_H_"
  echo "#define _SIG_HASH_H_"
  echo ""
  echo "/* 段属性宏：只有明确开启 NC_GUARD_SECTIONED 且非宿主测试时才生效。"
  echo " * 未开启时退化为空宏 —— 宿主编译/单元测试行为完全不变。 */"
  echo "#if defined(NC_GUARD_SECTIONED) && !defined(NCLINK_HOST_TEST)"
  echo "/* 数据段必须是【不可执行】的独立段：clang 不允许 const 数据进 AXR 段，"
  echo " * 会报 \"causes a section type conflict\"。见 nc_link.c 的注释。 */"
  # ⚠️ 显式判存在性，不依赖 set -e/pipefail 兜底：
  #    sed 失败时若被加上 2>/dev/null，$(...) 会静默返回空；
  #    而 set -e 对【命令替换赋值】不生效（`x=$(false)` 的退出码是 0），
  #    结果是一个空段名被原样 echo 进头文件，锁箱阶段才炸。
  #    2026-10-20 实测：只靠 set -e 时 exit=2 但报的是 sed 的错，
  #    排查者看不出"契约真相源缺失"这个根因。
  _LAYOUT_H="$SCRIPT_DIR/../src/nc_guard_layout.h"
  if [ ! -f "$_LAYOUT_H" ]; then
    echo "❌ 找不到 nc_guard_layout.h（so 加密契约的唯一真相源）: $_LAYOUT_H" >&2
    echo "   它应在 scripts/sigcheck/src/ 下；缺失 = 无法对拍 C 侧与 Python 侧" >&2
    echo "   的段名/尺寸/偏移契约，拒绝继续（否则会产出运行期 SIGILL 的包）。" >&2
    exit 1
  fi
  NC_CONST_SEC=$(sed -n 's/^#define NC_SEC_CONST[[:space:]]*"\([^"]*\)".*/\1/p' \
      "$_LAYOUT_H" || true)
  if [ -z "$NC_CONST_SEC" ]; then
    echo "❌ 无法从 nc_guard_layout.h 抽取 NC_SEC_CONST" >&2
    echo "   文件存在但没有 '#define NC_SEC_CONST \".xxx\"' 这行 —— 头文件被改坏了？" >&2
    exit 1
  fi
  echo "#  define SIG_HASH_SECTION __attribute__((section(\"${NC_CONST_SEC}\"), retain, used))"
  echo "#else"
  echo "#  define SIG_HASH_SECTION"
  echo "#endif"
  echo ""
  echo "#define SIG_HASH_LEN 32"
  echo "#define SIG_SALT_LEN 16"
  echo "SIG_HASH_SECTION"
  echo "static const unsigned char SIG_SALT[SIG_SALT_LEN] = {"
  for ((i = 0; i < 32; i += 16)); do
    row=""
    for ((j = 0; j < 16; j += 2)); do
      row+="0x${SALT_HEX:i+j:2}, "
    done
    echo "    ${row%, },"
  done
  echo "};"
  echo "SIG_HASH_SECTION"
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

# ── 第二份独立答案(2026-10 双线) ─────────────────────────────────────
# 仅当调用方给了第 3 个参数时生成。与第一份的关系:【同源指纹,不同派生】。
#   salt2  = os.urandom(16)                          独立随机(与 salt 无关联)
#   t2     = SHA256(b"G2" || fp)                     轮1: 加域分隔符,与 t1 不同
#   stored2[i] = t2[i] ^ salt2[(i*7) % 16]          轮2: 步进 7 的置换取盐
#              ^ ((i * 0x5B + 0x3D) & 0xFF)         不同的位置扩散系数
# 攻击者即使完全解开第一份的派生逻辑,也【推不出】第二份的公式与盐。
if [[ -n "$OUT2" ]]; then
  DERIVED2_JSON=$(python3 - "$HASH_HEX" <<'PYEOF'
import hashlib, os, sys, json
fp = bytes.fromhex(sys.argv[1])
salt = os.urandom(16)
t2 = hashlib.sha256(b"G2" + fp).digest()
stored = bytes(
    t2[i] ^ salt[(i * 7) % 16] ^ ((i * 0x5B + 0x3D) & 0xFF)
    for i in range(32)
)
print(json.dumps({"salt": salt.hex(), "stored": stored.hex()}))
PYEOF
)
  SALT2_HEX=$(printf '%s' "$DERIVED2_JSON" | grep -o '"salt": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{32\}')
  STORED2_HEX=$(printf '%s' "$DERIVED2_JSON" | grep -o '"stored": *"[0-9a-f]*"' | grep -o '[0-9a-f]\{64\}')
  if [[ ${#SALT2_HEX} -ne 32 || ${#STORED2_HEX} -ne 64 ]]; then
    echo "❌ 第二份派生失败(python 输出异常): $DERIVED2_JSON" >&2
    exit 1
  fi
  {
    echo "/* 由流水线自动生成:sig_guard2.c 专用(独立派生,与 sig_hash.h 不同源公式) */"
    echo "/* 攻防说明:两条线互不共享标准值 —— 改掉一条,另一条仍在判定 */"
    echo "#ifndef _SIG_GUARD2_H_"
    echo "#define _SIG_GUARD2_H_"
    echo "#define SG2_HASH_LEN 32"
    echo "#define SG2_SALT_LEN 16"
    echo "static const unsigned char SG2_SALT[SG2_SALT_LEN] = {"
    for ((i = 0; i < 32; i += 16)); do
      row=""
      for ((j = 0; j < 16; j += 2)); do
        row+="0x${SALT2_HEX:i+j:2}, "
      done
      echo "    ${row%, },"
    done
    echo "};"
    echo "static const unsigned char SG2_STORED[SG2_HASH_LEN] = {"
    for ((i = 0; i < 64; i += 16)); do
      row=""
      for ((j = 0; j < 16; j += 2)); do
        row+="0x${STORED2_HEX:i+j:2}, "
      done
      echo "    ${row%, },"
    done
    echo "};"
    echo "#endif"
  } > "$OUT2"
  echo "✅ sig_guard2.h 已生成(独立派生): salt2=$SALT2_HEX"
fi
