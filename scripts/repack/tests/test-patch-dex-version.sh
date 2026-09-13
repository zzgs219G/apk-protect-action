#!/usr/bin/env bash
# test-patch-dex-version.sh — scripts/repack/patch-dex-version.py 的最小回归
#
# 钉死的缺陷(报错二十九):
#   dcc 分发位置从 <仓库根>/build/dcc 迁到 <仓库根>/tools/dcc 时,本脚本里硬编码的
#   dcc 路径未同步更新(该路径写作 os.path.join(root, "build", "dcc", "dcc"),
#   不含连续字面量 "build/dcc",迁移时的全仓 grep 搜不到 → 被漏改)。
#   后果:restore 模式的 `read_manifest_min_sdk` 把不存在的目录插进 sys.path
#   (Python 静默忽略)→ `import androguard` ModuleNotFoundError,流水线在
#   `repack_build` 的 dex 版本恢复步骤崩溃(见 docs/build.log 尾部)。
#
# 覆盖:
#   A. dcc_dir() 指向真实存在的 dcc,且其中 androguard 可被 import(本次根因,修复前必红)
#   B. save 端到端(不依赖 androguard):合成 zip → dex-versions.json 内容正确
#
# 用法: bash scripts/repack/tests/test-patch-dex-version.sh
# 退出码: 0 = 全绿;非 0 = 有失败项。
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
SCRIPT="$ROOT/scripts/repack/patch-dex-version.py"

pass=0; fail=0
ok()  { echo "  ✅ $1"; pass=$((pass + 1)); }
bad() { echo "  ❌ $1"; fail=$((fail + 1)); }

[ -f "$SCRIPT" ] || { echo "❌ 找不到 $SCRIPT"; exit 1; }

echo "=== A. dcc 定位 + androguard 可导入 ==="
# 独立命名空间加载脚本(只 import,不跑 main),取其 dcc_dir() 并验证 androguard 可达。
# 修复前 dcc_dir() = <root>/build/dcc/dcc(不存在)→ 下面的 import 抛 ModuleNotFoundError。
python3 - "$SCRIPT" <<'PY'
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("pdv", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

d = mod.dcc_dir()
apk_py = os.path.join(d, "androguard", "core", "bytecodes", "apk.py")
assert os.path.isdir(d), f"dcc_dir() 指向不存在的目录: {d}"
assert os.path.isfile(apk_py), f"dcc_dir() 里缺 androguard: {apk_py}"

sys.path.insert(0, d)
from androguard.core.bytecodes.apk import APK  # noqa: F401  (能 import 即证明路径正确)

print(f"  ℹ️ dcc_dir() = {d}")
PY
if [ $? -eq 0 ]; then ok "dcc_dir() 指向真实 dcc,且 androguard 可导入"; else bad "dcc_dir()/androguard 校验失败(见上方回溯)"; fi

echo "=== B. save 端到端(合成 zip,不依赖 androguard) ==="
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# 合成一个含两个 dex(038/035)+ 一个非 dex 条目的最小 APK
python3 - "$tmp" <<'PY'
import os
import sys
import zipfile

tmp = sys.argv[1]


def dex(ver: bytes) -> bytes:
    """构造 dex 头:魔数 'dex\n' + 版本 3 字节 + 0x00,再补足长度。"""
    return b"dex\n" + ver + b"\x00" + b"\x00" * 128


with zipfile.ZipFile(os.path.join(tmp, "in.apk"), "w") as z:
    z.writestr("classes.dex", dex(b"038"))       # 原包 038
    z.writestr("classes2.dex", dex(b"035"))      # 原包 035
    z.writestr("resources.arsc", b"not-a-dex")   # 非 dex 条目不得进表
PY

out="$tmp/decompiled"
mkdir -p "$out"
python3 "$SCRIPT" save "$tmp/in.apk" "$out" >/dev/null 2>&1
if [ $? -eq 0 ] && [ -f "$out/dex-versions.json" ]; then
  got="$(python3 -c "import json;print(json.dumps(json.load(open('$out/dex-versions.json')),sort_keys=True))")"
  if [ "$got" = '{"classes.dex": "038", "classes2.dex": "035"}' ]; then
    ok "save 记录正确: $got"
  else
    bad "save 记录不符(期望 {\"classes.dex\": \"038\", \"classes2.dex\": \"035\"}): $got"
  fi
else
  bad "save 未产出 dex-versions.json"
fi

echo
echo "通过 $pass 项,失败 $fail 项"
[ "$fail" -eq 0 ]
