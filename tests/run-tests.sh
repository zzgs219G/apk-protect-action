#!/usr/bin/env bash
# run-tests.sh — 统一测试入口(AGENTS.md §3 要求的必跑命令)
# 任何改动(不论大小)后必须全绿;CI(.github/workflows/module-guard.yml)强制执行。
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FAIL=0
run() {
  echo "──────── $1 ────────"
  shift
  if "$@"; then
    :
  else
    echo "❌ $1 失败" >&2
    FAIL=1
  fi
}

# 冻结模块回归测试(AGENTS.md §1 清单一一对应)
run "extract-cert-fp(指纹提取)"   python3 tests/test_cert_fp.py
run "sig_check(宿主编译+路径+签名)" bash tests/test_sig_check.sh
run "inject-loadlib(插桩冒烟)"    python3 tests/test_inject_loadlib.py

# mark-native.py 冒烟:语法可编译 + 关键入口存在
echo "──────── mark-native(冒烟) ────────"
if python3 -m py_compile scripts/repack/mark-native.py 2>/dev/null \
   && grep -q "def main" scripts/repack/mark-native.py; then
  echo "✅ mark-native.py 语法与入口正常"
else
  echo "❌ mark-native.py 冒烟失败" >&2
  FAIL=1
fi

echo
if [[ $FAIL -eq 0 ]]; then
  echo "✅✅ 全部测试通过 —— 改动可以提交"
else
  echo "❌❌ 存在失败 —— 冻结模块可能被改坏,禁止提交(见 AGENTS.md §1)" >&2
fi
exit $FAIL
