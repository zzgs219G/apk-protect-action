#!/bin/bash
# protect-modules.yml 结构自检（无 yamllint 环境下的轻量校验）：
# 1) python3 yaml 模块可解析（PyYAML 可用时）
# 2) grep 断言关键结构：inputs 只剩 apk_url + protect_config；mapfile 过滤空行；无旧 inputs 残留
set -u
# 仓库根 = tests → actions → scripts → 根
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)" || exit 1
cd "$ROOT" || exit 1
YML=.github/workflows/protect-modules.yml
fail=0

if python3 -c "import yaml" 2>/dev/null; then
  python3 - "$YML" <<'EOF' || fail=1
import sys, yaml
d = yaml.safe_load(open(sys.argv[1], encoding="utf-8"))
# PyYAML 把裸 on 解析成布尔 True 键（YAML 1.1），两种键都接受
trigger = d.get("on", d.get(True, {}))
inputs = trigger["workflow_dispatch"]["inputs"]
assert set(inputs) == {"apk_url", "protect_config"}, f"inputs 应只剩 apk_url+protect_config: {list(inputs)}"
assert inputs["protect_config"]["required"] is True
steps = d["jobs"]["protect"]["steps"]
names = [s.get("name", "") for s in steps]
assert any("resolve-config.py" in (s.get("run") or "") for s in steps), "缺解析 step"
assert not any("勾选前置校验" in n for n in names), "旧前置校验 step 应删除"
assert not any("生成 Dex2C 规则" in n for n in names), "旧规则生成 step 应删除"
print("yaml OK:", list(inputs))
EOF
else
  echo "(PyYAML 不可用，跳过 yaml 解析，走 grep 断言)"
fi

grep -q 'INPUT_PROTECT_CONFIG: ${{ inputs.protect_config }}' "$YML" || { echo "❌ 缺 env 中转"; fail=1; }
grep -q 'mapfile -t ARGS < <(grep -v .\^$.\? schema_rules/args.txt)' "$YML" 2>/dev/null || \
  grep -F 'grep -v' "$YML" | grep -q 'args.txt' || { echo "❌ mapfile 未过滤空行（§10.2）"; fail=1; }
grep -F '"${ARGS[@]}"' "$YML" >/dev/null || { echo "❌ ARGS 未用引用展开"; fail=1; }
for legacy in inputs.sigcheck inputs.dex2c_rules inputs.string_rules inputs.lightobf inputs.packer inputs.antidiff inputs.envcheck; do
  grep -q "$legacy" "$YML" && { echo "❌ 旧 input 残留: $legacy"; fail=1; }
done
[[ $fail -eq 0 ]] && echo "protect-modules.yml 自检通过"
exit $fail
