#!/usr/bin/env python3
"""resolve-config.py — schema 驱动的 protect_config 通用解释器（方案 B + 保险丝）。

设计依据：《联合任务-设计方案.md》（仓库根目录，2025-09-18 用户逐条拍板）
  - §3.1/§3.2  enabled 语义与 config 生成规则的逆过程
  - §5.2       保险丝 a0/a/b/c/d/e/f 与输出格式（schema_rules/，一行一个参数）
  - §10.1      schema 有、config 无 → 视为 disabled 继续；反向（未知 key）→ fail-fast
  - §10.2      args.txt 结尾无空行；workflow 侧读取时仍须过滤空行
  - §10.5      schema 路径写死，经 GITHUB_WORKSPACE 或 __file__ 推算仓库根，不依赖 cwd
  - AGENTS.md  冻结模块零接触；本脚本只读 schema、写 schema_rules/，不碰任何冻结文件

用法（workflow 同 step 内）:
  env:
    INPUT_PROTECT_CONFIG: ${{ inputs.protect_config }}
  run: |
    python3 scripts/actions/resolve-config.py
    mapfile -t ARGS < <(grep -v '^$' schema_rules/args.txt)
    ./scripts/pipelines/protect.sh app.apk protected_unsigned.apk "${ARGS[@]}"
"""
import json
import os
import re
import sys

# ── §10.5 仓库根写死推算（不依赖 cwd）────────────────────────────────
ROOT = os.environ.get("GITHUB_WORKSPACE") or \
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SCHEMA_PATH = os.path.join(ROOT, "configs", "v1", "config-schema.json")
OUT_DIR = os.path.join(ROOT, "schema_rules")

# 保险丝 b：arg 白名单。注意 --dex2c 含数字 2，字符类必须含 0-9；
# 设计文档原文 ^--[a-z-]+$ 匹配不了它（已实测），此处收紧为 [a-z0-9-]+ 且
# 额外禁止连续连字符结尾歧义（等价覆盖文档意图：全小写、连字符分词、无其他字符）。
ARG_RE = re.compile(r"--[a-z0-9]+(-[a-z0-9]+)*")

failures = []


def fail(msg: str):
    """人话报错，fail-fast（保险丝 d/e 与类型错误统一出口）。"""
    failures.append(msg)


def die(msg: str):
    print(f"❌ protect_config 解析失败：{msg}", file=sys.stderr)
    sys.exit(1)


# ── 读 schema ────────────────────────────────────────────────────────
try:
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
except (OSError, json.JSONDecodeError) as e:
    die(f"schema 文件读取失败 {SCHEMA_PATH}: {e}")

SCHEMA_VERSION = schema.get("schema_version")
modules = schema.get("modules")
if not isinstance(SCHEMA_VERSION, int) or SCHEMA_VERSION < 1:
    die("schema.schema_version 缺失或非法")
if not isinstance(modules, list) or not modules:
    die("schema.modules 缺失或为空")

modules_by_key = {}
for m in modules:
    key = m.get("key")
    if not key or key in modules_by_key:
        die(f"schema 模块 key 缺失或重复: {key!r}")
    modules_by_key[key] = m

# ── 读 config ────────────────────────────────────────────────────────
raw = os.environ.get("INPUT_PROTECT_CONFIG", "").strip()
if not raw:
    die("INPUT_PROTECT_CONFIG 为空（App 未传 protect_config）")
try:
    config = json.loads(raw)
except json.JSONDecodeError as e:
    die(f"protect_config 不是合法 JSON: {e}")
if not isinstance(config, dict):
    die("protect_config 顶层必须是 JSON 对象")

# ── 保险丝 a0：版本漂移前置检查（§5.2，App 快照过期靠此拦截）─────────
cfg_version = config.get("schema_version")
if cfg_version is None:
    die("protect_config 缺少 schema_version（必填，App 生成时携带）")
if not isinstance(cfg_version, int):
    die(f"protect_config.schema_version 必须是整数，实际 {cfg_version!r}")
if cfg_version > SCHEMA_VERSION:
    die(f"App 使用的 schema 版本较新（v{cfg_version} > 流水线 v{SCHEMA_VERSION}），请更新流水线仓库")

# ── 保险丝 a：未知 key 拒绝（白名单）────────────────────────────────
# 注（设计方案审查 #4）：schema 与解析器同仓库同 commit，此检查防的是
# App assets 快照过期，不是仓库内部漂移。
known_top = {"schema_version"} | set(modules_by_key)
unknown_top = sorted(set(config) - known_top)
if unknown_top:
    die(f"protect_config 出现 schema 未定义的顶层 key: {unknown_top}（拒绝执行）")


def read_enabled(module_key: str, cfg_node) -> bool:
    """enabled 语义（§3.1，审查 #2）：leaf=顶层 bool；parent=.enabled。
    §10.1：模块 key 在 config 中缺失 → 视为 disabled（不报错）。"""
    m = modules_by_key[module_key]
    if cfg_node is _MISSING:
        return False
    if m.get("type") == "leaf":
        if not isinstance(cfg_node, bool):
            die(f"模块 {module_key} 是 leaf，值必须是布尔，实际 {cfg_node!r}")
        return cfg_node
    # parent
    if not isinstance(cfg_node, dict):
        die(f"模块 {module_key} 是 parent，值必须是对象 {{enabled: ...}}，实际 {cfg_node!r}")
    enabled = cfg_node.get("enabled", False)
    if not isinstance(enabled, bool):
        die(f"模块 {module_key}.enabled 必须是布尔，实际 {enabled!r}")
    return enabled


_MISSING = object()

argv_out = []          # 结构化拼 argv，全程不进 shell（保险丝 f）
rule_files = []        # (模块key, 内容)
enabled_any = False

for m in modules:
    key = m["key"]
    cfg_node = config.get(key, _MISSING)
    enabled = read_enabled(key, cfg_node)
    if not enabled:
        continue
    enabled_any = True

    # 保险丝 b：arg 白名单（leaf/parent 都必须带合法 arg）
    arg = m.get("arg", "")
    if not ARG_RE.fullmatch(arg):
        die(f"schema 模块 {key} 的 arg 非法: {arg!r}（须匹配 --xxx[-yyy]）")
    argv_out.append(arg)

    if m.get("type") != "parent":
        continue

    # 保险丝 a（模块内）：未知子 key 拒绝
    child_keys = {c.get("key") for c in m.get("children", [])}
    unknown_in_mod = sorted(set(cfg_node) - {"enabled"} - child_keys)
    if unknown_in_mod:
        die(f"模块 {key} 出现 schema 未定义的子 key: {unknown_in_mod}（拒绝执行）")

    for c in m.get("children", []):
        ckey = c.get("key")
        value_kind = c.get("value_kind")
        if value_kind is None:
            # §3.1/审查 #5：无 value_kind 的子字段（如 lightobf.mode）不进 config、
            # 不产生任何参数；若网页手填出现了也静默忽略（schema 有定义，不算未知 key）
            continue

        value = cfg_node.get(ckey, "")
        # 保险丝 c：未知 value_kind → 报错退出
        if value_kind != "rules_file":
            die(f"模块 {key}.{ckey} 的 value_kind 未知: {value_kind!r}（两端需同步支持）")
        if not isinstance(value, str):
            die(f"模块 {key}.{ckey} 的值必须是字符串，实际 {value!r}")

        # 保险丝 d：required 校验（与 App 同一套 schema 规则，D4）
        rule = c.get("required")
        blank = value.strip() == ""
        if rule is not None and blank:
            when = rule.get("when")
            if when != "always":
                die(f"模块 {key}.{ckey} 的 required.when 未知: {when!r}（v1 只支持 always，§10.3）")
            unless = rule.get("unless")
            exempt = False
            if unless is not None:
                ukey = unless.get("key")
                uis = unless.get("is")
                if ukey not in modules_by_key:
                    die(f"模块 {key}.{ckey} 的 unless 引用了不存在的模块: {ukey!r}")
                if not isinstance(uis, bool):
                    die(f"模块 {key}.{ckey} 的 unless.is 必须是布尔")
                # unless 引用按目标模块自身的类型走对应 enabled 路径（§3.1 审查 #2；
                # §10.1：目标模块在 config 中缺失 → disabled → 不豁免）
                exempt = read_enabled(ukey, config.get(ukey, _MISSING)) == uis
            if not exempt:
                hint = c.get("hint", "")
                fail(f"「{m.get('label', key)} · {c.get('label', ckey)}」已启用但规则为空"
                     + (f"（{hint}）" if hint else ""))

        # rules_file 执行语义：非空 → 写临时文件、路径追加在 arg 后；
        # 空但通过 unless 豁免 → 只吐 arg 不追加文件（dex2c 联合 sigcheck 自动抽主类）
        if not blank:
            rule_files.append((key, value))
            # §5.2：路径以 workspace 相对形式追加（schema_rules/<key>.txt），
            # workflow 在仓库根执行，protect.sh 与后续步骤均按相对路径可访问
            argv_out.append(f"schema_rules/{key}.txt")

# 保险丝 d 出口：required 校验失败集中报错（fail-fast，人话）
if failures:
    die("；".join(failures))

# 保险丝 e：至少一个模块 enabled
if not enabled_any:
    die("没有任何加固模块被启用（protect_config 中所有模块均为 disabled）")

# ── 输出（§5.2 输出格式写死，§10.2 结尾无空行）──────────────────────
os.makedirs(OUT_DIR, exist_ok=True)
for key, content in rule_files:
    # 用户填的是文件内容；路径由本脚本生成（workspace 相对，天然无空格），
    # 原样写入，不做任何 shell 转义（内容永不进 argv，防注入面）
    with open(os.path.join(OUT_DIR, f"{key}.txt"), "w", encoding="utf-8") as f:
        f.write(content)
        if not content.endswith("\n"):
            f.write("\n")

args_path = os.path.join(OUT_DIR, "args.txt")
with open(args_path, "w", encoding="utf-8") as f:
    for a in argv_out:
        f.write(a + "\n")   # 一行一个参数；最后一行以 \n 结束，无多余空行

print(f"✅ resolve-config: {len(argv_out)} 个参数, {len(rule_files)} 个规则文件 → {args_path}")
for a in argv_out:
    print(f"   {a}")
