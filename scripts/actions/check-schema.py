#!/usr/bin/env python3
"""configs/v1/config-schema.json 校验：
- JSON 可解析
- schema_version 与目录名一致（§10.6）
- 模块 key 唯一、arg 格式、required 结构
"""
import json
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as f:
    d = json.load(f)

assert d["schema_version"] == 1, f"schema_version 应为 1（目录 v1），实际 {d['schema_version']}"

keys = []
for m in d["modules"]:
    k = m["key"]
    keys.append(k)
    assert m["type"] in ("leaf", "parent"), f"{k}: type 非法"
    # 注意: --dex2c 含数字,字符类必须含 0-9;^--[a-z-]+$ 匹配不了它(勿"修正"回文档原样)
    assert re.fullmatch(r"--[a-z0-9-]+", m["arg"]), f"{k}: arg 非法 {m['arg']}"
    if m["type"] == "parent":
        for c in m["children"]:
            if "required" in c:
                r = c["required"]
                assert r["when"] == "always", f"{k}.{c['key']}: v1 只允许 when=always（§10.3）"
                if "unless" in r:
                    u = r["unless"]
                    assert set(u) == {"key", "is"}, f"{k}.{c['key']}: unless 必须是 key+is（D4）"
            if c["type"] == "select":
                vals = [o["value"] for o in c["options"]]
                assert c["default"] in vals, f"{k}.{c['key']}: default 不在 options"

assert len(keys) == len(set(keys)), "模块 key 重复"
assert keys == ["sigcheck", "dex2c", "stringenc", "lightobf", "antidiff", "envcheck"], keys
print("schema OK:", keys)
