#!/usr/bin/env python3
"""resolve-config.py 验收测试（设计方案 §7 验收清单 + §10 追加项）。

纯 stdlib，无 pytest 依赖：直接以子进程跑 resolve-config.py，断言输出。
覆盖：
  T1 sigcheck 单独勾选            → args.txt == ["--sigcheck"]
  T2 dex2c 单独勾选 + 规则        → --dex2c + 规则文件路径（workspace 相对）
  T3 dex2c 联合 sigcheck 留空规则 → --dex2c 不带文件参数（§7 重点）
  T4 stringenc 勾选未填规则       → 解析器 fail（App 端同规则应拦截）
  T5 lightobf 勾选 + 规则         → --light-obf + 规则；mode 不产生参数（§3.1）
  T6 全家桶组合                   → 参数齐全、顺序固定
  T7 未知顶层 key                 → 报错退出（保险丝 a，§10.1 反向）
  T8 config 缺失其余模块 key      → 视为 disabled 不报错（§10.1 正向）
  T9 schema_version 缺失          → 报错（必填校验）
  T10 schema_version 偏高         → 报错提示更新流水线（保险丝 a0）
  T11 全部 disabled               → 报错（保险丝 e）
  T12 规则内容含空格/特殊字符      → 原样写入文件，argv 仅相对路径（§7）
  T13 未知模块内子 key            → 报错退出（保险丝 a 模块内）
  T14 cwd 无关性（§10.5）          → 任意 cwd 下运行结果一致
  T15 args.txt 结尾无多余空行（§10.2）
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))   # tests → actions → scripts → 仓库根
SCRIPT = os.path.join(HERE, "..", "resolve-config.py")
SCHEMA = os.path.join(ROOT, "configs", "v1", "config-schema.json")

passed = failed = 0


def run(config_obj, cwd=None):
    """在独立临时根中运行解析器，返回 (rc, args_lines, files, stderr)。"""
    tmp = tempfile.mkdtemp(prefix="rc-test-")
    os.makedirs(os.path.join(tmp, "configs", "v1"))
    shutil.copy(SCHEMA, os.path.join(tmp, "configs", "v1", "config-schema.json"))
    env = dict(os.environ)
    env["INPUT_PROTECT_CONFIG"] = json.dumps(config_obj, ensure_ascii=False)
    env["GITHUB_WORKSPACE"] = tmp
    p = subprocess.run(
        [sys.executable, SCRIPT], env=env, cwd=cwd or tmp,
        capture_output=True, text=True,
    )
    args_lines, files = [], {}
    rules_dir = os.path.join(tmp, "schema_rules")
    if os.path.isdir(rules_dir):
        for name in sorted(os.listdir(rules_dir)):
            with open(os.path.join(rules_dir, name), encoding="utf-8") as f:
                files[name] = f.read()
        if "args.txt" in files:
            args_lines = [l for l in files["args.txt"].splitlines() if l.strip()]
    shutil.rmtree(tmp, ignore_errors=True)
    return p.returncode, args_lines, files, p.stderr


def check(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ✅ {name}")
    else:
        failed += 1
        print(f"  ❌ {name}  {detail}")


def cfg(**kw):
    base = {"schema_version": 1, "sigcheck": False, "dex2c": {"enabled": False},
            "stringenc": {"enabled": False}, "lightobf": {"enabled": False},
            "antidiff": False, "envcheck": False}
    base.update(kw)
    return base


print("== resolve-config.py 验收测试 ==")

# T1
rc, args, files, err = run(cfg(sigcheck=True))
check("T1 sigcheck 单独勾选 → 仅 --sigcheck", rc == 0 and args == ["--sigcheck"], f"rc={rc} err={err}")

# T2
rc, args, files, err = run(cfg(dex2c={"enabled": True, "rules_file": "**/com.test.**"}))
check("T2 dex2c+规则 → --dex2c + workspace 相对规则路径",
      rc == 0 and args == ["--dex2c", "schema_rules/dex2c.txt"]
      and files.get("dex2c.txt", "").strip() == "**/com.test.**",
      f"rc={rc} args={args}")

# T3（§7 重点）
rc, args, files, err = run(cfg(sigcheck=True, dex2c={"enabled": True, "rules_file": ""}))
check("T3 dex2c+sigcheck 留空规则 → --dex2c 无文件参数",
      rc == 0 and args == ["--sigcheck", "--dex2c"], f"rc={rc} args={args} err={err}")

# T4
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": ""}))
check("T4 stringenc 留空规则 → fail-fast", rc != 0 and "规则为空" in err, f"rc={rc} err={err}")

# T5
rc, args, files, err = run(cfg(lightobf={"enabled": True, "mode": "d", "rules_file": "**/com.a.**"}))
check("T5 lightobf+规则 → --light-obf + 规则（mode 不产生参数）",
      rc == 0 and args == ["--light-obf", "schema_rules/lightobf.txt"], f"rc={rc} args={args}")

# T6
rc, args, files, err = run(cfg(sigcheck=True, envcheck=True, antidiff=True,
                               dex2c={"enabled": True, "rules_file": "**/com.test.**"},
                               stringenc={"enabled": True, "rules_file": "**/com.s.**"},
                               lightobf={"enabled": True, "rules_file": "**/com.l.**"}))
expect = ["--sigcheck", "--dex2c", "schema_rules/dex2c.txt",
          "--stringenc", "schema_rules/stringenc.txt",
          "--light-obf", "schema_rules/lightobf.txt", "--anti-diff", "--envcheck"]
check("T6 全家桶 → 参数齐全且顺序固定", rc == 0 and args == expect, f"rc={rc} args={args}")

# T7（§10.1 反向）
rc, args, files, err = run(cfg(unknown_mod=True))
check("T7 未知顶层 key → 报错退出（保险丝 a）", rc != 0 and "未定义" in err, f"rc={rc} err={err}")

# T8（§10.1 正向）
rc, args, files, err = run({"schema_version": 1, "sigcheck": True})
check("T8 config 缺失其余模块 key → 视为 disabled 不报错",
      rc == 0 and args == ["--sigcheck"], f"rc={rc} args={args} err={err}")

# T9
c = cfg(sigcheck=True)
del c["schema_version"]
rc, args, files, err = run(c)
check("T9 缺 schema_version → 报错", rc != 0 and "schema_version" in err, f"rc={rc} err={err}")

# T10（保险丝 a0）
rc, args, files, err = run(cfg(sigcheck=True, schema_version=2))
check("T10 schema_version 偏高 → 报错提示更新流水线", rc != 0 and "更新流水线" in err, f"rc={rc} err={err}")

# T11（保险丝 e）
rc, args, files, err = run(cfg())
check("T11 全部 disabled → 报错", rc != 0 and "没有" in err, f"rc={rc} err={err}")

# T12（§7：特殊字符规则）
tricky = "**/com.test.**  # 注释 行 !排除\nactivity*\n\n$HOME `id` ; rm -rf\n"
rc, args, files, err = run(cfg(stringenc={"enabled": True, "rules_file": tricky}))
check("T12 特殊字符规则 → 原样写入文件、argv 仅相对路径",
      rc == 0 and args == ["--stringenc", "schema_rules/stringenc.txt"]
      and files.get("stringenc.txt") == tricky,
      f"rc={rc} args={args}")

# T13
rc, args, files, err = run(cfg(dex2c={"enabled": True, "rules_file": "x", "rogue": 1}))
check("T13 模块内未知子 key → 报错退出", rc != 0 and "未定义" in err, f"rc={rc} err={err}")

# T14（§10.5：cwd 无关）
rc, args, files, err = run(cfg(sigcheck=True), cwd="/")
check("T14 任意 cwd 运行 → 结果一致（仓库根推算）", rc == 0 and args == ["--sigcheck"], f"rc={rc} err={err}")

# T15（§10.2）
rc, args, files, err = run(cfg(sigcheck=True, envcheck=True))
raw = files.get("args.txt", "")
check("T15 args.txt 一行一个、结尾无多余空行", rc == 0 and raw == "--sigcheck\n--envcheck\n", f"raw={raw!r}")

print(f"\n结果: {passed} 通过, {failed} 失败")
sys.exit(1 if failed else 0)
