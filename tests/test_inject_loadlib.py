#!/usr/bin/env python3
"""test_inject_loadlib.py — inject-loadlib.py 冒烟测试(冻结模块护栏)

覆盖历史报错的高危回归点:
  1. 新建 <clinit>(报错十: mark-native 贪婪方法头——这里验证插入点精准)
  2. 已有 <clinit> 头插
  3. 幂等:已有 loadLibrary 跳过(报错十一: 多模块共存)
  4. SMALI_DIR_RE 多 dex 目录(报错七: '\\d' 双重转义 → smali_classes2 匹配)
  5. 类不存在 → 'missing'
"""
import importlib.util
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "inject_loadlib", ROOT / "scripts" / "inject" / "inject-loadlib.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

FAILS = []


def check(name, cond, detail=""):
    if cond:
        print(f"✅ {name}")
    else:
        FAILS.append(f"{name}: {detail}")
        print(f"❌ {name}: {detail}")


SAMPLE_CLASS = """.class public Lcom/xixin/box/MainActivity;
.super Landroid/app/Activity;

.method public constructor <init>()V
    .registers 1
    invoke-direct {p0}, Landroid/app/Activity;-><init>()V
    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .registers 2
    return-void
.end method
"""


def make_tree(tmp: Path, class_name: str = "Lcom/xixin/box/MainActivity;",
              content: str = SAMPLE_CLASS, smali_dir: str = "smali") -> Path:
    pkg = class_name.rstrip(";").replace("L", "", 1).replace("/", ".")
    # Lcom/xixin/box/MainActivity; -> com/xixin/box/MainActivity.smali
    rel = class_name.rstrip(";")[1:] + ".smali"
    d = tmp / smali_dir / Path(rel).parent
    d.mkdir(parents=True, exist_ok=True)
    f = d / Path(rel).name
    f.write_text(content)
    (tmp / "AndroidManifest.xml").write_text("<manifest/>")
    return f


def main() -> int:
    tmp = Path(tempfile.mkdtemp())

    # 1. 新建 <clinit>
    f = make_tree(tmp / "t1")
    r = mod.inject_loadlib_to_class("Lcom/xixin/box/MainActivity;", str(tmp / "t1"), "nc")
    c = f.read_text()
    check("新建<clinit>", r == "inserted" and "loadLibrary" in c
          and ".method static constructor <clinit>()V" in c, f"r={r}")
    check("插入点在 .class 行后(不吞方法体)",
          c.index("<clinit>") < c.index("onCreate")
          and "constructor <init>()V" in c, c)

    # 2. 已有 <clinit> 头插
    c2 = SAMPLE_CLASS.replace(
        ".class public Lcom/xixin/box/MainActivity;\n",
        ".class public Lcom/xixin/box/MainActivity;\n\n"
        ".method static constructor <clinit>()V\n"
        "    .registers 1\n    return-void\n.end method\n")
    f = make_tree(tmp / "t2", content=c2)
    r = mod.inject_loadlib_to_class("Lcom/xixin/box/MainActivity;", str(tmp / "t2"), "nc")
    c = f.read_text()
    check("已有<clinit>头插", r == "prepended"
          and c.index("loadLibrary") < c.index("return-void"), f"r={r}")

    # 3. 幂等
    f = make_tree(tmp / "t3", content=c2.replace(
        "return-void\n.end method", "return-void\n.end method", 1))
    mod.inject_loadlib_to_class("Lcom/xixin/box/MainActivity;", str(tmp / "t3"), "nc")
    r = mod.inject_loadlib_to_class("Lcom/xixin/box/MainActivity;", str(tmp / "t3"), "nc")
    check("幂等:二次调用返回 already", r == "already", f"r={r}")

    # 4. SMALI_DIR_RE 匹配 smali_classes2(报错七)
    f = make_tree(tmp / "t4", smali_dir="smali_classes2")
    r = mod.inject_loadlib_to_class("Lcom/xixin/box/MainActivity;", str(tmp / "t4"), "nc")
    check("smali_classes2 目录可命中(报错七)", r in ("inserted", "prepended"), f"r={r}")

    # 5. 类不存在
    r = mod.inject_loadlib_to_class("Lcom/no/Such;", str(tmp / "t4"), "nc")
    check("类不存在 → missing", r == "missing", f"r={r}")

    shutil.rmtree(tmp, ignore_errors=True)
    for x in FAILS:
        print(f"❌ {x}", file=sys.stderr)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
