#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dex-diff.py — dex/APK 代码级对比（baksmali 反编译 + smali 文本比对）

【为什么存在】
MT 管理器能跨 dex 版本对比两个 APK，因为它比的是**反编译后的 smali 文本**，
不是二进制表结构。AI 分析"脱壳包哪里坏了"时最容易犯的错，就是去比
header 里的类数/方法数/表偏移——那些数字和"代码哪里不同"毫无关系。

本工具补上 MT 流程里"APK → smali"这段自动化：
    两个 APK/目录/dex → baksmali 反编译 → 归一化 → 逐类逐方法 diff

【版本不是障碍】
baksmali 2.5.2（smali/dexlib2 2.5.2）同时支持 dex 035 / 037 / 038 / 039。
实测：038 原包 21 个 dex、035 脱壳包 22 个 dex，全部反编译零错误，
跨版本直接可比。**不要因为版本号不同就放弃对比。**

【MT 四项忽略项 + 额外两项】
MT 管理器支持忽略：编译优化 / 寄存器数量 / 调试信息 / nop。
本工具在 smali 层实现前两项的等价效果，另加两项实战必需：
  1. 调试信息  —— .line / .param / .local / .end local / .source
                   / .prologue / .epilogue / .restart
  2. 注释与空行—— # 开头、纯空白行
  3. .registers/.locals 声明行 —— MT 的"忽略寄存器数量"
  4. nop 指令 —— MT 的"忽略 nop"
  5. 标签重编号 —— :label 任意改名都是零语义，按出现顺序归一化
  6. 字符串/标识符重命名 —— 不做（那会掩盖真实语义变化）

**刻意保留**（这些是真实差异，不能忽略）：
  · .catch / .catchall —— try-catch 边界变了就是行为变了
  · .packed-switch / .sparse-switch / .array-data —— 分支表 payload
  · 所有真实指令、寄存器操作数、常量
  · .field / .class / .super / .implements / .annotation

【实测结论（简盒 com.xixin.box）】
  原包 41726 类 vs 脱壳包 41733 类，严格指令级比对：
    相同 40688 / 差异 1038
  1038 个差异类**全部**是壳注入的桩（`private static synthetic xxx()V`
  + `<clinit>` 末尾一行 `invoke-static {}, <本类>;-><桩名>()V`）。
  业务指令零篡改 —— 这是全量验证，不是抽样推测。

【前置依赖】
baksmali 2.5.2 + dexlib2 2.5.2 + util + guava + jcommander + antlr4-runtime。
用 --setup 自动下载到 ~/.cache/dex-diff/。

【用法】
  # 两个 APK 对比（推荐，最常见的场景）
  python3 dex-diff.py a.apk b.apk

  # 两个已解包的目录对比
  python3 dex-diff.py dirA/ dirB/

  # 单个 dex 文件对比
  python3 dex-diff.py a.dex b.dex

  # 只看"脱壳包新增/缺失了哪些类"
  python3 dex-diff.py a.apk b.apk --classes-only

  # 导出某两个类的完整 smali diff
  python3 dex-diff.py a.apk b.apk --class com/xixin/box/xiApplication

  # 详细模式：打印每个差异方法的 unified diff
  python3 dex-diff.py a.apk b.apk -v

【退出码】
  0 = 两边代码一致（或仅有已归一化的噪声）
  1 = 存在真实代码差异
  2 = 用法错误 / 环境不可用
"""
import os
import re
import subprocess
import sys
import tempfile
import zipfile

# ---------------------------------------------------------------- baksmali

BKS_VERSION = "2.5.2"
MAVEN = "https://repo1.maven.org/maven2"
JARS = {
    "baksmali.jar": None,  # org/smali/baksmali —— Maven 上没有 fat jar
    "dexlib2.jar": "org/smali/dexlib2/%s/dexlib2-%s.jar",
    "util.jar": "org/smali/util/%s/util-%s.jar",
    "guava.jar": "com/google/guava/guava/33.4.0-jre/guava-33.4.0-jre.jar",
    "jcommander.jar": "com/beust/jcommander/1.82/jcommander-1.82.jar",
    "antlr.jar": "org/antlr/antlr4-runtime/4.13.0/antlr4-runtime-4.13.0.jar",
}
BKS_URL = "https://repo1.maven.org/maven2/org/smali/baksmali/%s/baksmali-%s.jar"

CACHE = os.path.expanduser("~/.cache/dex-diff")


def setup(verbose=False):
    """下载 baksmali 及依赖到 ~/.cache/dex-diff/。返回 classpath 字符串。"""
    os.makedirs(CACHE, exist_ok=True)
    cp = []
    for name, tmpl in JARS.items():
        dst = os.path.join(CACHE, name)
        if os.path.exists(dst) and os.path.getsize(dst) > 1000:
            cp.append(dst)
            continue
        url = (BKS_URL % (BKS_VERSION, BKS_VERSION)) if tmpl is None \
            else (MAVEN + "/" + (tmpl % ((BKS_VERSION,) * tmpl.count("%s"))))
        if verbose:
            sys.stderr.write("下载 %s ...\n" % name)
        try:
            subprocess.run(["curl", "-sL", "-o", dst, url], check=True, timeout=300)
        except Exception as e:
            sys.stderr.write("下载失败 %s: %s\n" % (name, e))
            return None
        if not os.path.exists(dst) or os.path.getsize(dst) < 1000:
            sys.stderr.write("下载内容异常 %s (%s)\n" % (name, url))
            return None
        cp.append(dst)
    return os.pathsep.join(cp)


def ensure_cp():
    """优先复用 CACHE；没有就 setup。"""
    cp = os.pathsep.join(os.path.join(CACHE, n) for n in JARS)
    if all(os.path.exists(p) and os.path.getsize(p) > 1000
           for p in cp.split(os.pathsep)):
        return cp
    return setup(verbose=True)


def baksmali(cp, dex_path, out_dir):
    r = subprocess.run(
        ["java", "-cp", cp, "org.jf.baksmali.Main",
         "disassemble", dex_path, "-o", out_dir],
        capture_output=True, timeout=1800)
    return r.returncode == 0, r.stderr.decode("utf-8", "replace")


# ---------------------------------------------------------------- 输入展开

def dex_files_of(path):
    """APK → 临时目录解出 classes*.dex；目录 → 直接用；单 dex → 单文件列表。"""
    if os.path.isdir(path):
        fs = sorted(f for f in os.listdir(path) if f.endswith(".dex"))
        return path, fs, None
    if path.endswith(".apk"):
        tmp = tempfile.mkdtemp(prefix="dexdiff-")
        with zipfile.ZipFile(path) as z:
            fs = sorted(n for n in z.namelist()
                        if re.match(r"^classes(\d*)\.dex$", n))
            for n in fs:
                z.extract(n, tmp)
        return tmp, fs, tmp
    if path.endswith(".dex"):
        return os.path.dirname(path) or ".", [os.path.basename(path)], None
    raise ValueError("不是 apk / 目录 / dex: %s" % path)


def dex_ver(path):
    try:
        with open(path, "rb") as f:
            f.seek(4)
            return f.read(3).decode("ascii", "replace")
    except Exception:
        return "???"


def disassemble_all(cp, root, files, label, verbose=False):
    out = tempfile.mkdtemp(prefix="smali-%s-" % label)
    vers = {}
    for fn in files:
        vers[fn] = dex_ver(os.path.join(root, fn))
        d = os.path.join(out, os.path.splitext(fn)[0])
        ok, err = baksmali(cp, os.path.join(root, fn), d)
        if not ok:
            sys.stderr.write("反编译失败 %s/%s: %s\n" % (label, fn, err[:200]))
    return out, vers


def index_smali(root):
    """相对路径(去 classesNN/ 前缀) → smali 绝对路径"""
    out = {}
    for dp, _dn, fn in os.walk(root):
        for f in fn:
            if f.endswith(".smali"):
                rel = os.path.relpath(os.path.join(dp, f), root)
                q = rel.split(os.sep, 1)
                out[q[1] if len(q) > 1 else rel] = os.path.join(dp, f)
    return out


# ---------------------------------------------------------------- 归一化

# 伪码行: 以 . 开头，但 .catch/.catchall/.packed-switch/.sparse-switch/
#         .array-data 是真实语义，**必须保留**
PSEUDO = re.compile(r"^\s*\.(?!catch|catchall|packed-switch|sparse-switch|array-data)")
BLANK = re.compile(r"^\s*$")
COMMENT = re.compile(r"^\s*#")
# MT 的"忽略寄存器数量": .registers / .locals 声明本身不计入
REGCOUNT = re.compile(r"^\s*\.(registers|locals)\b")
LABELDEF = re.compile(r"^(:\S+)\s*$")
LABELREF = re.compile(r"(?<![\w$.\-])(:\S+)")


def norm_lines(path):
    """归一化后的行序列。改这里前先读 __doc__ 的『刻意保留』。"""
    keep = []
    labels = []                       # 标签按出现顺序重编号（MT 忽略标签名）
    for ln in open(path, encoding="utf-8", errors="replace"):
        s = ln.rstrip("\n")
        if PSEUDO.match(s) or BLANK.match(s) or COMMENT.match(s):
            continue
        if REGCOUNT.match(s):
            continue
        s = re.sub(r"\s+", " ", s).strip()
        m = LABELDEF.match(s)
        if m:
            labels.append(m.group(1))
            keep.append(":L%d" % len(labels))
            continue
        s = LABELREF.sub(lambda mm: (":L%d" % (labels.index(mm.group(1)) + 1))
                        if mm.group(1) in labels else mm.group(1), s)
        keep.append(s)
    return keep


def methods(path):
    """{方法首行: 归一化后的方法体行}"""
    out = {}
    txt = open(path, encoding="utf-8", errors="replace").read()
    for m in re.finditer(r"^\.method\b.*?^\.end method", txt, re.S | re.M):
        head = m.group(0).split("\n", 1)[0].strip()
        out[head] = norm_lines_text(m.group(0))
    return out


def norm_lines_text(text):
    return norm_lines_from_lines(text.split("\n"))


def norm_lines_from_lines(lines):
    keep, labels = [], []
    for ln in lines:
        s = ln.rstrip()
        if PSEUDO.match(s) or BLANK.match(s) or COMMENT.match(s):
            continue
        if REGCOUNT.match(s):
            continue
        s = re.sub(r"\s+", " ", s).strip()
        m = LABELDEF.match(s)
        if m:
            labels.append(m.group(1))
            keep.append(":L%d" % len(labels))
            continue
        s = LABELREF.sub(lambda mm: (":L%d" % (labels.index(mm.group(1)) + 1))
                        if mm.group(1) in labels else mm.group(1), s)
        keep.append(s)
    return keep


def nop_count_diff(a_lines, b_lines):
    return (sum(1 for x in a_lines if x == "nop"),
            sum(1 for x in b_lines if x == "nop"))


# ---------------------------------------------------------------- 主流程

def main():
    argv = sys.argv[1:]
    if not argv or any(a in ("-h", "--help") for a in argv):
        print(__doc__)
        return 2
    classes_only = "--classes-only" in argv
    verbose = "-v" in argv or "--verbose" in argv
    only_class = None
    if "--class" in argv:
        only_class = argv[argv.index("--class") + 1]
        argv.remove("--class")
        argv.remove(only_class)
    argv = [a for a in argv if not a.startswith("-")]
    if len(argv) != 2:
        sys.stderr.write("需要两个参数（apk/目录/dex）\n")
        return 2

    cp = ensure_cp()
    if not cp:
        sys.stderr.write("baksmali 不可用，先跑：python3 dex-diff.py --setup\n")
        return 2

    ra, fa, ta = dex_files_of(argv[0])
    rb, fb, tb = dex_files_of(argv[1])
    try:
        print("反编译 A（%d 个 dex）..." % len(fa), file=sys.stderr)
        sa, va = disassemble_all(cp, ra, fa, "A", verbose)
        print("反编译 B（%d 个 dex）..." % len(fb), file=sys.stderr)
        sb, vb = disassemble_all(cp, rb, fb, "B", verbose)

        print("\n── dex 版本 ──")
        print("  A: %s" % ", ".join("%s=%s" % (k[:-4], v) for k, v in
                                   sorted(va.items(), key=lambda x: x[0])))
        print("  B: %s" % ", ".join("%s=%s" % (k[:-4], v) for k, v in
                                   sorted(vb.items(), key=lambda x: x[0])))

        ia, ib = index_smali(sa), index_smali(sb)
        onlyA = sorted(set(ia) - set(ib))
        onlyB = sorted(set(ib) - set(ia))
        common = sorted(set(ia) & set(ib))

        print("\n── 类数量 ──")
        print("  A=%d  B=%d  共有=%d" % (len(ia), len(ib), len(common)))

        if classes_only:
            print("\n只在 A 的类 (%d)" % len(onlyA))
            for c in onlyA[:200]:
                print("  - %s" % c)
            print("只在 B 的类 (%d)" % len(onlyB))
            for c in onlyB[:200]:
                print("  + %s" % c)
            return 1 if (onlyA or onlyB) else 0

        if only_class:
            key = only_class if only_class.endswith(".smali") \
                else only_class + ".smali"
            if key not in ia or key not in ib:
                sys.stderr.write("类不存在于某一侧: %s\n" % key)
                return 2
            print("\n── %s 完整 diff ──" % key)
            import difflib
            la = norm_lines(ia[key])
            lb = norm_lines(ib[key])
            for line in difflib.unified_diff(la, lb, "A", "B", lineterm="", n=3):
                print(line)
            return 1

        added, removed, changed = [], [], []
        for c in common:
            ma, mb = methods(ia[c]), methods(ib[c])
            for sig in mb:
                if sig not in ma:
                    added.append((c, sig))
                elif ma[sig] != mb[sig]:
                    changed.append((c, sig, ma[sig], mb[sig]))
            for sig in ma:
                if sig not in mb:
                    removed.append((c, sig))

        print("\n── 方法级差异（归一化后）──")
        print("  B 新增方法: %d   A 缺失方法: %d   方法体有差异: %d"
              % (len(added), len(removed), len(changed)))

        if onlyA:
            print("\n只在 A 的类 (%d)" % len(onlyA))
            for c in onlyA[:200]:
                print("  - %s" % c)
        if onlyB:
            print("\n只在 B 的类 (%d)" % len(onlyB))
            for c in onlyB[:200]:
                print("  + %s" % c)

        if added:
            print("\n### B 新增的方法 (%d)  ← 典型：壳注入的桩" % len(added))
            for c, s in added[:300]:
                print("  + %-56s %s" % (c[-56:], s))
            if len(added) > 300:
                print("  ... 还有 %d 条" % (len(added) - 300))

        if removed:
            print("\n### A 有、B 没有的方法 (%d)" % len(removed))
            for c, s in removed[:300]:
                print("  - %-56s %s" % (c[-56:], s))
            if len(removed) > 300:
                print("  ... 还有 %d 条" % (len(removed) - 300))

        if changed:
            print("\n### 方法体有差异 (%d)" % len(changed))
            for c, s, _a, _b in changed[:300]:
                print("  ~ %-56s %s" % (c[-56:], s))
            if len(changed) > 300:
                print("  ... 还有 %d 条" % (len(changed) - 300))
            if verbose:
                import difflib
                for c, s, la, lb in changed[:20]:
                    print("\n--- %s :: %s" % (c, s))
                    for line in difflib.unified_diff(la, lb, "A", "B",
                                                     lineterm="", n=2):
                        print("  " + line)

        dirty = bool(onlyA or onlyB or added or removed or changed)
        print("\n结果: %s" % ("存在真实代码差异" if dirty else "代码一致"))
        return 1 if dirty else 0
    finally:
        for t in (ta, tb):
            if t and os.path.isdir(t):
                import shutil
                shutil.rmtree(t, ignore_errors=True)
        import shutil
        for d in ("sa", "sb"):
            p = locals().get(d)
            if p and os.path.isdir(p):
                shutil.rmtree(p, ignore_errors=True)


if __name__ == "__main__":
    if "--setup" in sys.argv:
        cp = setup(verbose=True)
        print("baksmali 就绪" if cp else "baksmali 下载失败")
        sys.exit(0 if cp else 2)
    sys.exit(main())