#!/usr/bin/env python3
"""mark-native.py — 把 dcc 转译过的方法在解包后的 smali 里改成 native 壳,
并在所属类中插入 System.loadLibrary("nc"),保证 so 被加载。

背景:dcc.py 的 dcc() 只有在【不指定 --project-archive】时才顺手做
native 化(改 smali + 重打包);我们流水线用 --no-build + --project-archive
只取工程包,native 化必须自己做。dcc 原版 native_class_methods 只改壳,
不插 loadLibrary(README 要求手工在 Application.onCreate 加),而我们的
方案是纯成品 APK 后处理,没有源码可改,必须自动插桩。

插桩策略(防误插):
  - 每个含 native 方法且含静态初始化路径的类,在其 <clinit> 或首个被抽走
    方法所在类插入 static { System.loadLibrary("nc"); }
  - 若类已有 loadLibrary 调用则跳过(幂等)
  - 对插不进 static 块的类(无 <clinit>),在 native 方法所在类新建
    .method static constructor,apktool 会正确合并进 dex

输入:
  $1  dcc-project.zip(或解包目录)内 compiled_methods.txt 路径,
      每行格式: Lcom/a/B;method(args)ret   (dcc 的 full_name,无箭头)
  $2  apktool 解包目录(含 smali*/ 子目录)

用法: mark-native.py <compiled_methods.txt> <解包目录>
"""
import os
import re
import sys

SO_NAME = 'nc'


def parse_compiled_methods(path):
    """解析 compiled_methods.txt → {(类名, 方法名, 原型): True}
    行格式: Lcom/a/B;onCreate(Landroid/os/Bundle;)V"""
    result = set()
    with open(path) as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            m = re.match(r'^(L[^;]+;)([^(]+)(\(.*\)\S+)$', line)
            if not m:
                print(f'⚠️ 无法解析行: {line}', file=sys.stderr)
                continue
            result.add((m.group(1), m.group(2), m.group(3)))
    return result


SMALI_DIR_RE = __import__('re').compile(r'^smali(?:_classes\d+)?$')


def find_smali_files(decompiled_dir):
    for root, _dirs, files in os.walk(decompiled_dir):
        # 匹配 apktool 输出目录结构: <解包目录>/smali*/...,要求路径中
        # 存在名为 smali / smali_classes2 / smali_classes3 ... 的层级
        parts = root[len(decompiled_dir):].lstrip(os.sep).split(os.sep)
        if any(SMALI_DIR_RE.match(p) for p in parts if p):
            for f in files:
                if f.endswith('.smali'):
                    yield os.path.join(root, f)


def class_name_of(smali_path):
    with open(smali_path) as fp:
        for line in fp:
            if line.startswith('.class'):
                m = re.search(r'L[^;\s]+;', line)
                if m:
                    return m.group(0)
    return None


def process_smali(smali_path, targets):
    """targets: {(类名,方法名,原型)} 中属于本类的条目 → native 化 + 插桩"""
    with open(smali_path) as fp:
        content = fp.read()

    cls = class_name_of(smali_path)
    if not cls:
        return 0

    my_targets = {(c, n, p) for (c, n, p) in targets if c == cls}
    if not my_targets:
        return 0

    changed = False
    lines = content.split('\n')
    out = []
    i = 0
    n_methods = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        stripped = line.strip()
        if stripped.startswith('.method'):
            header = stripped
            # 解析方法头:.method public onCreate(Landroid/os/Bundle;)V
            m = re.match(r'\.method\s+.*?([^\s(]+)(\(.*\)\S+)\s*$', header)
            if m:
                name, proto = m.group(1), m.group(2)
                if (cls, name, proto) in my_targets:
                    # 把方法体整体替换为 native 声明(跳到 .end method)
                    j = i
                    while j < len(lines) and lines[j].strip() != '.end method':
                        j += 1
                    # native 方法不能有方法体:替换行为纯声明
                    access = header[len('.method'):].strip()
                    out[-1] = f'.method native {access}'.replace(
                        f' {name}{proto}', '') + f' {name}{proto}'
                    # 跳过原方法体
                    i = j  # 循环尾部 i+=1 后指向 .end method 行,一并丢弃
                    n_methods += 1
                    changed = True
                    i += 1
                    continue
        i += 1

    if n_methods == 0:
        return 0

    content = '\n'.join(out)

    # 插 System.loadLibrary:优先已有 <clinit>,否则新建 static 块
    if 'loadLibrary' not in content:
        load_stmt = (f'const-string v0, "{SO_NAME}"\n'
                     'invoke-static {v0}, Ljava/lang/System;'
                     '->loadLibrary(Ljava/lang/String;)V\n')
        if '.method static constructor <clinit>()V' in content:
            content = content.replace(
                '.method static constructor <clinit>()V\n',
                '.method static constructor <clinit>()V\n' + load_stmt, 1)
        else:
            # 在 .class 行后插入一个新的 <clinit>
            clinit = (f'.method static constructor <clinit>()V\n'
                      f'    .registers 1\n\n' + load_stmt +
                      '    return-void\n.end method\n\n')
            content = re.sub(r'(\.class[^\n]*\n)', r'\1\n' + clinit, content, count=1)
        changed = True

    if changed:
        with open(smali_path, 'w') as fp:
            fp.write(content)
    return n_methods


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        return 1
    methods_txt, decompiled_dir = sys.argv[1], sys.argv[2]
    if not os.path.exists(methods_txt):
        print(f'❌ compiled_methods.txt 不存在: {methods_txt}', file=sys.stderr)
        return 1
    if not os.path.isdir(decompiled_dir):
        print(f'❌ 解包目录不存在: {decompiled_dir}', file=sys.stderr)
        return 1

    targets = parse_compiled_methods(methods_txt)
    print(f'ℹ️ 待 native 化方法: {len(targets)} 个')

    total = 0
    touched = 0
    for smali in find_smali_files(decompiled_dir):
        n = process_smali(smali, targets)
        if n:
            total += n
            touched += 1
            print(f'  🔧 {os.path.relpath(smali, decompiled_dir)}: {n} 个方法 → native')

    missing = len(targets) - total
    print(f'✅ native 化完成: {total} 个方法 / {touched} 个文件')
    if missing > 0:
        print(f'⚠️ 有 {missing} 个方法未在 smali 中找到(可能是混淆内联或解析失败),请检查',
              file=sys.stderr)
        return 3
    return 0


if __name__ == '__main__':
    sys.exit(main())
