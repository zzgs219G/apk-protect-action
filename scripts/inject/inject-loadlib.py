#!/usr/bin/env python3
"""inject-loadlib.py — smali loadLibrary 插桩的【可复用基础模块】(模块化设计)。

背景(模块化路线):
  每个加固功能模块(dex2c / 单独签名校验 / 未来的卡片式勾选组合)都需要
  "让某个 so 被加载"这一步。本模块提供统一的插桩能力,各流水线按需调用,
  不再各自维护一份 smali 改写代码。

两种用法:
  1. 库方式(推荐,供其他脚本 import):
       from inject_loadlib import inject_loadlib_to_class, find_launcher_class
       inject_loadlib_to_class('Lcom/a/MainActivity;', decompiled_dir, so_name='nc')

  2. 命令行方式(调试/独立测试):
       inject-loadlib.py <解包目录> <smali类名 Lcom/a/B;> [--so-name nc]
       inject-loadlib.py <解包目录> --launcher [--so-name nc]   # 自动找 LAUNCHER activity

插桩策略(与 mark-native.py 一致,防误插):
  - 目标类已有 loadLibrary 调用 → 跳过(幂等,多模块共存时不重复插)
  - 已有 <clinit> → 在其开头插入
  - 没有 <clinit> → 在 .class 行后新建一个
"""
import os
import re
import sys

SMALI_DIR_RE = re.compile(r'^smali(?:_classes\d+)?$')


def find_smali_file_by_class(decompiled_dir, class_name):
    """按 smali 类名(Lcom/a/B;)定位 .smali 文件路径。
    覆盖 smali / smali_classes2 / smali_classes3 ... 多 dex 目录。
    找不到返回 None。"""
    rel = class_name[1:-1] + '.smali'          # 去掉 L 与 ; → com/demo/B.smali
    pkg_path, basename = os.path.split(rel)    # pkg_path='com/demo', basename='B.smali'
    sub_dirs = pkg_path.split(os.sep) if pkg_path else []
    for root, _dirs, files in os.walk(decompiled_dir):
        parts = [p for p in root[len(decompiled_dir):].lstrip(os.sep).split(os.sep) if p]
        if not any(SMALI_DIR_RE.match(p) for p in parts):
            continue
        # root 相对路径末尾须与类包路径(com/demo)对齐,且文件名匹配
        if sub_dirs:
            if parts[-len(sub_dirs):] == sub_dirs and basename in files:
                return os.path.join(root, basename)
        elif basename in files:
            return os.path.join(root, basename)
    return None


def inject_loadlib_to_class(class_name, decompiled_dir, so_name='nc'):
    """给单个类插 System.loadLibrary("<so_name>")。幂等。
    class_name 支持 Lcom/a/B; 或 Lcom/a/B(自动补分号)。
    返回: 'inserted'(新建<clinit>) / 'prepended'(已有<clinit>头插) /
          'already'(已有 loadLibrary,跳过) / 'missing'(类文件不存在)"""
    if not class_name.endswith(';'):
        class_name += ';'
    smali_path = find_smali_file_by_class(decompiled_dir, class_name)
    if not smali_path:
        return 'missing'

    with open(smali_path) as fp:
        content = fp.read()

    # 幂等:类里已有任何 loadLibrary 就不再插(多模块共存安全)
    if 'loadLibrary' in content:
        return 'already'

    load_stmt = (f'const-string v0, "{so_name}"\n'
                 'invoke-static {v0}, Ljava/lang/System;'
                 '->loadLibrary(Ljava/lang/String;)V\n')

    if '.method static constructor <clinit>()V' in content:
        content = content.replace(
            '.method static constructor <clinit>()V\n',
            '.method static constructor <clinit>()V\n' + load_stmt, 1)
        result = 'prepended'
    else:
        clinit = ('.method static constructor <clinit>()V\n'
                  '    .registers 1\n\n' + load_stmt +
                  '    return-void\n.end method\n\n')
        content = re.sub(r'(\.class[^\n]*\n)', r'\1\n' + clinit, content, count=1)
        result = 'inserted'

    with open(smali_path, 'w') as fp:
        fp.write(content)
    return result


def find_launcher_classes(decompiled_dir, package_name=None):
    """从 apktool 解包目录的 AndroidManifest.xml(文本)提取 LAUNCHER activity。
    纯文本正则,不依赖 androguard(与 dcc 模块解耦,模块化原则)。
    返回 smali 格式类名列表(Lcom/a/B;)。"""
    manifest = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest):
        return []
    with open(manifest, encoding='utf-8', errors='replace') as fp:
        content = fp.read()

    if package_name is None:
        m = re.search(r'package="([^"]+)"', content)
        package_name = m.group(1) if m else ''

    launchers = []
    for am in re.finditer(r'<activity\b[^>]*>', content, re.S):
        tag = am.group(0)
        nm = re.search(r'android:name="([^"]+)"', tag)
        if not nm:
            continue
        name = nm.group(1)
        # 相对类名补全
        if name.startswith('.'):
            full = package_name + name
        elif '.' not in name:
            full = package_name + '.' + name
        else:
            full = name
        # 该 activity 要有 MAIN+LAUNCHER intent-filter:
        # 看 <activity ...> 之后到 </activity> 之间的两个子标签
        tail_start = am.end()
        end = content.find('</activity>', tail_start)
        # 自闭合 <activity .../> 无 intent-filter,跳过
        seg_end = end if (end != -1 and (content.find('/>', am.end(), end) == -1
                                         or end == -1)) else am.end()
        if end == -1:
            seg = content[tail_start:tail_start + 4000]
        else:
            seg = content[tail_start:end]
        has_main = re.search(r'action\s+android:name="android\.intent\.action\.MAIN"', seg) or \
                   re.search(r'android:name="android\.intent\.action\.MAIN"', seg)
        has_launcher = re.search(r'android:name="android\.intent\.category\.LAUNCHER"', seg)
        if has_main and has_launcher:
            launchers.append('L' + full.replace('.', '/') + ';')
    return sorted(set(launchers))


def _parse_cli_args(argv):
    """解析 CLI 参数 → (decompiled_dir, target, so_name, launcher)。
    支持 --launcher / --so-name 出现在任意位置。"""
    decompiled_dir = None
    target = None
    so_name = 'nc'
    launcher = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--so-name' and i + 1 < len(argv):
            so_name = argv[i + 1]
            i += 2
        elif a == '--launcher':
            launcher = True
            i += 1
        elif decompiled_dir is None:
            decompiled_dir = a
            i += 1
        else:
            target = a
            i += 1
    return decompiled_dir, target, so_name, launcher


def _cli():
    """命令行入口(调试/独立测试用)。"""
    decompiled_dir, target, so_name, launcher = _parse_cli_args(sys.argv[1:])
    if not decompiled_dir or (not target and not launcher):
        print(__doc__, file=sys.stderr)
        return 1

    if launcher:
        classes = find_launcher_classes(decompiled_dir)
        if not classes:
            print('❌ 未从 AndroidManifest.xml 找到 LAUNCHER activity', file=sys.stderr)
            return 2
        print(f'ℹ️ LAUNCHER activity: {classes}', file=sys.stderr)
    else:
        classes = [target]

    rc = 0
    for cls in classes:
        r = inject_loadlib_to_class(cls, decompiled_dir, so_name)
        print(f'  {cls}: {r}')
        if r == 'missing':
            rc = 3
    return rc


if __name__ == '__main__':
    sys.exit(_cli())
