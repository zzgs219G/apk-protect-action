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

LAUNCHER 解析(报错五修复后 manifest 全程保持二进制):
  - 顶层 AndroidManifest.xml 为二进制 AXML 时走 androguard 解析
    (dcc 自带,见 make-filter-from-apk.py 同款导入方式)
  - 解析失败或为文本 XML 时降级为文本正则(兼容旧流程/调试)
"""
import os
import re
import sys

SMALI_DIR_RE = re.compile(r'^smali(?:_classes\\d+)?$')

# androguard 从 dcc 目录导入(dcc 内置版,勿用 pip 版替换,见 make-filter-from-apk.py)
_DCC_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         '..', '..', 'sigcheck', 'dex2c', 'dcc'))


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


def _find_launcher_from_axml(manifest_path, package_name):
    """二进制 AXML 路径:用 dcc 内置 androguard 的 AXMLPrinter 转文本后复用
    现有正则逻辑。裸 AXML 不是 zip,不能喂给 APK();必须走 AXMLPrinter。
    成功返回 smali 格式类名列表;androguard 不可用/解析失败返回 None(降级)。"""
    if os.path.getsize(manifest_path) < 8:
        return None
    with open(manifest_path, 'rb') as fp:
        head = fp.read(4)
    if head != b'\x03\x00\x08\x00':     # 非二进制 AXML → 交给文本正则分支
        return None
    if _DCC_DIR not in sys.path:
        sys.path.insert(0, _DCC_DIR)
    try:
        from androguard.core.bytecodes.axml import AXMLPrinter
        with open(manifest_path, 'rb') as fp:
            xml_bytes = AXMLPrinter(fp.read()).get_xml()
        content = xml_bytes.decode('utf-8', 'replace') \
            if isinstance(xml_bytes, bytes) else str(xml_bytes)
    except ImportError as e:
        # 常见根因(报错六):dcc 内置 androguard 的 AXMLPrinter 依赖 lxml,
        # runner 系统 python 不带 → pip3 install -r sigcheck/dex2c/dcc/requirements.txt
        print(f'⚠️ androguard 不可用({_DCC_DIR}): {e};'
              f'若提示缺 lxml,请先 pip3 install -r sigcheck/dex2c/dcc/requirements.txt;'
              f'降级文本解析(仅对文本 XML 有效,二进制 AXML 必失败)', file=sys.stderr)
        return None
    except Exception as e:
        print(f'⚠️ AXML 解析失败: {type(e).__name__}: {e},降级文本解析', file=sys.stderr)
        return None
    return _find_launchers_in_text(content, package_name)


def find_launcher_classes(decompiled_dir, package_name=None):
    """从 apktool 解包目录的 AndroidManifest.xml 提取 LAUNCHER activity。
    二进制 AXML → androguard AXMLPrinter;文本 XML → 纯文本正则。
    返回 smali 格式类名列表(Lcom/a/B;)。"""
    manifest = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest):
        return []

    # 报错五修复后顶层 manifest 是二进制 AXML;先试 androguard,失败降级文本正则
    result = _find_launcher_from_axml(manifest, package_name)
    if result is not None:
        return result

    with open(manifest, encoding='utf-8', errors='replace') as fp:
        content = fp.read()

    return _find_launchers_in_text(content, package_name)


def _find_launchers_in_text(content, package_name=None):
    """文本 XML → LAUNCHER activity smali 类名列表(AXMLPrinter 分支复用)。"""
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
