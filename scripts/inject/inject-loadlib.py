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
       inject-loadlib.py <解包目录> --launcher --entrypoints    # 双保险:<clinit>+onCreate

插桩策略(与 mark-native.py 一致,防误插):
  - 目标类已有 loadLibrary 调用 → 跳过(幂等,多模块共存时不重复插)
  - 已有 <clinit> → 在其开头插入
  - 没有 <clinit> → 在 .class 行后新建一个

双保险模式(--entrypoints,单独签名校验方案用):
  <clinit> + onCreate 各插一份 System.loadLibrary,攻击者要删两处才绕过。
  联合方案(dex2c)不需要:onCreate 已被抽进 so 变 native 壳,攻击者删
  <clinit> 的 loadLibrary 会让 native 壳 UnsatisfiedLinkError 自爆,
  双保险反而多余。

LAUNCHER 解析(报错五修复后 manifest 全程保持二进制):
  - 顶层 AndroidManifest.xml 为二进制 AXML 时走 androguard 解析
    (dcc 自带,见 make-filter-from-apk.py 同款导入方式)
  - 解析失败或为文本 XML 时降级为文本正则(兼容旧流程/调试)
"""
import os
import re
import sys

SMALI_DIR_RE = re.compile(r'^smali(?:_classes\d+)?$')

# androguard 从 dcc 目录导入(dcc 内置版,勿用 pip 版替换,见 make-filter-from-apk.py)
_DCC_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         '..', '..', 'sigcheck', 'dex2c', 'dcc'))


def _count_param_regs(args_sig):
    """统计方法参数描述符占用的寄存器数(J/D 各占 2 个寄存器)。
    args_sig 为方法签名 () 内的描述符串,如 'Landroid/os/Bundle;'。"""
    n = 0
    i = 0
    while i < len(args_sig):
        c = args_sig[i]
        if c == 'L':
            i = args_sig.index(';', i) + 1
            n += 1
        elif c == '[':
            while i < len(args_sig) and args_sig[i] == '[':
                i += 1
            if i < len(args_sig) and args_sig[i] == 'L':
                i = args_sig.index(';', i)
            n += 1
            i += 1
        elif c in 'JD':
            n += 2
            i += 1
        else:
            n += 1
            i += 1
    return n


_CLINIT_HEADER_RE = re.compile(
    r'^\.method\s[^\n]*\bconstructor\s+<clinit>\(\)', re.M)
_ONCREATE_HEADER_RE = re.compile(r'^\.method\s[^\n]*\bonCreate\(', re.M)


def _method_span(content, header_re):
    """header_re 命中的方法 → (方法头行起始偏移, .end method 行结束偏移)。
    找不到返回 None。"""
    m = header_re.search(content)
    if not m:
        return None
    end = content.find('.end method', m.start())
    if end == -1:
        return None
    return m.start(), end + len('.end method')


def _inject_into_method_body(content, header_re, so_name):
    """向【已有】方法体开头头插 System.loadLibrary。

    寄存器策略:插桩指令用 v0。v0 必须是局部寄存器(非参数):
      .locals M    → M >= 1 时 v0 是局部
      .registers N → N > 参数寄存器数时 v0 是局部
    零局部方法跳过不插 —— 若给 .registers +1,参数寄存器在末尾、编号会全体
    平移,方法体里用 v 别名引用参数的指令全部错位,得不偿失。onCreate
    现实中必有局部寄存器(至少要调 super.onCreate),此分支仅兜底。

    返回 (new_content, status):
      prepended / already / no-method / no-registers / no-local-register
    """
    span = _method_span(content, header_re)
    if not span:
        return content, 'no-method'
    body = content[span[0]:span[1]]
    if 'loadLibrary' in body:
        return content, 'already'

    rm = re.search(r'^[ \t]*\.(registers|locals)[ \t]+(\d+)[ \t]*$', body, re.M)
    if not rm:
        return content, 'no-registers'
    kind, total = rm.group(1), int(rm.group(2))

    if kind == 'locals':
        if total < 1:
            return content, 'no-local-register'
    else:
        first_line = body[:body.index('\n')]
        pm = re.search(r'\(([^)]*)\)', first_line)
        if not pm:
            return content, 'no-local-register'
        p_regs = _count_param_regs(pm.group(1))
        if not re.search(r'\bstatic\b', first_line):
            p_regs += 1                      # virtual 方法 this 占 1 个
        if total <= p_regs:
            return content, 'no-local-register'

    load_stmt = ('const-string v0, "%s"\n'
                 'invoke-static {v0}, Ljava/lang/System;'
                 '->loadLibrary(Ljava/lang/String;)V' % so_name)
    # 插在寄存器声明行之后(re.M 下 $ 匹配在 \n 之前,故补 \n;
    # load_stmt 不带尾换行,由原文的 \n 收尾)
    body = body[:rm.end()] + '\n' + load_stmt + body[rm.end():]
    return content[:span[0]] + body + content[span[1]:], 'prepended'


def inject_loadlib_to_entrypoints(class_name, decompiled_dir, so_name='nc'):
    """双保险插桩:<clinit> + onCreate 各插一份 System.loadLibrary。

    背景:攻击者可整体删除 <clinit>(或其中 loadLibrary 语句)绕过签名校验
    (单独签名校验方案没有 dex2c 的 native 壳自爆保护);onCreate 里再插
    一份,要删两处才失效。两处各自独立幂等(按方法体检查 loadLibrary,
    而非按类 —— 否则 clinit 已插会连累 onCreate 跳过)。

    为什么 <clinit> 不能被 dex2c 抽进 so:被抽进 so 的方法依赖先加载 so
    才能执行,而 loadLibrary 就在 <clinit> 里,鸡生蛋。dex 里必须永远
    保留一条 Java 层 loadLibrary(filter 的 !<clinit|init> 排除即此意)。

    返回 {'clinit': 状态, 'onCreate': 状态}:
      clinit:   inserted(新建)/ prepended(已有头插)/ already / missing
      onCreate: prepended / already / no-method(类未 override onCreate,
                继承自父类,无法插 —— clinit 那份仍在)/ no-registers /
                no-local-register / missing
    """
    if not class_name.endswith(';'):
        class_name += ';'
    smali_path = find_smali_file_by_class(decompiled_dir, class_name)
    if not smali_path:
        return {'clinit': 'missing', 'onCreate': 'missing'}

    with open(smali_path) as fp:
        content = fp.read()

    # <clinit>:有则头插,无则新建(与 inject_loadlib_to_class 相同逻辑)
    content, clinit_status = _inject_into_method_body(
        content, _CLINIT_HEADER_RE, so_name)
    if clinit_status == 'no-method':
        clinit = ('.method static constructor <clinit>()V\n'
                  '    .registers 1\n\n'
                  'const-string v0, "%s"\n'
                  'invoke-static {v0}, Ljava/lang/System;'
                  '->loadLibrary(Ljava/lang/String;)V\n'
                  '    return-void\n.end method\n\n' % so_name)
        content = re.sub(r'(\.class[^\n]*\n)', r'\1\n' + clinit, content, count=1)
        clinit_status = 'inserted'

    # onCreate:类未 override(继承父类)时 no-method,不强插 —— clinit 那份仍在
    content, oncreate_status = _inject_into_method_body(
        content, _ONCREATE_HEADER_RE, so_name)

    with open(smali_path, 'w') as fp:
        fp.write(content)
    return {'clinit': clinit_status, 'onCreate': oncreate_status}


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
    """解析 CLI 参数 → (decompiled_dir, target, so_name, launcher, entrypoints)。
    支持 --launcher / --so-name / --entrypoints 出现在任意位置。"""
    decompiled_dir = None
    target = None
    so_name = 'nc'
    launcher = False
    entrypoints = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--so-name' and i + 1 < len(argv):
            so_name = argv[i + 1]
            i += 2
        elif a == '--launcher':
            launcher = True
            i += 1
        elif a == '--entrypoints':
            entrypoints = True
            i += 1
        elif decompiled_dir is None:
            decompiled_dir = a
            i += 1
        else:
            target = a
            i += 1
    return decompiled_dir, target, so_name, launcher, entrypoints


def _cli():
    """命令行入口(调试/独立测试用)。"""
    decompiled_dir, target, so_name, launcher, entrypoints = _parse_cli_args(sys.argv[1:])
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
        if entrypoints:
            r = inject_loadlib_to_entrypoints(cls, decompiled_dir, so_name)
            print(f'  {cls}: clinit={r["clinit"]} onCreate={r["onCreate"]}')
            if r['clinit'] == 'missing':
                rc = 3
        else:
            r = inject_loadlib_to_class(cls, decompiled_dir, so_name)
            print(f'  {cls}: {r}')
            if r == 'missing':
                rc = 3
    return rc


if __name__ == '__main__':
    sys.exit(_cli())
