#!/usr/bin/env python3
"""inject-javacheck.py — Java 层判决式签名校验注入器(非冻结,签名校验模块成员)

CLI 契约:
  inject-javacheck.py <解包目录> [--so-name nc] [--wrapper-name Lcom/x/Guard;]
  inject-javacheck.py clean <解包目录>

设计(docs/流程文档.md §3.11,与用户逐条对齐):
  - 判决式:Java 只"量"(PackageManager → SHA256 → SHA256)并执行杀;
    标准值与比对全在 so(nc_link.c),指纹永不过境进 dex。
  - fail-closed:so 缺失(UnsatisfiedLinkError)→ 杀 —— loadLibrary 成为承重墙,
    "删开关静默绕过"这个 sigcheck-only 最大缺口由此关闭。
  - 测量环境异常(其他 Throwable)→ 静默跳过(so 独立校验仍是权威,防误杀)。
  - 固定桥接类 Lcom/nc/link/NcLink;(JNI 短名绑定要求,同 StrDec 工具命名先例)
    + 自适应命名逻辑类(R8 混淆包 → 短名风格;普通包 → app 包名派生,用户拍板)。
  - 幂等:类文件带 # nc-javacheck-applied v1 标记 + javacheck-components.json;
  - 零寄存器手术:调用点只插 `invoke-static {p0}, ...`(p0 为现成参数寄存器,
    且写入前校验其物理编号 ≤ v15,否则弃用该调用点);新类 .locals 全部自持
    —— 从构造上规避报错二十一/二十二/三十四整类寄存器炸弹。
  - 插入点:LAUNCHER 与 Application 的 onCreate(均各插一份,双保险);
    方法不存在则新建 onCreate 覆写(super 调用 + 本调用,应用类/启动页合法形态)。

⚠️ smali 由本文件按 stub-src/*.java 语义手工生成(宿主无 d8 链路,偏离
   报错二十六 D3 决策的替代纪律):每个生成文件过三道渲染防线(占位符残留 /
   类体顶层裸指令 / so 名字符合法性),并由 tests/test-javacheck.sh 做
   SmaliBuilder 真汇编 + androguard 读回闭环;完整链路由 CI workflow 兜底。
"""
import json
import os
import re
import sys

MARKER = '# nc-javacheck-applied v1'
CALL_MARKER = '# nc-javacheck-call'
COMPONENTS_JSON = 'javacheck-components.json'
BRIDGE_DESC = 'Lcom/nc/link/NcLink;'
# ⚠️ 2026-10-17 回归教训：曾为 .ncx 自检单独造 Lcom/nc/guard/NcGuard;
# 类,只在 smali 模板里加了【调用】却忘了【生成类】→ selftest() 抛
# UnsatisfiedLinkError → 被 catch(Throwable) 静默吞掉 → 连带跳过后面的
# heartbeat()/startHeartbeat() → 心跳停喂 → watchdog 误杀（复现报错四十九）。
# 现改为【挂到已注入的 NcLink 上】:零新类、零新链路,selftest 与 ncVerify/
# heartbeat 同源。native 侧对应 Java_com_nc_link_NcLink_selftest。
SO_NAME_RE = re.compile(r'^[A-Za-z0-9_]{1,30}$')
SMALI_DIR_RE = re.compile(r'^smali(?:_classes\d+)?$')   # 与 inject-loadlib/mark-native 同源,改动须 grep 三处

_DCC_DIR = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         '..', '..', '..', 'tools', 'dcc'))


def _ensure_dcc_dir():
    """dcc 解压目录缺失时从 tools/dcc.zip 幂等解压(项目导览 §四份解压设计的
    第 5 份副本:同目标路径、幂等、解压后校验 dcc.py 在位)。"""
    if not os.path.isfile(os.path.join(_DCC_DIR, 'dcc.py')):
        dcc_zip = os.path.normpath(os.path.join(_DCC_DIR, '..', 'dcc.zip'))
        if not os.path.isfile(dcc_zip):
            raise FileNotFoundError(f'dcc 分发包缺失: {dcc_zip}')
        import zipfile
        os.makedirs(os.path.dirname(_DCC_DIR), exist_ok=True)
        with zipfile.ZipFile(dcc_zip) as zf:
            zf.extractall(os.path.dirname(_DCC_DIR))
        if not os.path.isfile(os.path.join(_DCC_DIR, 'dcc.py')):
            raise FileNotFoundError(f'dcc.zip 解压后缺 dcc.py: {_DCC_DIR}')
    return _DCC_DIR


# ───────────────────────── Manifest 解析 ─────────────────────────

def _read_manifest_text(decompiled_dir):
    """二进制 AXML → AXMLPrinter 转文本;文本 XML 原样读。失败返回 None。"""
    path = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    if not os.path.isfile(path):
        return None
    with open(path, 'rb') as fp:
        raw = fp.read()
    if len(raw) < 8:
        return None
    if raw[:4] == b'\x03\x00\x08\x00':          # 二进制 AXML(报错五:全程保持二进制)
        dcc_dir = _ensure_dcc_dir()
        if dcc_dir not in sys.path:
            sys.path.insert(0, dcc_dir)
        try:
            from androguard.core.bytecodes.axml import AXMLPrinter
            xml_bytes = AXMLPrinter(raw).get_xml()
        except Exception as e:
            print(f'❌ AXML 解析失败: {type(e).__name__}: {e}', file=sys.stderr)
            return None
        return xml_bytes.decode('utf-8', 'replace') if isinstance(xml_bytes, bytes) else str(xml_bytes)
    return raw.decode('utf-8', 'replace')        # 文本 XML(调试/旧流程)


def _complete_class(name, package):
    """相对类名补全:.App → pkg.App;无点短名 App → pkg.App(与 make-filter-from-apk 同规则)。"""
    if name.startswith('.'):
        return package + name
    if '.' not in name:
        return package + '.' + name
    return name


def parse_manifest(decompiled_dir):
    """返回 dict(package, app_class, launchers);类名均为 smali 描述符 L...;。"""
    text = _read_manifest_text(decompiled_dir)
    if text is None:
        raise RuntimeError('AndroidManifest.xml 不存在或解析失败(解包目录不完整?)')
    m = re.search(r'\bpackage="([^"]+)"', text)
    package = m.group(1) if m else ''

    def to_desc(java_name):
        return 'L' + java_name.replace('.', '/') + ';'

    app_class = None
    am = re.search(r'<application\b[^>]*>', text, re.S)
    if am:
        nm = re.search(r'android:name="([^"]+)"', am.group(0))
        if nm and nm.group(1):
            app_class = to_desc(_complete_class(nm.group(1), package))

    launchers = []
    for act in re.finditer(r'<activity\b[^>]*>(.*?)</activity>|<activity\b[^>]*/>', text, re.S):
        tag = act.group(0)
        nm = re.search(r'android:name="([^"]+)"', tag)
        if not nm:
            continue
        if re.search(r'android:enabled="false"', tag):
            continue
        body = act.group(1) or ''
        if ('android.intent.action.MAIN' in body
                and 'android.intent.category.LAUNCHER' in body):
            launchers.append(to_desc(_complete_class(nm.group(1), package)))
    return {'package': package, 'app_class': app_class, 'launchers': launchers}


# ───────────────────────── smali 扫描/类名策略 ─────────────────────────

def iter_smali_files(decompiled_dir):
    for entry in sorted(os.listdir(decompiled_dir)):
        if SMALI_DIR_RE.match(entry):
            root = os.path.join(decompiled_dir, entry)
            for dirpath, _dirs, files in os.walk(root):
                for fn in files:
                    if fn.endswith('.smali'):
                        yield os.path.join(dirpath, fn)


def scan_class_names(decompiled_dir):
    """{全名描述符: 简名} —— 碰撞检查与混淆风格判定共用。"""
    names = {}
    cls_re = re.compile(r'^\.class[^;]*?\s(L[^;]+;)\s*$')
    for path in iter_smali_files(decompiled_dir):
        with open(path, encoding='utf-8', errors='replace') as fp:
            for line in fp:
                m = cls_re.match(line.strip())
                if m:
                    desc = m.group(1)
                    simple = desc[desc.rfind('/') + 1:-1]
                    names[desc] = simple
    return names


def pick_wrapper_name(decompiled_dir, package, launcher_desc):
    """自适应命名(用户拍板方案):
    - 混淆包(多数简名 ≤2 字符) → 在高频既有包下取未占用的短名(如 Lab/Gc);
    - 普通包 → app 包名派生 NativeGuard 系列名。
    确定性:同一输入产出同一名字(有序遍历)。"""
    names = scan_class_names(decompiled_dir)
    taken = set(names)
    simple_list = [s for s in names.values() if len(s) <= 32]
    obf = sum(1 for s in simple_list if len(s) <= 2)
    if simple_list and obf / len(simple_list) > 0.5:
        pkg_counts = {}
        for desc, simple in names.items():
            if len(simple) <= 2:
                pkg = desc[1:desc.rfind('/')]
                pkg_counts[pkg] = pkg_counts.get(pkg, 0) + 1
        pkgs = sorted(pkg_counts, key=lambda k: (-pkg_counts[k], k))
        for pkg in pkgs:
            for c1 in 'abcdefgh':
                for c2 in 'abcdefgh':
                    cand = f'L{pkg}/{c1}{c2};'
                    if cand not in taken:
                        return cand
        raise RuntimeError('短名空间耗尽(不可能触达)')
    for cand_name in ('NativeGuard', 'AppGuard', 'IntegrityCheck', 'GuardUtil'):
        cand = f'L{package.replace(".", "/")}/{cand_name};'
        if cand not in taken:
            return cand
    n = 2
    while True:
        cand = f'L{package.replace(".", "/")}/NativeGuard{n};'
        if cand not in taken:
            return cand
        n += 1


# ───────────────────────── smali 渲染(防线内置) ─────────────────────────

def _render_asserts(text, so_name):
    """报错二十五式三防线:占位符残留 / 类体顶层裸指令 / so 名合法性。"""
    if not SO_NAME_RE.match(so_name):
        raise AssertionError(f'so 名非法(防 smali 注入): {so_name!r}')
    if '%' in text:
        raise AssertionError('渲染产物含 % 占位符残留(报错二十五防线)')
    in_method = False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith('.method'):
            in_method = True
        if not in_method and s and not s.startswith('.') and not s.startswith('#'):
            raise AssertionError(f'类体顶层出现裸指令(报错二十五防线): {s!r}')


def render_bridge(so_name):
    """NcLink 桥接类:类名/方法名参与 JNI 短名绑定,改名字必须同步 nc_link.c。"""
    text = f"""# {MARKER}
# Java 层判决式签名校验 · 固定桥接类(JNI 名绑定依赖此名,勿改包名/类名/方法名)
# 语义真相: stub-src/NcLink.java
.class public final {BRIDGE_DESC}
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# 幂等加载 so(重复调用 no-op);缺失时抛 UnsatisfiedLinkError → 调用方 fail-closed
.method public static ensureLoaded()V
    .locals 1
    const-string v0, "{so_name}"
    invoke-static {{v0}}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
    return-void
.end method

# 判决入口:入参 t1 = SHA256(SHA256(实测证书DER));标准答案常驻 so,从不出境
.method public static native ncVerify([B)Z
.end method

# 心跳喂食入口:Guard 的 daemon 线程每 5s 调一次;native 侧校验调用者身份
# (IsSameObject 锁死本类)后记录时间戳;env_watchdog 超时未喂 → 杀。
# 语义真相: stub-src/NcLink.java
.method public static native heartbeat()V
.end method

# .ncx 段自解密自检(2026-12):59=完整链路通过,-100=已自检过重入,
# 负数=解锁失败(码表见 nc_guard_boot.c 的 ncg_head_unlock)。纯观测,不参与防御判定。
# ⚠️ 挂靠 NcLink(与 ncVerify/heartbeat 同源),不要另造类——
# 2026-10-17 曾独立造 Lcom/nc/guard/NcGuard; 却只加调用不生成类,
# selftest() 抛 UnsatisfiedLinkError 被主 catch 吞掉并跳过 heartbeat,
# 复现报错四十九(真机日志连打"Java 心跳丢失")。
.method public static native selftest()I
.end method
"""
    _render_asserts(text, so_name)
    return text


def render_guard(wrapper_desc):
    """Guard 逻辑类:测量(PackageManager) + 执行(杀);标准值永不出 so。
    寄存器账本:.locals 7(v0-v6) + p0 = v7,全部 ≤ v15(35c 上限)。"""
    text = f"""# {MARKER}
# Java 层判决式签名校验 · 测量与执行(自适应命名;逻辑真相: stub-src/Guard.java)
.class public final {wrapper_desc}
.super Ljava/lang/Object;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Object;-><init>()V
    return-void
.end method

# 单发守卫字段(daemon 线程只开一次)
.field private static hbStarted:Z

# 心跳喂食线程(daemon,5s 一次):语义真相 stub-src/Guard.java#startHeartbeat
# 单发守卫由 Guard$hbStarted 标志位承担;喂失败吞 Throwable(native 超时自会兜底)
.method public static startHeartbeat()V
    .locals 4
    sget-boolean v0, {wrapper_desc}->hbStarted:Z
    if-eqz v0, :cond_hb_go
    return-void
    :cond_hb_go
    const/4 v0, 0x1
    sput-boolean v0, {wrapper_desc}->hbStarted:Z
    new-instance v1, {wrapper_desc[:-1]}$Hb;
    invoke-direct {{v1}}, {wrapper_desc[:-1]}$Hb;-><init>()V
    const/4 v0, 0x1
    invoke-virtual {{v1, v0}}, Ljava/lang/Thread;->setDaemon(Z)V
    invoke-virtual {{v1}}, Ljava/lang/Thread;->start()V
    return-void
.end method

.method public static c(Landroid/content/Context;)V
    .locals 7

    .catch Ljava/lang/UnsatisfiedLinkError; {{:try_start_0 .. :try_end_0}} :catch_link
    .catch Ljava/lang/Throwable; {{:try_start_0 .. :try_end_0}} :catch_skip

    :try_start_0
    invoke-static {{}}, {BRIDGE_DESC}->ensureLoaded()V
    # .ncx 段自解密自检(2026-12):so 已加载即触发一次性解锁。
    # 59 = 完整链路通过;-100 = 已自检过;负数 = 解锁失败(码表见 nc_guard_boot.c)。
    # ⚠️ 必须用【独立的 try/catch】包住:2026-10-17 曾把 selftest 直接放在
    # 主 try 里,而当它抛 UnsatisfiedLinkError 时会被主 catch(Throwable)
    # 吞掉并【连带跳过后面的 heartbeat()/startHeartbeat()】→ 心跳停喂 →
    # watchdog 误杀(报错四十九复现,真机日志连打"Java 心跳丢失")。
    # 现在自检的任何失败都只影响自己,绝不能波及心跳。
    # selftest 与 ncVerify/heartbeat 同挂 NcLink —— native 方法在库里是
    # 同一批注册的,只要 ensureLoaded() 成功它就必然存在,不会抛
    # UnsatisfiedLinkError(报错四十九的根因就是"类不存在")。
    # .ncx 未解锁时 native 侧返回负数而非抛异常,所以主 catch 不会因它触发。
    invoke-static {{}}, {BRIDGE_DESC}->selftest()I
    move-result v0
    const/16 v1, 0x3b
    if-eq v0, v1, :after_selftest
    const-string v0, "ncguard"
    const-string v1, "selftest rc!=59"
    invoke-static {{v0, v1}}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I
    :after_selftest
    # 心跳前置(2026-10-16 修复):喂食必须与"测量是否成功"解耦。
    # 旧形态放在 ncVerify 通过之后 —— 测量链抛任何非 ULE Throwable 就跳
    # :catch_skip 静默返回 → 一次都不喂 → env_watchdog 把"没喂"误判成
    # "Java 壳被删" → 正常包冷启动 ~6s 必杀(真机实证 docs/sigcheck_log.txt)。
    # so 已加载(ensureLoaded 成功)即开始喂;判决不过走 :cond_kill,测量异常
    # 走 :catch_skip —— 两者的处置各归各路,不再由心跳把"测量失败"升级成死刑。
    invoke-static {{}}, {BRIDGE_DESC}->heartbeat()V
    invoke-static {{}}, {wrapper_desc}->startHeartbeat()V
    const-string v0, "SHA-256"
    invoke-static {{v0}}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;
    move-result-object v1
    invoke-virtual {{p0}}, Landroid/content/Context;->getPackageManager()Landroid/content/PackageManager;
    move-result-object v2
    invoke-virtual {{p0}}, Landroid/content/Context;->getPackageName()Ljava/lang/String;
    move-result-object v3
    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I
    const/16 v5, 0x1c
    if-lt v4, v5, :cond_legacy
    const v6, 0x8000000
    invoke-virtual {{v2, v3, v6}}, Landroid/content/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v4
    iget-object v4, v4, Landroid/content/pm/PackageInfo;->signingInfo:Landroid/content/pm/SigningInfo;
    invoke-virtual {{v4}}, Landroid/content/pm/SigningInfo;->getApkContentsSigners()[Landroid/content/pm/Signature;
    move-result-object v4
    goto :goto_have_sig
    :cond_legacy
    const/16 v6, 0x40
    invoke-virtual {{v2, v3, v6}}, Landroid/content/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;
    move-result-object v4
    iget-object v4, v4, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;
    :goto_have_sig
    const/4 v5, 0x0
    aget-object v4, v4, v5
    invoke-virtual {{v4}}, Landroid/content/pm/Signature;->toByteArray()[B
    move-result-object v4
    invoke-virtual {{v1, v4}}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v4
    invoke-virtual {{v1, v4}}, Ljava/security/MessageDigest;->digest([B)[B
    move-result-object v4
    invoke-static {{v4}}, {BRIDGE_DESC}->ncVerify([B)Z
    move-result v4
    if-eqz v4, :cond_kill
    return-void
    :try_end_0
    :cond_kill
    invoke-static {{}}, Landroid/os/Process;->myPid()I
    move-result v0
    invoke-static {{v0}}, Landroid/os/Process;->killProcess(I)V
    return-void
    :catch_link
    invoke-static {{}}, Landroid/os/Process;->myPid()I
    move-result v0
    invoke-static {{v0}}, Landroid/os/Process;->killProcess(I)V
    return-void
    :catch_skip
    return-void
.end method
"""
    _render_asserts(text, 'nc')
    return text


def render_hb(wrapper_desc):
    """Hb 内部类:心跳喂食循环(daemon Thread 子类,5s 一次)。
    喂失败吞 Throwable 继续 —— native 侧超时自会处置(Xop 同款纪律)。"""
    text = f"""# {MARKER}
# Java→Native 心跳喂食循环(语义真相: stub-src/Guard.java#startHeartbeat)
.class public final {wrapper_desc[:-1]}$Hb;
.super Ljava/lang/Thread;

.method public constructor <init>()V
    .locals 0
    invoke-direct {{p0}}, Ljava/lang/Thread;-><init>()V
    return-void
.end method

.method public run()V
    .locals 2

    :goto_loop
    :try_start_0
    invoke-static {{}}, {BRIDGE_DESC}->heartbeat()V
    const-wide/16 v0, 0x1388
    invoke-static {{v0, v1}}, Ljava/lang/Thread;->sleep(J)V
    :try_end_0
    .catch Ljava/lang/Throwable; {{:try_start_0 .. :try_end_0}} :catch_hb
    goto :goto_loop
    :catch_hb
    goto :goto_loop
.end method
"""
    return text


# ───────────────────────── 调用点注入 ─────────────────────────

PARAM_RE = re.compile(r'\(([^)]*)\)')
TYPE_WORD2 = ('J', 'D')            # long/double 占 2 个寄存器槽
DIRECTIVE_RE = re.compile(r'^\.')


def _param_words(proto):
    """参数字数(不含 this):J/D 计 2,其余 1;数组/对象/基本类型按描述符解析。"""
    args = PARAM_RE.search(proto).group(1)
    words, i = 0, 0
    while i < len(args):
        c = args[i]
        if c in TYPE_WORD2:
            words += 1
            i += 1
        elif c == '[':
            i += 1
            while i < len(args) and args[i] == '[':
                i += 1
            if i < len(args) and args[i] == 'L':       # [L...;
                i = args.index(';', i) + 1
            else:
                i += 1
            words += 1
        elif c == 'L':
            i = args.index(';', i) + 1
            words += 1
        else:
            i += 1
            words += 1
    return words


def _method_info(lines, start_idx):
    """解析 .method 头 → (is_static, proto, total_registers)。缺 .registers 时按 .locals 推。"""
    header = lines[start_idx].strip()
    is_static = re.search(r'\bstatic\b', header.split('(')[0]) is not None
    proto = header[header.index('('):header.rindex(')') + 1]
    arg_words = _param_words(proto)
    this_words = 0 if is_static else 1
    total = None
    for i in range(start_idx + 1, len(lines)):
        s = lines[i].strip()
        if s.startswith('.end method'):
            break
        m = re.match(r'^\.registers\s+(\d+)', s)
        if m:
            total = int(m.group(1))
            break
        m = re.match(r'^\.locals\s+(\d+)', s)
        if m:
            total = int(m.group(1)) + arg_words + this_words
            break
    if total is None:
        total = arg_words + this_words          # smali 缺省 .locals 0
    return is_static, proto, total


def _first_instruction_idx(lines, start_idx):
    """方法体内第一条指令的行号(跳过 .registers/.locals/.annotation 等
    指令性伪指令与空行/注释 —— 它们全部以 . 或 # 开头)。"""
    for i in range(start_idx + 1, len(lines)):
        s = lines[i].strip()
        if s.startswith('.end method'):
            return None                          # 空方法体(异常形态,不处理)
        if s and not s.startswith('.') and not s.startswith('#'):
            return i
    return None


def inject_call_site(path, wrapper_desc):
    """往该 smali 文件的 onCreate 里插一行 invoke-static {p0}(零新增寄存器)。
    onCreate 不存在则新建覆写(合法形态:super 调用 + 本调用)。
    onCreate 被 mark-native 抽成 native 壳时跳过该点(报错三十九防线)。
    返回 (changed, note);p0 物理编号 > v15 时弃用该点(报错二十一式防线)。"""
    with open(path, encoding='utf-8') as fp:
        lines = fp.read().splitlines()
    if any(CALL_MARKER in ln for ln in lines):
        return False, 'already'
    if not any('onCreate' in ln and ln.strip().startswith('.method') for ln in lines):
        return False, 'no-method'

    target = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith('.method') and 'onCreate' in ln and ' end' not in ln:
            target = i
            break
    if target is None:
        return False, 'no-method'

    # 报错三十九(2026-10-12 build.log,dex2c 组合场景):onCreate 被
    # mark-native 抽成 native 壳(无方法体,dex 寄存器数为 0)。空壳会
    # 落进下面 ins is None 的"补方法体"分支 → 给 native 方法凭空造体,
    # 回编必炸:"A native method cannot have any instructions" + p0 按
    # 零寄存器解析成负号(2 参数槽 → v-2)。native 壳本身就是承重墙
    # (删 loadLibrary → UnsatisfiedLinkError fail-closed),跳过该点
    # 不降整体防护——app 侧调用点仍在(双保险),与 inject-loadlib 对
    # native 壳的保守策略同向(其 'no-registers' 分支天然跳过)。
    if re.search(r'\bnative\b', lines[target]):
        return False, 'native-onCreate'

    is_static, proto, total = _method_info(lines, target)
    this_words = 0 if is_static else 1
    # p0 的物理寄存器编号 = total - 参数总字数(this 计入);>v15 则 35c 装不下
    p0_phys = total - (_param_words(proto) + this_words)
    if is_static or p0_phys > 15 or p0_phys < 0:
        return False, f'register-unsafe(p0=v{p0_phys},35c 上限 v15)'

    call_line = (f'    invoke-static {{p0}}, {wrapper_desc}'
                 f'->c(Landroid/content/Context;)V {CALL_MARKER}')
    ins = _first_instruction_idx(lines, target)
    if ins is None:
        # 空方法体:在 .end method 前补 return-void + 调用
        end_idx = next(i for i in range(target + 1, len(lines))
                       if lines[i].strip().startswith('.end method'))
        lines[end_idx:end_idx] = [call_line, '    return-void', '']
        changed = True
    else:
        lines.insert(ins, call_line)
        changed = True
    with open(path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines) + '\n')
    return changed, f'{os.path.relpath(path, os.path.dirname(path))} @onCreate'


def find_smali_file(decompiled_dir, desc):
    rel = desc[1:-1] + '.smali'
    for entry in sorted(os.listdir(decompiled_dir)):
        if SMALI_DIR_RE.match(entry):
            p = os.path.join(decompiled_dir, entry, rel)
            if os.path.isfile(p):
                return p
    return None


def _create_oncreate_override(path, desc, super_desc):
    """给没有 onCreate 的目标类新建覆写(super 调用 + return)。
    Application.onCreate()V 无参;Activity 系 onCreate(Landroid/os/Bundle;)V 带参。
    invoke-super 沿父链向上解析,直接用声明 .super 即可;读回测试兜底。"""
    with open(path, encoding='utf-8') as fp:
        content = fp.read()
    if '.method' in content and 'onCreate' in content:
        return False
    if super_desc == 'Landroid/app/Application;':
        block = (f'\n.method public onCreate()V\n'
                 f'    .locals 0\n'
                 f'    invoke-super {{p0}}, {super_desc}->onCreate()V\n'
                 f'    return-void\n'
                 f'.end method\n')
    else:
        block = (f'\n.method public onCreate(Landroid/os/Bundle;)V\n'
                 f'    .locals 0\n'
                 f'    invoke-super {{p0, p1}}, {super_desc}'
                 f'->onCreate(Landroid/os/Bundle;)V\n'
                 f'    return-void\n'
                 f'.end method\n')
    with open(path, 'a', encoding='utf-8') as fp:
        fp.write(block)
    return True


# ───────────────────────── 主流程 ─────────────────────────

def do_inject(decompiled_dir, so_name, wrapper_override=None):
    comp_path = os.path.join(decompiled_dir, COMPONENTS_JSON)
    if os.path.isfile(comp_path):
        print(f'ℹ️ 已注入过({COMPONENTS_JSON} 在位),幂等跳过')
        return 0

    info = parse_manifest(decompiled_dir)
    print(f'📋 manifest: package={info["package"]} app={info["app_class"]} '
          f'launchers={info["launchers"]}')

    wrapper = wrapper_override or pick_wrapper_name(
        decompiled_dir, info['package'],
        info['launchers'][0] if info['launchers'] else None)
    print(f'🏷️ 自适应命名: 逻辑类={wrapper} 桥接类={BRIDGE_DESC}')

    wrapper_path = os.path.join(decompiled_dir, 'smali',
                                wrapper[1:-1].replace('/', '/') + '.smali')
    bridge_path = os.path.join(decompiled_dir, 'smali',
                               BRIDGE_DESC[1:-1] + '.smali')
    for p in (wrapper_path, bridge_path):
        os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(wrapper_path, 'w', encoding='utf-8') as fp:
        fp.write(render_guard(wrapper))
    with open(bridge_path, 'w', encoding='utf-8') as fp:
        fp.write(render_bridge(so_name))
    # 心跳喂食循环(daemon Thread 子类,与 Guard 同目录)
    hb_path = os.path.join(decompiled_dir, 'smali',
                           (wrapper[1:-1] + '$Hb') + '.smali')
    with open(hb_path, 'w', encoding='utf-8') as fp:
        fp.write(render_hb(wrapper))

    # 调用点:LAUNCHER 优先(必在),Application 可选;双保险
    sites, notes = [], []
    candidates = [('launcher', d) for d in info['launchers']]
    if info['app_class']:
        candidates.append(('app', info['app_class']))
    for kind, desc in candidates:
        path = find_smali_file(decompiled_dir, desc)
        if path is None:
            notes.append(f'{kind} {desc}: smali 不存在,跳过')
            continue
        if not any('onCreate' in ln and ln.strip().startswith('.method')
                   for ln in open(path, encoding='utf-8')):
            super_m = re.search(r'^\.super\s+(\S+)', open(path, encoding='utf-8').read(),
                                re.M)
            if super_m:
                _create_oncreate_override(path, desc, super_m.group(1))
        changed, note = inject_call_site(path, wrapper)
        if changed:
            sites.append({'kind': kind, 'desc': desc, 'path': path})
            notes.append(f'{kind} {desc}: 已注入')
        else:
            notes.append(f'{kind} {desc}: {note}')

    if not sites:
        print('❌ 没有任何可用调用点(LAUNCHER/Application 均缺失或寄存器不安全)', file=sys.stderr)
        return 2

    with open(comp_path, 'w', encoding='utf-8') as fp:
        json.dump({'bridge': BRIDGE_DESC, 'wrapper': wrapper, 'so_name': so_name,
                   'marker': MARKER, 'call_marker': CALL_MARKER,
                   'sites': sites,
                   'generated': [bridge_path, wrapper_path]},
                  fp, ensure_ascii=False, indent=1)

    for n in notes:
        print(f'  · {n}')
    print(f'✅ 注入完成: 2 个新类 + {len(sites)} 个调用点(判决式,标准值不出 so)')
    return 0


def do_clean(decompiled_dir):
    comp_path = os.path.join(decompiled_dir, COMPONENTS_JSON)
    if not os.path.isfile(comp_path):
        print('ℹ️ 无 javacheck-components.json,无残留可清')
        return 0
    with open(comp_path, encoding='utf-8') as fp:
        comp = json.load(fp)

    removed, kept = [], []
    for path in comp.get('generated', []):
        if os.path.isfile(path):
            with open(path, encoding='utf-8') as f:
                if MARKER not in f.read():
                    kept.append(path)          # 无标记 = 用户自己的类,绝不越界(报错十八式纪律)
                    continue
            os.remove(path)
            removed.append(path)

    call_marker = comp.get('call_marker', CALL_MARKER)
    touched = 0
    for site in comp.get('sites', []):
        path = site.get('path')
        if not path or not os.path.isfile(path):
            continue
        with open(path, encoding='utf-8') as f:
            lines = f.read().splitlines()
        kept_lines = [ln for ln in lines if call_marker not in ln]
        if len(kept_lines) != len(lines):
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(kept_lines) + '\n')
            touched += 1

    os.remove(comp_path)
    print(f'✅ clean: 删除 {len(removed)} 个生成类,清理 {touched} 个调用点文件'
          + (f',保留无标记文件 {len(kept)} 个' if kept else ''))
    return 0


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    if argv[0] == 'clean':
        if len(argv) < 2:
            print('用法: inject-javacheck.py clean <解包目录>', file=sys.stderr)
            return 1
        return do_clean(argv[1])

    decompiled_dir = argv[0]
    so_name, wrapper_override = 'nc', None
    i = 1
    while i < len(argv):
        if argv[i] == '--so-name' and i + 1 < len(argv):
            so_name = argv[i + 1]
            i += 2
        elif argv[i] == '--wrapper-name' and i + 1 < len(argv):
            wrapper_override = argv[i + 1]
            i += 2
        else:
            print(f'未知参数: {argv[i]}', file=sys.stderr)
            return 1
    if not os.path.isdir(decompiled_dir):
        print(f'解包目录不存在: {decompiled_dir}', file=sys.stderr)
        return 1
    return do_inject(decompiled_dir, so_name, wrapper_override)


if __name__ == '__main__':
    sys.exit(main())
