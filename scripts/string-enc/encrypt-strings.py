#!/usr/bin/env python3
"""encrypt-strings.py — dex 层字符串常量加密(构建期异或 + 运行期 Java 解密桩)

【这是什么】
把「用户选中类」里 dex 的字符串常量(const-string 字面量)在构建期加密,
运行期由注入的纯 Java 解密桩解密。目标是让 `strings`/静态特征扫描看不到
源码里写死的明文(URL/API key/日志文案等),提高人工逆向成本。

【边界(必须知道)】
  * 加密粒度 = 指令级字面量。只改 `const-string` / `const-string/jumbo`。
  * 字段的字符串值(`static final String S = "x"`)编译后就是 <clinit> 里的
    const-string + sput-object(R8 内联时是每个使用点各一条),**天然被覆盖**,
    不需要为字段写任何专门逻辑。
  * 字段名 / 方法名 / 类名 / 类型描述符属于 dex 结构引用,永不触碰。
  * 注解值(value = "x")不是 const-string 指令,天然不在扫描面。
  * 这是「防静态可见性」,不是密码学安全:密钥流派生材料同在包内,
    懂格式者仍可解。真正的密钥材料请走服务端/白盒方案。

【选类范围】
完全复用 dcc 那套规则解析(scripts/filter/rules-to-filter.py),语法一致:
  精确类名 com.app.MainActivity / com.test.** / com.test.* / com.test*
  activity*(需 --classes) / !排除 / # 注释 / 空行

【硬排除(用户要求:全量通配也不许动)】
即使规则写了 `**`,下列前缀的类一律不加密(系统类与框架依赖):
  android. androidx. android.support. com.android. com.google.android.
  dalvik. java. javax. kotlin. kotlinx. org.jetbrains.
  org.apache. org.json. org.w3c. org.xml. sun.
外加解密桩自身。`!` 排除行在非系统类范围内优先级最高;
命中系统前缀的类无条件硬排除(与 classify 的实际判定顺序一致)。

【算法 v2/S2(与 stub 里的 Java 实现必须逐字节一致,靠对拍测试锁定)】
  seed        : 8 字节随机(secrets.token_bytes(8);--seed-hex 供复现)
  payload     : Base64( offset_be24 || cipher )
                offset = 本构建内该明文的 UTF-8 字节在'全包虚拟密钥流'里的起始下标
  keystream   : splitmix64 现算,O(1) 取第 i 个字节(零表,见 §3.3)
                key_byte(seed, i) = (mix64(seed + (i>>3)*GAMMA) >> ((i&7)*8)) & 0xFF
                cipher[k] = plain[k] ^ key_byte(seed, offset + k)
  stub        : 注入 Lcom/nc/strdec/StrDec;,d(String) 解密(纯 XOR + UTF-8)
  分配器      : 全包按顺序为每条密文分配不重叠区段 [offset, offset+len)

  【与 v1 的关系】v1 运行期每条做 N 次 SHA-256 派生密钥,全包 1.3 万条在
  debuggable 下把冷启动首帧卡死。S2 把密钥"生产"变成纯算术现算(纳秒级),
  全包仅 1 个解密方法、0 张表、只存 8 字节种子。

【幂等】
  * 已加密的类插入了标记注释 `# nc-strdec-encrypted`(注释不进 dex),
    重跑时整类跳过,输出稳定。
  * 桩文件已存在时:解析回其中的 SEED 继续使用,保证旧密文仍可解;
    若不是本工具生成的同名文件则 fail-fast,拒绝覆盖用户代码。

用法:
  encrypt-strings.py <解包目录> <规则文件> [--classes 类列表] \\
                     [--exclude-methods compiled_methods.txt] [--seed-hex HEX]
"""
import argparse
import base64
import importlib.util
import json
import os
import re
import secrets
import sys


_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # scripts/string-enc → 仓库根


def _load_module(name: str, rel_path: str):
    """文件名带连字符,不能常规 import → 与 mark-native.py 同款 importlib 加载。
    (报错三教训:基于 __file__ 的路径在脚本移动后必须重算,这里从本文件位置推算)"""
    path = os.path.join(_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# 规则解析复用 dcc 侧同一脚本(用户要求"语法与 dex2c_rules 完全一致")
_RULES = _load_module('rules_to_filter', 'scripts/filter/rules-to-filter.py')
# smali 目录名约定复用 inject-loadlib 的单一真相(报错七:别处不要另写一份正则)
_INJECT = _load_module('inject_loadlib', 'scripts/inject/inject-loadlib.py')
SMALI_DIR_RE = _INJECT.SMALI_DIR_RE

# ── 解密桩约定 ──────────────────────────────────────────────────────
STUB_DESC = 'Lcom/nc/strdec/StrDec;'
STUB_PKG_DIR = ('com', 'nc', 'strdec')
STUB_FILE = 'StrDec.smali'
STUB_GEN_MARK = '# nc-strdec-gen v2'          # 桩文件内的生成标记(识别"这是我们写的")
# 解密主方法名 —— 「只盯最危险一步」的警报器只管这个方法(见 _check_stub_registers)
STUB_DECRYPT_METHOD = 'd'
STUB_SRC = 'stub-src/StrDec.java'             # 解密桩唯一源码真相(本脚本相对路径)
STUB_D8_JAR = 'tools/d8.jar'                  # 固定版本 D8(报错六教训:工具版本漂移即翻车)
CLASS_MARK = '# nc-strdec-encrypted'          # 已加密类的标记注释(幂等判定)
COMPONENTS_FILE = 'stringenc-components.json'  # 组件标记(报错十八式:元数据 save/restore)

# ── 硬排除:系统类与框架依赖(规则层不可突破) ─────────────────────────
SYSTEM_CLASS_PREFIXES = (
    'android.', 'androidx.', 'android.support.', 'com.android.',
    'com.google.android.', 'dalvik.', 'java.', 'javax.',
    'kotlin.', 'kotlinx.', 'org.jetbrains.',
    'org.apache.', 'org.json.', 'org.w3c.', 'org.xml.', 'sun.',
    # xCrash(爱奇艺 native 崩溃/ANR 捕获库):其 Java 层与 native 层通过 JNI 回调
    # 互相绑定(xcrash.NativeCrashHandler 的 native 方法 + callback),字符串或
    # 类/方法名一旦被加密/改写 → 崩溃捕获失效甚至自身崩溃。属"框架依赖",必须在
    # 规则层之上硬排除(与 kotlin./androidx. 同型)。前缀 'xcrash.' 覆盖其主包。
    'xcrash.',
)

IDX_MAX = (1 << 24) - 1                      # idx/offset 占 3 字节(共享表上限同源)

# ── 无价值串跳过:编译器生成的调试/内联标记(对比实验定性,2026-09) ────
# 背景:用户全量规则加密 3438 类后 app"进不去且无日志",而第三方字符串加密
# 工具同规则正常。解剖两产物发现关键差异:第三方工具内置"跳过名单",保留
# Kotlin/Compose/R8 desugar 编译器自动生成的调试标记串明文(仅 classes15 一个
# dex 就保留 1637 条 $i$f$ + 450 条 $this$ + 87 条 $changed);本工具此前
# 一个不漏全加密。这些串对 app 运行毫无作用(纯编译器/调试器记号),却让
# 解密桩为它们白付一份 keystream 成本与体积。跳过它们:体积更小、启动解密
# 更少,且不存在任何行为风险(没有人会依赖调试标记做业务判断)。
# 命中规则(逐明文串前缀判断,非类名):
#   $i$f$    — Kotlin inline 函数标记($i$f$functionName)
#   $i$a$    — Kotlin inline 匿名对象标记
#   $this$   — Kotlin 扩展/接收者标记($this$forEach 等)
#   $changed — Compose Composable 形参记号($changed / $changed\N 转义形态)
#   $stable  — Compose 稳定性记号
#   $-       — R8/D8 desugaring 合成 lambda 标记($-feat-$-lambda-... 形态)
_SKIP_STRING_PREFIXES = (
    '$i$f$', '$i$a$', '$this$', '$changed', '$stable', '$-',
)


def is_instrumentation_string(plain: str) -> bool:
    """编译器调试/内联标记串判定:命中即跳过加密(保留明文,不占 idx)。"""
    return plain.startswith(_SKIP_STRING_PREFIXES)


# ── 解密桩骨架(纯 Java 编译产物,零表零占位符) ────────────────────────
#
# 【SEED 双锚点注入契约(与 build-stub.sh 共同维护,勿单方面改)】
# build-stub.sh 用哨兵种子 0x5EED000000000000 编译 StrDec.java,d8 的实测行为:
#   ① 种子非 0 → smali 里保留 `.field private static final SEED:J = 0x...L`
#   ② 同时把该常量【内联】到每个使用点(如 `const-wide/high16 v9, 0x...L`)
# 所以种子必须【同时】改写这两处,且数量守恒:
#   只改 .field → 运行期 d() 用的是内联常量,种子没生效;
#   只改内联   → 复用桩时读不回种子,续跑时构建期/运行期不一致。
# 两者不一致的后果:全包字符串乱码(且不是崩溃,是静默错误)。
# 下面 SENTINEL_SEED 是与 build-stub.sh 约定的哨兵值。
SENTINEL_SEED = '0x5eed000000000000L'

_FIELD_SEED_RE = re.compile(
    r'^(?P<indent>[ \t]*)\.field[ \t]+(?P<mid>[^\n]*?\bSEED:J[ \t]*)'
    r'(?:=[ \t]*(?P<val>\S+))?[ \t]*$', re.M)
# 内联常量:d8 视数值大小选 const-wide / const-wide/high16 / const-wide/16 变体
_INLINE_SEED_RE = re.compile(
    r'^(?P<indent>[ \t]*)const-wide(?P<variant>/\w+)?[ \t]+'
    r'(?P<reg>[vp]\d+)[ \t]*,[ \t]*(?P<val>0x[0-9a-fA-F]+L?)[ \t]*(?P<tail>#[^\n]*)?$',
    re.M)


def load_stub_skeleton() -> str:
    """加载 build-stub.sh 产出的桩骨架(无占位符,可直接汇编)。

    骨架来源:build-stub.sh 对 stub-src/StrDec.java 跑 javac → d8 → baksmali
    的产物(仓库内缓存为 stub-src/StrDec.smali)。smali 是中间产物、永不手写;
    改算法只改 StrDec.java,然后重跑 build-stub.sh 刷新缓存。

    本函数只做"骨架完整性"自检:SEED 字段锚点与内联锚点必须都存在且都等于
    哨兵种子(否则说明 build-stub.sh 的哨兵策略被改动,注入契约已失效)。
    """
    tpl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            'stub-src', 'StrDec.smali')
    try:
        with open(tpl_path, encoding='utf-8') as fp:
            tpl = fp.read()
    except OSError as exc:
        raise SystemExit(
            f'❌ 桩骨架缺失: {tpl_path}({exc})\n'
            f'   先运行 scripts/string-enc/build-stub.sh 生成(它把 '
            f'{STUB_SRC} 编译为 smali)。')
    find_stub_seed_anchors(tpl)      # 锚点自检(失败即抛 SystemExit)
    # 防线(报错二十二):骨架必须过参数寄存器自检
    _check_stub_registers(tpl)
    # 防线(报错二十五):类体顶层(非 .method 区)不许出现裸指令。
    # 骨架是编译产物,理论上不会违规;这条兜底拦住任何"把指令写进类体顶层"
    # 的回归(该形态 smali 汇编器报 no viable alternative)。
    in_method = False
    for line in tpl.split('\n'):
        s = line.strip()
        if s.startswith('.method'):
            in_method = True
        elif s == '.end method':
            in_method = False
        elif (in_method is False and s and not s.startswith(('.', '#'))
              and not s.startswith(':')):
            raise SystemExit(
                f'❌ 桩骨架自检失败:类体顶层出现裸指令 ——\n   {line}\n'
                f'   指令只允许出现在 .method .. .end method 之间(报错二十五)。')
    return tpl


def find_stub_seed_anchors(content: str, expect_sentinel: bool = True):
    """按结构定位骨架里的 SEED 锚点。
    返回 (字段行 match, 内联常量 match 列表)。缺失即 fail-fast。

    expect_sentinel=True:要求两处锚点的值都等于哨兵种子(校验"骨架是可信产物")。
    expect_sentinel=False:只要求结构存在(用于注入后的终检,那时值已是真种子)。"""
    fm = _FIELD_SEED_RE.search(content)
    if not fm:
        raise SystemExit(
            '❌ 桩骨架缺少 `.field ... SEED:J = <初值>` 锚点。\n'
            '   d8 在种子为 0 时会把它优化掉 → 无法注入种子。\n'
            '   请重跑 build-stub.sh(它用非 0 哨兵种子编译)。')
    if fm.group('val') is None:
        raise SystemExit(
            '❌ 桩骨架的 SEED 字段没有初值(.field ... SEED:J 无 "= ...")。\n'
            '   同上报错原因:哨兵种子必须非 0,否则 d8 不保留初值。')
    if expect_sentinel and fm.group('val').rstrip('Ll').lower() \
            != SENTINEL_SEED.rstrip('Ll').lower():
        raise SystemExit(
            f'❌ 桩骨架的 SEED 字段初值({fm.group("val")})与哨兵种子'
            f'({SENTINEL_SEED})不一致 —— 骨架不是 build-stub.sh 的可信产物。')
    # 内联锚点:骨架阶段必须存在且等于哨兵;注入后终检只数结构
    inlines = [m for m in _INLINE_SEED_RE.finditer(content)
               if not expect_sentinel
               or m.group('val').rstrip('Ll').lower() == SENTINEL_SEED.rstrip('Ll').lower()]
    if expect_sentinel and not inlines:
        raise SystemExit(
            f'❌ 桩骨架里找不到内联的哨兵种子常量(期望 {SENTINEL_SEED})。\n'
            f'   d8 的常量内联行为可能变了,或骨架与 build-stub.sh 不同步。\n'
            f'   重跑 build-stub.sh;若仍失败,需重审本文件的注入契约。')
    return fm, inlines


def inject_stub_seed(skeleton: str, seed_word: str) -> str:
    """把骨架里的哨兵种子【双锚点同时】改写为真种子。

    seed_word: smali 长整型字面量(如 '0x1a2b3c4d5e6f7a8bL')。
    改写后再次自检:两处锚点都等于真种子、内联锚点数量守恒、骨架行数守恒 ——
    任一不满足即 fail-fast,绝不让"半注入/被截断"的桩进产物(那是静默乱码、
    或下游 apktool 汇编失败,都不在当场暴露,更难查;见报错二十七)。
    """
    fm, inlines = find_stub_seed_anchors(skeleton)
    n_inline = len(inlines)
    n_lines = len(skeleton.split('\n'))
    sentinel = SENTINEL_SEED.rstrip('Ll').lower()
    seed_int = int(seed_word.rstrip('Ll'), 16)

    # 锚点 1:字段初值行(保留缩进,只换值)
    skeleton = skeleton[:fm.start('val')] + seed_word + skeleton[fm.end('val'):]

    # 锚点 2:全部内联常量。d8 可能内联到多处,按其实际出现次数全改。
    # 倒序替换,避免前面的替换使后面的 offset 失效。
    #
    # 【必须整行重建,不能只换字面量 —— 两个坑都在这里(报错二十七)】
    # 坑 A(指令变体):d8 为哨兵种子 0x5eed000000000000 选的变体是
    #   `const-wide/high16`,该形态只接受"低 48 位全为 0"的字面量;真种子是任意
    #   64 位随机数,只换数字会让这条指令非法(smali: Invalid literal value:
    #   Low 48 bits must be zeroed out)。故按新值重选变体:装不下即折回无后缀
    #   `const-wide`(可编码任意 64 位)。
    # 坑 B(文件截断):替换范围只能到【行尾】。m.start()..m.end() 不含换行,
    #   行尾之后的内容必须原样保留 —— 曾经把 m.end() 之后的文本整段丢弃,骨架
    #   被腰斩成 92 行(方法中途 EOF),下游 apktool 报
    #   `mismatched input '' expecting END_METHOD_DIRECTIVE`。
    #   顺带:m.end() 覆盖了行尾的十进制浮点注释(d8 为旧值生成的),它随整段
    #   一起被丢弃,无需单独判断。
    def _fits(variant, value):
        """该指令变体能否编码 value(无后缀 const-wide 恒可)。"""
        if variant == '/high16':
            return (value & 0x0000FFFFFFFFFFFF) == 0
        if variant == '/16':
            return -0x8000 <= value <= 0xFFFF
        return True

    for m in reversed(list(_INLINE_SEED_RE.finditer(skeleton))):
        if m.group('val').rstrip('Ll').lower() != sentinel:
            continue
        variant = m.group('variant') or ''
        op = 'const-wide' if not _fits(variant, seed_int) else 'const-wide' + variant
        line = f"{m.group('indent')}{op} {m.group('reg')}, {seed_word}"
        skeleton = skeleton[:m.start('indent')] + line + skeleton[m.end():]

    # 终检 1:哨兵种子必须一处不剩(残留 = 漏改,运行期会用到旧种子)
    if sentinel in skeleton.lower():
        raise SystemExit(
            f'❌ 桩种子注入终检失败:骨架里仍残留哨兵种子 {SENTINEL_SEED}\n'
            f'   (说明有锚点未被改写;绝不能带着哨兵进产物)')
    # 终检 2:改写前"值等于哨兵的锚点数"必须等于改写后"值等于真种子的锚点数"。
    # 必须用同一个口径(按值数)对比:若拿"所有 const-wide 行数"去数,会把 GAMMA
    # 等无关常量算进来 —— 旧实现在这里恰好与截断互相抵消(截断吃掉 3 条无关
    # const-wide/16 后,1 == 1 照样通过),破损桩因此静默进了产物(报错二十七)。
    _, all_after = find_stub_seed_anchors(skeleton, expect_sentinel=False)
    n_after = sum(1 for m in all_after
                  if m.group('val').rstrip('Ll').lower() == seed_word.rstrip('Ll').lower())
    if n_after != n_inline:
        raise SystemExit(
            f'❌ 桩种子注入终检失败:内联锚点数量从 {n_inline} 变为 {n_after}\n'
            f'   (注入改坏了骨架结构,拒绝写入产物)')
    # 终检 3:结构完整性 —— 注入是逐值替换,骨架行数必须严格守恒。
    # 这一条直接拦住"替换范围越界把文件吞掉"的形态(报错二十七):截断后的骨架
    # 仍能通过锚点/哨兵残留检查,却能通过汇编阶段才炸(方法中途 EOF)。
    if len(skeleton.split('\n')) != n_lines:
        raise SystemExit(
            f'❌ 桩种子注入终检失败:骨架行数从 {n_lines} 变为 '
            f'{len(skeleton.split(chr(10)))} —— 注入吞掉了骨架内容(截断)。\n'
            f'   检查内联锚点的替换范围是否只覆盖到行尾。')
    # 终检 4:字段初值必须确已变为真种子
    fm3, _ = find_stub_seed_anchors(skeleton, expect_sentinel=False)
    if fm3.group('val').rstrip('Ll').lower() != seed_word.rstrip('Ll').lower():
        raise SystemExit(
            f'❌ 桩种子注入终检失败:字段初值为 {fm3.group("val")},'
            f'期望 {seed_word}')
    return skeleton


def read_stub_seed(content: str) -> bytes:
    """从已存在的桩里读回 8 字节种子(续跑/复用桩时用,否则旧密文解不开)。"""
    fm = _FIELD_SEED_RE.search(content)
    if not fm or fm.group('val') is None:
        raise SystemExit('❌ 桩文件缺少 SEED 字段初值,无法复用其种子')
    word = fm.group('val').rstrip('Ll')
    try:
        val = int(word, 16)
    except ValueError:
        raise SystemExit(f'❌ 桩文件的 SEED 初值不是十六进制字面量: {fm.group("val")}')
    return (val & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')



# ── 解密桩自检:参数寄存器不得被当临时槽覆盖(报错二十二) ──────────────
#
# 为什么需要它:桩的 xor 曾把内层循环临时寄存器写成 v14/v15,而 `.registers 16`
# + 双参 `([BI)` 让 p0 恰好落在 v14、p1 落在 v15 ⇒ 指令静默改写形参本身,
# 汇编通过、静态对拍也过(算法对),只有运行期才崩(SIGSEGV/无 FATAL 日志)。
# "文字警告防不住文本级重写,只有机制能"——故把这条不变量做成构建期断言:
# 桩模板展开后,任何一条【写】指令的目标寄存器都不得落在参数寄存器区间内。
_NO_DEST_OPCODES = (
    'invoke-', 'if-', 'goto', 'return', 'throw', 'nop', 'move-exception',
    'monitor-', 'check-cast',          # check-cast 目标即源,不产生新值
)
_DEST_FIRST_RE = re.compile(
    r'^(?P<op>[a-z][a-z0-9/\-]*)'
    r'(?:\s+(?P<first>v\d+|p\d+))?')
_METHOD_HDR_RE = re.compile(
    r'^\.method\b[^\n]*?\b([A-Za-z_$][\w$]*|<init>|<clinit>)?\s*'
    r'\((?P<args>[^)]*)\)[^\n]*$')
_REGS_RE = re.compile(r'^[ \t]*\.(?P<kind>registers|locals)[ \t]+(?P<n>\d+)[ \t]*$')


def _param_reg_count(arg_desc: str, is_static: bool) -> int:
    """方法形参占用的寄存器数(J/D 占 2 个,this 占 1 个)。"""
    n = 0 if is_static else 1
    i = 0
    while i < len(arg_desc):
        c = arg_desc[i]
        if c == 'L':
            end = arg_desc.find(';', i)
            if end < 0:
                return -1
            i = end + 1
            n += 1
        elif c == '[':
            while i < len(arg_desc) and arg_desc[i] == '[':
                i += 1
            if i < len(arg_desc) and arg_desc[i] == 'L':
                end = arg_desc.find(';', i)
                if end < 0:
                    return -1
                i = end + 1
            else:
                i += 1
            n += 1
        elif c in 'JD':
            n += 2
            i += 1
        elif c in 'ZBSCIF':
            n += 1
            i += 1
        else:
            return -1
    return n


def _check_stub_registers(smali_text: str) -> None:
    """构建期断言:桩内无指令把参数寄存器当目标覆盖。违反即 fail-fast。"""
    lines = smali_text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        hdr = _METHOD_HDR_RE.match(line.strip()) if line.strip().startswith('.method') else None
        if not hdr:
            i += 1
            continue
        method = hdr.group(1) or '(anonymous)'
        args = hdr.group('args')
        is_static = bool(re.search(r'\bstatic\b', line))
        nparams = _param_reg_count(args, is_static)
        # 收集方法体到 .end method
        j = i + 1
        body = []
        while j < n and not lines[j].strip() == '.end method':
            body.append(lines[j])
            j += 1
        # 找 .registers / .locals
        # 【易错】两者语义不同(报错二十二 自检曾因此误报):
        #   .registers N → N 是【总寄存器数】(含参数)
        #   .locals N    → N 是【局部寄存器数】,总寄存器数 = N + 参数数
        # 桩由 javac 生成,用的是 .locals;把 .locals 的 N 当总数会导致
        # param_lo 偏小、误报"局部槽覆盖形参"。
        total = None
        for bl in body:
            m = _REGS_RE.match(bl)
            if m:
                n_val = int(m.group('n'))
                total = n_val if m.group('kind') == 'registers' \
                    else n_val + max(nparams, 0)
                break
        if total is None or nparams < 0:
            i = j + 1
            continue
        # 参数寄存器边界(限于 v 编号):p0..pK 映射到 v(total-nparams)..v(total-1)。
        # 注意:这里不再用它拦"写形参"——那会误伤编译器产物(见下方 _param_* 说明)。
        # 保留 total/param_lo 的解析仅为兼容旧行为审计,实际判定见 _param_overwritten_before_use。
        _ = total - nparams
        for bl in body:
            s = bl.strip()
            # 显示跳过:空行 / 指令外元素(.directive)/ label(:x)/ 注释(#)—— 注释里
            # 出现 "aget-byte v14" 这类说明文字不得被当真实指令(否则说明文案会误伤自检)
            if not s or s.startswith(('.', ':', '#')):
                continue
            op = s.split()[0]
            if op.startswith(_NO_DEST_OPCODES):
                continue
            m = _DEST_FIRST_RE.match(s)
            if not m:
                continue
            dst = m.group('first')
            if not dst:
                continue
            # 「警报器」范围(按用户裁决:只盯最危险的那一步):
            #   * 只对【解密主方法 d()】保持 fail-fast —— 它是唯一会调用系统
            #     Base64 解码工具的方法,形参被弄脏 → 解码拿到脏数据
            #     (报错二十二的真身:闪退且无 FATAL 日志)。
            #   * 对 mix64/keyByte 这类【纯算数内部方法】放行 —— 它们不调用任何
            #     外部工具,形参读写是编译器正常产物(如 `seed += ...`),
            #     拦它只会误伤,不带来任何安全性。
            if method != STUB_DECRYPT_METHOD:
                continue
            if dst.startswith('p') or dst.startswith('v'):
                vnum = total - nparams if dst.startswith('p') else int(dst[1:])
                if vnum >= total - nparams:
                    raise SystemExit(
                        f'❌ 解密桩自检失败:{method} 里 `{s}` 以参数寄存器 {dst} 为目标,\n'
                        f'   而 d() 随后还要用这些形参调用系统解码工具 → 运行期会传脏参数\n'
                        f'   (报错二十二:闪退且无 FATAL 日志)。\n'
                        f'   请改用方法内确无依赖的局部寄存器槽。')
        i = j + 1


# ── smali 字符串字面量转义表(与 smali 汇编器的 unescape 对齐) ──────────
_UNESCAPE = {
    'n': '\n', 't': '\t', 'r': '\r', 'b': '\b', 'f': '\f',
    "'": "'", '"': '"', '\\': '\\',
}
_HEX = set('0123456789abcdefABCDEF')

# const-string 指令行:抓缩进 / jumbo / 目标寄存器 / 字面量起始
_INSTR_RE = re.compile(
    r'^(?P<indent>[ \t]*)const-string(?P<jumbo>/jumbo)?[ \t]+'
    r'(?P<dst>v\d+|p\d+)[ \t]*,[ \t]*"(?P<rest>.*)$')

# field 行携带的字符串字面量(R8 把 static final 常量折叠成 @value 注解形态)。
# 例: .field public static final URL:Ljava/lang/String; = "https://x"
# 类型必须以字段名后的 ':' 为锚(否则 [^;\s]+; 会把名字末尾的字符吞进类型)
_FIELD_RE = re.compile(
    r'^(?P<indent>[ \t]*)\.field(?P<mid>.*?)(?P<name>[A-Za-z_$][\w$]*):'
    r'(?P<type>[L\[][^\s]*?;)[ \t]*=[ \t]*"(?P<rest>.*)$')

# 值得加密的字段类型:String 本身,以及 String 数组(元素值同样是明文)
FIELD_STRING_TYPES = ('Ljava/lang/String;', '[Ljava/lang/String;')


def smali_unescape(text: str) -> str:
    """解码 smali 字符串字面量内容(两侧引号已剥掉)。

    识别不了转义时抛 ValueError(调用方跳过该条,绝不猜)——
    宁可漏一条也不静默改错字符串值。"""
    out = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != '\\':
            out.append(ch)
            i += 1
            continue
        i += 1
        if i >= n:
            raise ValueError('结尾孤立反斜杠')
        esc = text[i]
        if esc == 'u':
            if i + 4 >= n:
                raise ValueError('\\u 转义不完整')
            hexs = text[i + 1:i + 5]
            if len(hexs) != 4 or any(c not in _HEX for c in hexs):
                raise ValueError('\\u 转义非 4 位十六进制')
            cp = int(hexs, 16)
            i += 5
            # baksmali 按 UTF-16 code unit 逐个转义:非 BMP 字符(emoji 等)
            # 输出成 \uD83D\uDE00 代理对。必须在这里合并成单个码点,
            # 否则 chr() 产生的孤立代理项后续 .encode('utf-8') 直接炸
            # (报错十九: UnicodeEncodeError: surrogates not allowed)。
            if 0xD800 <= cp <= 0xDBFF:                       # 高代理 → 必须跟低代理
                if i + 1 < n and text[i] == '\\' and text[i + 1] == 'u' \
                        and i + 6 <= n:
                    lo_hexs = text[i + 2:i + 6]
                    if len(lo_hexs) != 4 or any(c not in _HEX for c in lo_hexs):
                        raise ValueError('代理对低半 \\u 转义非法')
                    lo = int(lo_hexs, 16)
                    if not (0xDC00 <= lo <= 0xDFFF):
                        raise ValueError(f'高代理 \\u{cp:04X} 后未跟低代理(孤立代理项)')
                    out.append(chr(0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00)))
                    i += 6
                else:
                    raise ValueError(f'高代理 \\u{cp:04X} 后未跟低代理(孤立代理项)')
            elif 0xDC00 <= cp <= 0xDFFF:
                raise ValueError(f'孤立低代理 \\u{cp:04X}')
            else:
                out.append(chr(cp))
        elif esc in _UNESCAPE:
            out.append(_UNESCAPE[esc])
            i += 1
        else:
            raise ValueError(f'未知转义 \\{esc}')
    return ''.join(out)


def parse_const_string(line: str):
    """解析一条 const-string 指令行。
    返回 (match, literal_text, tail) 或 None(不是该指令/引号不闭合)。"""
    m = _INSTR_RE.match(line)
    if not m:
        return None
    rest = m.group('rest')
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            break
        i += 1
    else:
        return None                                   # 引号不闭合,当异常行跳过
    return m, rest[:i], rest[i + 1:]


def parse_field_string(line: str):
    """解析携带字符串字面量的 .field 行(R8 折叠的 static final 常量)。
    返回 (match, literal_text, tail) 或 None。"""
    m = _FIELD_RE.match(line)
    if not m:
        return None
    if m.group('type') not in FIELD_STRING_TYPES:
        return None                                   # 只处理 String / String[] 字段
    rest = m.group('rest')
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            break
        i += 1
    else:
        return None
    return m, rest[:i], rest[i + 1:]


def _strip_field_literal(line: str, m) -> 'str | None':
    """字段去初值(2026-09-12):`.field ... X:Ljava/lang/String; = "明文"` → `.field ... X:...;`

    只删"初值那一段",字面量之后保留(兼容 R8 的 `# annotations` 尾注与 `.field`
    自身的其它修饰)。无法安全定位(如行尾有引号转义)时返回 None,调用方保持原样。

    为什么不用计划书 §3.4 那种 sub 写法:① 字面量类用 [^"]* 时遇到转义引号会提前
    收尾;② 非贪婪 + 行尾锚点在同一行有多个 等号引号 时会吃掉错的一段。
    这里复用 parse_field_string 已经算好的引号区间,精确到字符。"""
    rest = m.group('rest')                  # 初值所在区间(从第一个 `"` 之后开始)
    lit_len = 0                             # 字面量在 rest 里的长度(可含转义)
    i = 0
    while i < len(rest):
        c = rest[i]
        if c == '\\':
            i += 2
            continue
        if c == '"':
            break
        i += 1
    if i > len(rest):
        return None
    lit_len = i
    if lit_len >= len(rest) or rest[lit_len] != '"':
        return None                         # 引号不闭合
    head = line[:m.start('rest') - 1]       # 去掉开引号(leftover = "   = ")
    tail = rest[lit_len + 1:]               # 闭合引号之后的一切(R8 注解尾注等)
    # 把 "= <可选空白>" 一并去掉(head 形如 '.field ... X:Ljava/lang/String;   = ')
    head = re.sub(r'[ \t]*=[ \t]*$', '', head)
    return head.rstrip() + tail


# ── splitmix64 密钥流(Python 侧参考实现;与 StrDec.java 逐字节一致) ──────
# 【易错点,改这两行前先读】
#  ① Python 的 >> 是算术右移,必须保证操作数是已掩码的非负数(每步 & MASK64);
#     Java 用 >>>(无符号右移),long 溢出天然 = mod 2^64。
#  ② 字节序:b = (w >> ((i & 7) * 8)) & 0xFF —— 低位在前,Java 侧同式。
# 这两条由 scripts/string-enc/tests/test-keystream-crosscheck.sh 逐字节钉死。
MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15
_M1 = 0xBF58476D1CE4E5B9
_M2 = 0x94D049BB133111EB


def _mix64(z: int) -> int:
    z = (z ^ (z >> 30)) & MASK64
    z = (z * _M1) & MASK64
    z = (z ^ (z >> 27)) & MASK64
    z = (z * _M2) & MASK64
    return (z ^ (z >> 31)) & MASK64


def key_byte(seed: int, i: int) -> int:
    """虚拟密钥流第 i 个字节,O(1) 现算(对应 StrDec.keyByte)。"""
    w = _mix64((seed + (i >> 3) * GAMMA) & MASK64)
    return (w >> ((i & 7) * 8)) & 0xFF


def read_seed_bytes() -> bytes:
    """新构建的种子:8 字节随机。"""
    return secrets.token_bytes(8)


def encrypt_payload_v2(seed: int, offset: int, plain: bytes) -> str:
    """v2 明文 → Base64( offset_be24 || cipher ),cipher[k] = plain[k] ^ key_byte(seed, offset+k)。"""
    head = bytes(((offset >> 16) & 0xFF, (offset >> 8) & 0xFF, offset & 0xFF))
    cipher = bytes(p ^ key_byte(seed, offset + k) for k, p in enumerate(plain))
    return base64.b64encode(head + cipher).decode('ascii')


def desc_to_dot(desc: str) -> str:
    """Lcom/x/Y; → com.x.Y"""
    return desc[1:-1].replace('/', '.')


def build_matchers(rules_path: str, classes_file):
    """规则文件 → (include 正则表, exclude 正则表)。语法与 dcc 侧完全一致。"""
    with open(rules_path, encoding='utf-8') as fp:
        raw_rules = [line.strip() for line in fp]

    includes, excludes = [], []
    activity_mode = False
    for rule in raw_rules:
        if not rule or rule.startswith('#'):
            continue
        negate = rule.startswith('!')
        body = rule[1:].strip() if negate else rule
        if not body:
            continue
        if body == 'activity*':
            activity_mode = True
            if not classes_file:
                raise SystemExit('❌ 规则含 activity*,必须提供 --classes 类列表文件')
            for cls in _RULES.expand_activity_keyword(classes_file):
                pat = _RULES.class_rule_to_filter(cls[1:-1], False)
                (excludes if negate else includes).append(re.compile(pat))
            continue
        pat = _RULES.class_rule_to_filter(body, _RULES.has_wildcard(body))
        (excludes if negate else includes).append(re.compile(pat))
    return includes, excludes, activity_mode


def parse_compiled_methods(path: str):
    """compiled_methods.txt → {(类名, 方法名, 原型)}(格式同 §4.2,无箭头)。"""
    result = set()
    with open(path, encoding='utf-8') as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            m = re.match(r'^(L[^;]+;)([^(]+)(\(.*\)\S+)$', line)
            if m:
                result.add((m.group(1), m.group(2), m.group(3)))
    return result


def iter_smali_files(decompiled_dir: str):
    for root, _dirs, files in os.walk(decompiled_dir):
        parts = root[len(decompiled_dir):].lstrip(os.sep).split(os.sep)
        if any(SMALI_DIR_RE.match(p) for p in parts if p):
            for f in files:
                if f.endswith('.smali'):
                    yield os.path.join(root, f)


def class_desc_of(content: str):
    """取 .class 行的类描述符(同 mark-native.py 的取法)。"""
    for line in content.split('\n'):
        if line.startswith('.class'):
            m = re.search(r'L[^;\s]+;', line)
            if m:
                return m.group(0)
    return None


STUB_DOT = STUB_DESC[1:-1].replace('/', '.')

# 已加密条目的形态:const-string 紧跟本桩的 invoke-static(用于续跑时续 offset)。
# 必须同时认 `invoke-static {..}` 与 `invoke-static/range {.. .. ..}` 两种形态
# (报错二十一改注入形态后,/range 是新产物;若这里只认旧形态,max_existing_idx
# 会漏算 → 续跑 offset 从 0 重来 → 共享密钥表区段复用)
_PAYLOAD_RE = re.compile(
    r'const-string(?:/jumbo)?[ \t]+(?:v\d+|p\d+)[ \t]*,[ \t]*"([^"\n]*)"\n'
    r'[ \t]*invoke-static(?:/range)? \{[^}\n]*\}, ' + re.escape(STUB_DESC) + r'->d\(')

# 字段常量回填引用(报错二十四改形态后):<clinit> 里的
#   sget-object vX, 本桩 ->F\d+
# (续跑时字段占用的表区间也要计入,否则新字段 offset 从 0 重来 → 密钥区段复用。
# 旧形态 `= StrDec;->F\d+:` 是报错二十四的非法 FIELD 型 static_value,已废弃,
# 且被 _ILLEGAL_FIELD_INIT_RE 构建期断言拦截。v2 里 F 编号与表 offset 同源递增,
# F(\d+) 读出的编号本身即"该字段占用的下一个 offset 下界"——字段名在分配时
# 用占用前的 offset 命名,故引用计数语义 = offset+len 由分配器统一维护)
_FIELD_REF_RE = re.compile(
    # 回填引用形态(报错二十四):<clinit> 里的 sget-object vX, StrDec;->FNNNNNN
    r'sget-object[ \t]+(?:v\d+|p\d+),[ \t]*' + re.escape(STUB_DESC) + r'->F(\d+):')

# 非法形态断言(报错二十四):.field 初值绝不允许是 StrDec 字段引用。
# 该形态会被 smali 汇编成 FIELD 型(0x19) encoded static_value —— dex 规范
# 不允许的初值类型,ART 类初始化阶段(字节码执行之前)即失败 → 秒闪退且无日志。
_ILLEGAL_FIELD_INIT_RE = re.compile(
    r'^[ \t]*\.field[^\n]*=[ \t]*' + re.escape(STUB_DESC) + r'->F\d+:', re.M)

# 字段去初值断言(2026-09-12):目标类的 String/String[] 字段初值绝不允许是
# 明文字面量 —— 否则 `strings` 扫产物照样命中(本次改动的存在理由)。
# 只扫"我们处理过的类"(含 CLASS_MARK)与解密桩自身:没被规则命中的类(硬排除的
# androidx/kotlin 等)本就不归本模块管,不能拿它们的字段去 fail 构建。
# 桩自身的 `.field ... SEED:J` 是 long,不在扫描面内。
_ILLEGAL_FIELD_LITERAL_RE = re.compile(
    r'^[ \t]*\.field[^\n]*[A-Za-z_$][\w$]*:(?:Ljava/lang/String;|\[Ljava/lang/String;)'
    r'[ \t]*=[ \t]*"', re.M)


def _scope_allows_field_scan(content: str) -> bool:
    """该文件是否属于"本模块的加密面"(据此决定字段初值断言是否适用)。"""
    return CLASS_MARK in content or STUB_DESC in content


def is_system_class(cls_dot: str) -> bool:
    """系统类/框架依赖前缀判定(带点号前缀,不误伤 androidXxx 这种同前缀类)。"""
    return cls_dot.startswith(SYSTEM_CLASS_PREFIXES)


def classify(cls_dot: str, cls_desc: str, includes, excludes) -> str:
    """给类定性:no-match / system / excluded / stub / target。
    判定顺序:未命中 include → system(硬排除,规则层不可突破)→ stub →
    用户 ! 排除 → target。system 与 excluded 结果同为不加密,仅日志统计
    口径不同:命中系统前缀的类计入 skipped_system(即使用户 ! 排除行也
    拦不住硬排除的优先地位)。"""
    if not any(r.search(cls_desc) for r in includes):
        return 'no-match'
    if is_system_class(cls_dot):
        return 'system'
    if cls_dot == STUB_DOT:
        return 'stub'
    if any(r.search(cls_desc) for r in excludes):
        return 'excluded'
    return 'target'


def max_existing_idx(content: str) -> int:
    """v2: 已加密类里占用过的最大表区间末尾(续跑时接着分配,避免密钥区段复用)。
    同时扫两类形态:指令密文(_PAYLOAD_RE)与回填引用(_FIELD_REF_RE)。
    返回值语义 = "下一个可用 offset 下界"(最大 offset + len)。"""
    biggest = -1
    for m in _PAYLOAD_RE.finditer(content):
        try:
            raw = base64.b64decode(m.group(1), validate=True)
        except Exception:
            continue
        if len(raw) >= 3:
            off = int.from_bytes(raw[:3], 'big')
            biggest = max(biggest, off + (len(raw) - 3))
    for m in _FIELD_REF_RE.finditer(content):
        biggest = max(biggest, int(m.group(1), 10))
    return biggest


def find_stub_path(decompiled_dir: str):
    """在 smali*/ 里找桩文件(只有解包目录下、且位于桩包路径中的才算)。"""
    for root, _dirs, files in os.walk(decompiled_dir):
        parts = root[len(decompiled_dir):].lstrip(os.sep).split(os.sep)
        if not any(SMALI_DIR_RE.match(p) for p in parts if p):
            continue
        if STUB_FILE in files and root.endswith(os.path.join(*STUB_PKG_DIR)):
            return os.path.join(root, STUB_FILE)
    return None


def read_existing_salt(decompiled_dir: str):
    """已存在且是本工具生成的桩 → 复用其 SEED(否则旧密文解不开)。
    返回 (seed_bytes 或 None, 是否需要写桩)。同名非本工具文件 → fail-fast。"""
    stub_path = find_stub_path(decompiled_dir)
    if not stub_path:
        return None, True
    with open(stub_path, encoding='utf-8') as fp:
        content = fp.read()
    if STUB_GEN_MARK not in content:
        raise SystemExit(f'❌ 已存在同名类但非本工具生成,拒绝覆盖: {stub_path}\n'
                         f'   请改名或移走用户的 {STUB_DESC} 后重试')
    return read_stub_seed(content), False


def _pick_smali_root(decompiled_dir: str) -> str:
    """桩落在哪个 smali 目录:优先 smali/,否则第一个 smali*/。"""
    preferred = os.path.join(decompiled_dir, 'smali')
    if os.path.isdir(preferred):
        return preferred
    for name in sorted(os.listdir(decompiled_dir)):
        if SMALI_DIR_RE.match(name) and os.path.isdir(os.path.join(decompiled_dir, name)):
            return os.path.join(decompiled_dir, name)
    raise SystemExit(f'❌ 解包目录下找不到 smali/ 或 smali_classes*/ : {decompiled_dir}')


def write_components_stamp(decompiled_dir: str, cls_desc: str) -> str:
    """记录本次注入的组件(类名 + 源文件路径)。

    报错十八教训:流水线中途会丢失信息(回编降级抹掉 dex 版本),必须在丢失前 save。
    这里同理 —— apktool 重打包会重新分派 dex 号,唯一稳定的定位依据是
    "描述符 + 源文件路径"对。落盘后,`clean` 子命令可长期正确清理残留的桩类
    (例如本次运行一条都没加密、旧桩却还在)。"""
    root = _pick_smali_root(decompiled_dir)
    payload = {
        'version': 1,
        'classes': [{
            'desc': cls_desc,
            'src': os.path.relpath(
                os.path.join(root, *STUB_PKG_DIR, STUB_FILE), decompiled_dir),
        }],
    }
    path = os.path.join(decompiled_dir, COMPONENTS_FILE)
    with open(path, 'w', encoding='utf-8') as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
        fp.write('\n')
    return path


def clean_components(decompiled_dir: str) -> int:
    """按组件标记删除残留的注入物(解密桩)。幂等,清完删标记文件。

    只删标记里登记的路径,且要求两者同时满足「路径在本解包目录内」+
    「文件内容带本工具生成标记」—— 绝不误删用户自己的类。

    fail-fast(报错二十):删桩前先扫全解包目录,若存在仍引用桩的已加密类
    (CLASS_MARK + ->d( / ->F\\d+: 引用),说明上一轮加密产物没被恢复/重建,
    此时删桩会留下半加密目录 → 汇编失败或运行期 NoClassDefFoundError。
    正常流水线每次全新解包不会触发;本地反复调试会踩,拒绝优于静默坏产物。"""
    path = os.path.join(decompiled_dir, COMPONENTS_FILE)
    if not os.path.isfile(path):
        return 0
    # 半加密目录探测:带 CLASS_MARK 且引用本桩的类
    tainted = []
    for cls_path in iter_smali_files(decompiled_dir):
        try:
            with open(cls_path, encoding='utf-8') as fp:
                content = fp.read()
        except OSError:
            continue
        if CLASS_MARK in content and (STUB_DESC + '->d(' in content
                                      or _FIELD_REF_RE.search(content)):
            tainted.append(cls_path)
    if tainted:
        sample = os.path.relpath(tainted[0], decompiled_dir)
        raise SystemExit(
            f'❌ 解包目录存在仍引用解密桩的已加密类({len(tainted)} 个,如 {sample}),\n'
            f'   删除桩会留下半加密目录。请重新解包(全新 mktemp 目录)或先用 git '
            f'恢复原始 smali,\n   再跑本命令。加密类必须在桩存在的前提下进产物。')
    with open(path, encoding='utf-8') as fp:
        payload = json.load(fp)
    root_abs = os.path.abspath(decompiled_dir)
    removed = 0
    for entry in payload.get('classes', []):
        target = os.path.abspath(os.path.join(decompiled_dir, entry.get('src', '')))
        if not target.startswith(root_abs + os.sep):
            continue                                # 标记被篡改 → 绝不越界删除
        if not os.path.isfile(target):
            continue
        with open(target, encoding='utf-8') as fp:
            if STUB_GEN_MARK not in fp.read():
                continue                            # 不是我们的文件 → 不删
        os.remove(target)
        removed += 1
    os.remove(path)
    return removed


def write_stub(decompiled_dir: str, seed: bytes) -> str:
    """写 v2/S2 解密桩。

    S2 的桩是构建期编译产物(build-stub.sh 出的骨架),注入只有一件事:
    把骨架里的哨兵种子替换为本次构建的 8 字节真种子(双锚点同时改)。
    没有 KEYS 表、没有 <clinit>、没有字段回填链 —— 这些在 S2 里全部不存在。

    seed: 8 字节。
    """
    if len(seed) != 8:
        raise SystemExit(f'❌ 内部错误:种子必须是 8 字节,收到 {len(seed)} 字节')
    root = _pick_smali_root(decompiled_dir)
    stub_dir = os.path.join(root, *STUB_PKG_DIR)
    os.makedirs(stub_dir, exist_ok=True)
    stub_path = os.path.join(stub_dir, STUB_FILE)

    skeleton = load_stub_skeleton()
    seed_word = f'0x{int.from_bytes(seed, "big"):016x}L'
    content = inject_stub_seed(skeleton, seed_word)

    # 生成标记(非注释行的行首注释即可,注释不进 dex)。必须存在:
    # 续跑时靠它区分"本工具生成的桩"与"用户同名类",决定是复用还是拒绝。
    content = content + f'\n{STUB_GEN_MARK}\n'
    if STUB_GEN_MARK not in content:
        raise SystemExit('❌ 解密桩渲染终检失败:缺少生成标记')
    # 终检:哨兵种子绝不许进产物(否则运行期与构建期密钥流不一致 → 全包乱码)
    if SENTINEL_SEED.rstrip('Ll').lower() in content.lower():
        raise SystemExit('❌ 解密桩渲染终检失败:产物残留哨兵种子')
    with open(stub_path, 'w', encoding='utf-8') as fp:
        fp.write(content)
    return stub_path


def process_file(path: str, cls_desc: str, includes, excludes,
                 exclude_methods, seed: int, next_off: int):
    """就地加密一个 .smali 文件。返回 (改动字符串数, 新 next_off, field_backfills)。

    S2: next_off 是全包虚拟密钥流的下一个可用 offset;每条密文按需消耗
    offset..offset+len 区段,分配器保证不重叠。种子是唯一的构建期密钥材料。
    field_backfills: [{owner_cls, field, type, payload}] —— R8 折叠的
    static final String 常量,初值保持明文,值由 <clinit> 运行期回填(报错二十四/D4)。
    """
    with open(path, encoding='utf-8') as fp:
        content = fp.read()
    if CLASS_MARK in content:
        # 幂等:整类已处理。但仍要把它占用的区段计入,续跑时不重复分配
        return 0, max(next_off, max_existing_idx(content)), []

    lines = content.split('\n')
    out = []
    cur_method = None
    hits = 0
    idx = next_off
    field_backfills = []      # 报错二十四/D4:<clinit> 回填登记
    li = 0
    n_lines = len(lines)
    while li < n_lines:
        line = lines[li]
        li += 1
        stripped = line.strip()
        if stripped.startswith('.method'):
            # 同 mark-native.py:名字取括号前紧邻一段,防参数里嵌方法引用的贪婪误判
            m = re.match(r'\.method\s+(.*\S)\s*(\(.*\)\S+)\s*$', stripped)
            if m:
                toks = m.group(1).split()
                cur_method = (toks[-1], m.group(2))
            else:
                cur_method = None
            out.append(line)
            continue
        if stripped == '.end method':
            cur_method = None
            out.append(line)
            continue

        # R8 折叠的 static final String 常量: .field ... = "明文"
        # (报错二十四)字段初值【保持原字面量不动】—— 绝不允许改成
        # `= StrDec;->FNNNNNN` 引用形态:那会被汇编成 FIELD 型(0x19)
        # encoded static_value,dex 规范不允许 → ART 类初始化阶段
        # (字节码执行之前)即失败,秒闪退且无任何日志。
        # 明文的"隐藏"改由回填实现:在所属类 <clinit> 里注入
        # sget-object(桩字段) + sput-object(本字段),运行期用解密结果
        # 覆盖字面量初值。桩自身 <clinit> 填 F 字段用的就是同一套合法形态。
        fparsed = parse_field_string(line)
        if fparsed and cur_method is None:
            fm, fliteral, ftail = fparsed
            try:
                fplain = smali_unescape(fliteral)
            except ValueError as exc:
                print(f'⚠️ 跳过无法安全解析的字段字面量({exc}): {path}', file=sys.stderr)
                out.append(line)
                continue
            if idx > IDX_MAX:
                raise SystemExit(f'❌ 加密字符串数超过 {IDX_MAX}(idx 3 字节上限),请缩小规则范围')
            if is_instrumentation_string(fplain) or not fplain:
                # 编译器调试/内联标记:保留明文字面量
                # 空串:无信息量,且桩对 3 字节 payload 走"原样返回"兜底会返回
                # Base64 串本身(语义错误)→ 一律跳过,不进加密面
                out.append(line)
                continue
            fenc = fplain.encode('utf-8')
            # 【报错二十四/D4 + 字段去初值(2026-09-12)】
            # 初值从"明文字面量"改为"无初值":明文不再出现在任何字段声明里,
            # `strings` 扫产物对字段值零命中。字段值仍由 <clinit> 回填链写入
            # (inject_clinit_backfills),链里含 intern(),是字段值的唯一来源。
            #
            # 【与报错二十四的区别(为什么这次允许去初值)】
            # 报错二十四的非法形态是 `.field ... = StrDec;->FNNNNNN`(引用型
            # encoded static_value,FIELD 型 0x19)—— dex 规范不允许。而"无初值"
            # 是 STRING 型初值 offset=0(NO_INDEX),dex 规范明确允许(static
            # final 字段由 <clinit> 赋值是 javac 的常规产物),两者机制不同。
            # 注意:这仍属静态数据区改写,只有 `apktool b` 真汇编 + androguard
            # 读回才能证明合法 —— 冒烟测试⑨/断言 A9 就是干这个的(报错二十四
            # "汇编器宽容 ≠ 产物合法"教训)。
            #
            # 【幂等】初值已去掉的行不匹配 parse_field_string(需要 '= "..."'),
            # 故重跑时自然不重复回填;代价是"初值永远拆不回明文"——这正是本改动
            # 的意图(明文不该留在产物里)。用 git 恢复源码重跑才是重回明文的正路。
            new_field = _strip_field_literal(line, fm)
            if new_field is None:
                print(f'⚠️ 字段行形态无法安全去初值,保持原样: {path}', file=sys.stderr)
                out.append(line)
                continue
            out.append(new_field)
            field_backfills.append({
                'owner_cls': cls_desc,            # Lcom/x/Y; 形式
                'field': fm.group('name'),
                'type': fm.group('type'),
                'payload': encrypt_payload_v2(seed, idx, fenc),
            })
            idx += len(fenc)
            hits += 1
            continue

        excluded_by_dex2c = bool(
            cur_method and (cls_desc, cur_method[0], cur_method[1]) in exclude_methods)

        # 已加密条目(解密桩可能来自上一次运行)→ 跳过,并续用表区段,
        # 避免把密文当明文再加密一次
        if STUB_DESC + '->d(' in line:
            out.append(line)
            midx = max_existing_idx(line + '\n')
            if midx >= 0:
                idx = max(idx, midx)
            continue

        parsed = parse_const_string(line)
        if not parsed:
            out.append(line)
            continue
        # 逐行前瞻防二次加密(报错二十式双保险):即使类标记被外部工具删掉,
        # 密文 const-string 的下一行必是本桩的 invoke-static ...->d(...),
        # 命中即连同密文行原样保留(与上方 ->d( 分支同样的续 offset 语义)
        if li < n_lines and STUB_DESC + '->d(' in lines[li]:
            out.append(line)
            midx = max_existing_idx(line + '\n' + lines[li] + '\n')
            if midx >= 0:
                idx = max(idx, midx)
            continue
        if excluded_by_dex2c:
            out.append(line)                            # 该方法将被 dex2c 抽走 → 不浪费体积
            continue

        m, literal, tail = parsed
        try:
            plain = smali_unescape(literal)
        except ValueError as exc:
            print(f'⚠️ 跳过无法安全解析的字符串({exc}): {path}', file=sys.stderr)
            out.append(line)
            continue

        enc = plain.encode('utf-8')
        if idx + len(enc) > IDX_MAX + 1:
            raise SystemExit(f'❌ 加密字符串总字节数超过密钥流区段上限 {IDX_MAX + 1},'
                             f'请缩小规则范围')
        if is_instrumentation_string(plain) or not enc:
            # 编译器调试/内联标记:保留明文 const-string(见常量区说明)
            # 空串:无信息量,且桩对 3 字节 payload 会走"原样返回"兜底,
            # 把 Base64 串本身当明文返回(语义错误)→ 一律跳过
            out.append(line)
            continue

        payload = encrypt_payload_v2(seed, idx, enc)
        jumbo = m.group('jumbo') or ''
        indent = m.group('indent')
        dst = m.group('dst')
        out.append(f'{indent}const-string{jumbo} {dst}, "{payload}"{tail}')
        # 寄存器宽度陷阱(报错二十一):const-string 是 21c 格式(8 位寄存器,
        # v0–v255),而 invoke-* 是 35c 格式(寄存器列表仅 4 位,上限 v15)。
        # 原 const-string 的目标寄存器可合法取到 v16+(大方法/Compose),或写成
        # pN 而换算后编号 ≥16 → 直接 {dst} 会被 smali 汇编器拒绝,整个重打包
        # 失败("Invalid register: vNN. Must be between v0 and v15" /
        # "The maximum allowed register in this context is list of registers is v15")。
        # 统一用 /range:单寄存器 range 恒连续、dex 中同为 3 个 code unit(无体积
        # 代价),且对 v/p 两种写法都合法 → 无需解析 .registers/.locals 做换算。
        out.append(f'{indent}invoke-static/range {{{dst} .. {dst}}}, '
                   f'{STUB_DESC}->d(Ljava/lang/String;)Ljava/lang/String;')
        out.append(f'{indent}move-result-object {dst}')
        idx += len(enc)                     # 消费对应表区段(不重叠分配)
        hits += 1

    if hits == 0:
        # 没有新加密,但可能只命中了"已加密条目跳过"分支(类标记丢失 +
        # 三行形态)—— 此时 idx 已被续到旧密文之后,必须带回去,
        # 否则续跑时新条目从 0 分配 → 密钥区段复用(报错二十式)
        return 0, max(next_off, idx), []

    # 插幂等标记注释(注释不进 dex)
    final = []
    marked = False
    for ln in out:
        final.append(ln)
        if not marked and ln.lstrip().startswith('.class'):
            final.append(f'{CLASS_MARK} (do not remove)')
            marked = True
    with open(path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(final))
    return hits, idx, field_backfills


def inject_clinit_backfills(path: str, backfills) -> bool:
    """报错二十四/D4:在 path 所属类的 <clinit> 末尾(return-void 之前)注入:

        const-string v0, "<密文>"
        invoke-static/range {v0 .. v0}, Lcom/nc/strdec/StrDec;->d(...)...
        move-result-object v0
        sput-object v0, <owner>;-><field>:<type>

    为什么必须回填而不能直接改初值:
      static final String 的初值在 dex 里是【字符串常量引用】,若把初值改成
      密文,ART 不会自动解密 → 业务读到密文(错值,且不报错)。而 FIELD 型
      0x19 static_value 直接指向本桩字段在 ART 类初始化时会秒闪退且无日志
      (报错二十四)。唯一合法形态就是"初值保持明文 + <clinit> 运行期覆盖"。

    S2 形态比 v1 更轻: 不再需要每个字段一个桩字段 FNNNNNN,密文直接内联在
    <clinit> 的 const-string 里 —— 桩里零字段、零表。

    <clinit> 不存在则新建(.locals 1,只用 v0,恒在 21c/35c 上限内)。
    返回是否发生了注入。"""
    with open(path, encoding='utf-8') as fp:
        content = fp.read()

    lines = content.split('\n')
    clinit_idx = None          # '.method static constructor <clinit>()V' 行号
    clinit_end = None
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('.method') and 'constructor' in s and '<clinit>' in s:
            clinit_idx = i
            for j in range(i + 1, len(lines)):
                if lines[j].strip() == '.end method':
                    clinit_end = j
                    break
            break
    has_clinit = clinit_idx is not None and clinit_end is not None

    # 回填体:全部走 v0(自依赖链,任何 <clinit> 都容得下一个 v0)
    fill_lines = []
    for bf in backfills:
        payload = bf['payload']
        ty = bf['type']
        fill_lines.append(f'    const-string v0, "{payload}"')
        fill_lines.append(f'    invoke-static/range {{v0 .. v0}}, '
                          f'{STUB_DESC}->d(Ljava/lang/String;)Ljava/lang/String;')
        fill_lines.append('    move-result-object v0')
        # 【intern (2026-09-12)】字段去初值后,常量的 interned 实例来自这里,
        # 必须保持"解密结果 == 编译期字面量"的引用语义(历史 §3.7.4 曾依赖它)。
        fill_lines.append('    invoke-virtual {v0}, '
                          'Ljava/lang/String;->intern()Ljava/lang/String;')
        fill_lines.append('    move-result-object v0')
        fill_lines.append(f'    sput-object v0, {bf["owner_cls"]}->{bf["field"]}:{ty}')

    if has_clinit:
        # <clinit> 的 .locals/.registers 至少要能容纳 v0
        for j in range(clinit_idx, clinit_end):
            mm = re.match(r'[ \t]*\.(?P<kind>registers|locals)[ \t]+(?P<n>\d+)[ \t]*$',
                          lines[j])
            if mm and int(mm.group('n')) < 1:
                lines[j] = re.sub(r'\.(?P<k>registers|locals)[ \t]+\d+',
                                  lambda mo: f'.{mo.group("k")} 1', lines[j], count=1)
                break
        insert_at = clinit_end
        for j in range(clinit_end - 1, clinit_idx, -1):
            if lines[j].strip() == 'return-void':
                insert_at = j
                break
        lines[insert_at:insert_at] = fill_lines
    else:
        # 无 <clinit> → 追加一个最小的(放在最后一个 .method 之后、类体末尾)
        last_end = 0
        for j, ln in enumerate(lines):
            if ln.strip() == '.end method':
                last_end = j
        new_clinit = ['', '.method static constructor <clinit>()V', '    .locals 1', '']
        new_clinit += fill_lines
        new_clinit += ['', '    return-void', '.end method']
        lines[last_end + 1:last_end + 1] = new_clinit

    with open(path, 'w', encoding='utf-8') as fp:
        fp.write('\n'.join(lines))
    return True


def main():
    argv = sys.argv[1:]
    # 子命令:clean(按组件标记清残留,幂等) | encrypt(默认)
    if argv and argv[0] == 'clean':
        if len(argv) != 2:
            print('用法: encrypt-strings.py clean <解包目录>', file=sys.stderr)
            return 1
        removed = clean_components(argv[1])
        print(f'✅ 清理残留解密桩: {removed} 个')
        return 0

    ap = argparse.ArgumentParser(
        description='dex 层字符串常量加密(按 dcc 同款规则选类,注入 Java 解密桩)')
    ap.add_argument('decompiled', help='apktool 解包目录(含 smali*/)')
    ap.add_argument('rules', help='类名规则文件(语法同 dex2c_rules)')
    ap.add_argument('--classes', help='activity* 展开所需类列表(make-filter-from-apk 产物)')
    ap.add_argument('--exclude-methods',
                    help='compiled_methods.txt:这些方法将被 dex2c 抽走,跳过不加密')
    ap.add_argument('--seed-hex', help='固定种子(8 字节 hex),仅供测试/复现')
    ap.add_argument('--quiet', action='store_true', help='只打错误')
    args = ap.parse_args(argv)

    if not os.path.isdir(args.decompiled):
        print(f'❌ 解包目录不存在: {args.decompiled}', file=sys.stderr)
        return 1
    if not os.path.isfile(args.rules):
        print(f'❌ 规则文件不存在: {args.rules}', file=sys.stderr)
        return 1

    includes, excludes, activity_mode = build_matchers(args.rules, args.classes)
    if not includes:
        print('❌ 规则文件没有产生任何包含规则(只有排除/注释?)', file=sys.stderr)
        return 1

    exclude_methods = set()
    if args.exclude_methods:
        if not os.path.isfile(args.exclude_methods):
            print(f'❌ --exclude-methods 文件不存在: {args.exclude_methods}', file=sys.stderr)
            return 1
        exclude_methods = parse_compiled_methods(args.exclude_methods)

    if args.seed_hex:
        try:
            seed = bytes.fromhex(args.seed_hex)
        except ValueError:
            print('❌ --seed-hex 不是合法 hex', file=sys.stderr)
            return 1
        if len(seed) != 8:
            print('❌ --seed-hex 必须是 8 字节(16 位 hex)', file=sys.stderr)
            return 1
    else:
        seed = secrets.token_bytes(8)

    # 幂等/复用:已有桩则沿用其 seed(否则旧密文解不开)
    existing_seed, need_write_stub = read_existing_salt(args.decompiled)
    if existing_seed is not None:
        seed = existing_seed

    # S2:密钥流是 O(1) 现算的,不存在"表"也就没有表长/扩容概念;
    # 全局 offset 只是"已分配区段"的水位线(每条密文按需消耗 len 字节)。
    seed_int = int.from_bytes(seed, 'big')

    total_str, total_cls, idx = 0, 0, 0
    skipped_system = skipped_excluded = skipped_stub = 0
    for path in sorted(iter_smali_files(args.decompiled)):
        with open(path, encoding='utf-8') as fp:
            content = fp.read()
        cls_desc = class_desc_of(content)
        if not cls_desc:
            continue
        cls_dot = desc_to_dot(cls_desc)
        verdict = classify(cls_dot, cls_desc, includes, excludes)
        if verdict == 'no-match':
            continue
        if verdict == 'system':
            skipped_system += 1
            continue
        if verdict == 'excluded':
            skipped_excluded += 1
            continue
        if verdict == 'stub':
            skipped_stub += 1
            continue
        n, idx, backfills = process_file(path, cls_desc, includes, excludes,
                                         exclude_methods, seed_int, idx)
        if n:
            total_str += n
            total_cls += 1
        if backfills:
            # 报错二十四/D4:字段初值保持明文,值由 <clinit> 运行期回填。
            # process_file 已重写并加幂等标记,这里重读注入,两条链互不干扰。
            inject_clinit_backfills(path, backfills)

    if need_write_stub and total_str > 0:
        stub_path = write_stub(args.decompiled, seed)
        stamp = write_components_stamp(args.decompiled, STUB_DESC)
        if not args.quiet:
            print(f'  🔧 注入解密桩: {os.path.relpath(stub_path, args.decompiled)}'
                  f' (组件标记 {os.path.basename(stamp)})')
    # 复用桩的场景 S2 无需任何字段合并:桩里只有种子,续跑时种子原样保留,
    # 新密文用同一种子 + 新区段即可解 —— 这正是 S2 相对 v1/S1 的幂等优势。

    # 报错二十四 构建期防线:任何产物 .field 初值都不允许是 StrDec 字段引用
    # (FIELD 型 0x19 encoded static_value,ART 类初始化即失败 → 秒闪退无日志)。
    # 此前版本曾把字段初值改写成该形态且 apktool 编译器宽容放行,教训:
    # 汇编器宽容 ≠ 产物合法。每次跑完都复读全包做硬断言,违反即 fail-fast。
    illegal = []
    literal = []
    for cls_path in iter_smali_files(args.decompiled):
        try:
            with open(cls_path, encoding='utf-8') as fp:
                c = fp.read()
        except OSError:
            continue
        if _ILLEGAL_FIELD_INIT_RE.search(c):
            illegal.append(cls_path)
        elif _scope_allows_field_scan(c) and _ILLEGAL_FIELD_LITERAL_RE.search(c):
            literal.append(cls_path)
    if illegal:
        sample = os.path.relpath(illegal[0], args.decompiled)
        raise SystemExit(
            f'❌ 构建期断言失败:{len(illegal)} 个文件出现非法字段初值形态 '
            f'(.field ... = {STUB_DESC}->F...):\n   {sample}\n'
            f'   该形态会被汇编成 FIELD 型(0x19) static_value,ART 类初始化即闪退'
            f'(报错二十四)。字段常量回填必须走 <clinit> 的 sget/sput 链。')
    if literal:
        sample = os.path.relpath(literal[0], args.decompiled)
        with open(literal[0], encoding='utf-8') as fp:
            hit = _ILLEGAL_FIELD_LITERAL_RE.search(fp.read())
        raise SystemExit(
            f'❌ 构建期断言失败:{len(literal)} 个文件的 String 字段初值仍是字面量 '
            f'(去初值漏改):\n   {sample}\n   {hit.group(0).strip() if hit else ""}\n'
            f'   该初值会原样进 dex 字符串池,`strings` 一扫即命中字段值明文 —— '
            f'字段分支必须走 _strip_field_literal 去掉初值 + <clinit> 回填。')

    if not args.quiet:
        if activity_mode:
            print('ℹ️ 规则含 activity*,已按 --classes 展开')
        if skipped_system:
            print(f'ℹ️ 命中规则但被硬排除(系统/框架依赖类)跳过: {skipped_system} 个类')
        if skipped_excluded:
            print(f'ℹ️ 被用户 ! 规则排除跳过: {skipped_excluded} 个类')
        if skipped_stub:
            print(f'ℹ️ 解密桩自身跳过: {skipped_stub} 个')
        print(f'✅ 字符串加密完成: {total_str} 条 / {total_cls} 个类'
              f' (seed={seed.hex()}, '
              f'桩={"已注入" if (need_write_stub and total_str) else "复用/未用"})')
        if total_str == 0:
            print('⚠️ 没有任何字符串被加密 —— 检查规则是否命中(系统/依赖类会被硬排除)',
                  file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
