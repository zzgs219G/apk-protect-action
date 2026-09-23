#!/usr/bin/env python3
"""anti-diff.py — 防对比混淆(anti-diff)模块 · MVP(变换 A+B+C)

【这是什么】
攻击者手上同时有原版 APK 和处理过的 APK 时,反编译两份做逐文件 diff,
被抽/被改的类"稀疏、可定位"——本模块给全量 smali 加一层**零语义无损**的
结构噪声(标签重命名 / 类内块重排 / 方法入口垃圾指令),让 diff 全红,
像"同一 App 的不同编译版本",而不是"被精确动过手"。

【红线(开发文档 §2.2,绝不能破)】
  * 不改类名 / 方法名 / 字段名 / 方法签名 / 字段类型 / 字符串内容
  * 不注入死代码 / 死方法 / nop 填充 / 控制流平坦化
  * 只动 smali 文本层"注释、标签名、块顺序、入口垃圾指令"——
    dex 语义(方法/字段/类型/字符串表引用)一项都不许变

【三个变换(MVP)】
  A 跳转标签重命名:方法内 :label_name 全部换成确定性随机名(:nc3f9 风格)。
    baksmali 生成的标签名局部唯一,换成等价随机名后 diff 必变,语义零变。
    跳过 <init>/<clinit>(执行顺序敏感,sigcheck/dcc 依赖)。
  B 类内块重排:一个类的多个 .method/.field 块按确定性随机序重排。
    跳过 <init>/<clinit>(必须紧跟 .class 声明,不能挪)与含 .annotation 的块。
    smali 允许方法任意顺序,DEX 无序;重排只改文本,引用全部按描述符解析。
  D 局部寄存器重编号(覆盖增强):方法内局部寄存器 v0..vN 做确定性随机
    置换,dex 层每条指令的寄存器号真实变化,规则归一化无法抹平。
    硬约束(报错三十三):低/高双域(4-bit 指令只能寻址 v0..v15),
    /range 连续区间成员锁定不动,wide 对作整体单元、永不跨域拆分,
    参数 pN 区永不参与,恒等置换跳过;语义等价由"读/写同步替换"保证。
  E 条件反转 + 跳转链(阶段 2 增强):方法内的条件分支做"反折"——
      if-eqz vX, :L      →    if-nez vX, :nc新
                                goto :L
                              :nc新
    生成的指令真实落进 dex(if+goto 都是真实执行流,非 nop),MT/IDA 对比下
    每个反折处都多出 1 条 goto 指令 + 新标签名;原目标标签定义行不动,
    多分支引用同一标签也不受影响。语义零变(验证器可见的执行路径不变)。
    跳过:含 try-catch 的方法(保守,不碰边界)、fall-through 恰为跳转
    目标的分支(反折绕路无意义,还可能让 diff 工具一眼看穿模式)。
    跳过 <init>/<clinit>(执行顺序敏感,sigcheck/dcc 依赖)。
  F 恒等算术重编码(零损耗):shl-int/lit8 vA, vB, k → mul-int/lit8
    vA, vB, 2^k 的确定性单向改写。两者同为 22b 格式
    (4 字节,等长零膨胀),32 位补码语义下 vB << k ≡ vB × 2^k(含负数与
    溢出回绕,数学恒等);R8 强度削减会把"乘 2 的幂"规约成 shl,故乘 2
    的幂的 mul 重编码形态 R8 从不产出,不可被上游消除也无法预测。仅改
    写移位量 k ∈ 0x1..0x6(2^k ≤ 0x40 才落回 mul 的 8 位字面量域),
    k=0 与 k>6
    原样保留。跳过 <init>/<clinit>(同 A)。
  C 方法入口 + return 前垃圾指令(谨慎版·强化):仅当方法同时满足全部
    硬条件才插:
      - 不是 <init>/<clinit>
      - 不是 native(dcc 抽走的,无方法体,天然跳过)
      - 方法体内没有任何 .catchall/.catch(try-catch 边界禁止动)
      - .locals ≥ 4(v0..v3 必为纯局部寄存器)
    插入位置(打破"只插方法开头"的可识别模式):
      - 方法入口 1~max_per_method 条(原行为)
      - 每个 return 指令前 1~2 条;被 return 读取的寄存器(return vX /
        return-wide vX 占 v 与 v+1)绝对排除,return-void 无限制
    插入条只用 const/4 纯写,只写 v0..v3 局部寄存器,不改 .locals 值。
    (报错三十二:曾含 move 自赋值——move 读源寄存器,而局部寄存器在方法
    入口处可能从未初始化,ART verifier 直接 VerifyError 秒闪退,已移除。)
    C0 .locals 提升(覆盖增强):.locals N<4 的方法(R8 产物常见 0/1,
    无局部寄存器可用)提升到 4——smali pN 是虚拟参数名,汇编时自动重映射,
    参数语义不变;提升后这些方法才有 v0..v3 可插垃圾指令/可置换。
    return 前的指令从方法入口可达,反编译器不会丢弃。

【幂等】
  * 类文件一旦被处理,会在 .class 声明行下方写一行标记注释
    `# nc-antidiff-applied v1`(注释不进 dex)。
  * 重跑时整类跳过,输出稳定。
  * 随机性完全由确定性 PRNG 驱动:种子 = SHA-256(解包目录全部 smali
    相对路径+内容),同一输入跑两次产物逐字节一致;内容一变种子自动变,
    等于"新版本"。

用法:
  anti-diff.py <解包目录> [--seed-hex HEX] [--level 1] [--max-per-method N]

  --level 1        = MVP(A+B+C),目前只有 1
  --seed-hex HEX   = 固定随机种子(hex,测试/复现用);不给则从输入内容推导
  --max-per-method = 变换 C 单方法最多插入条数(默认 3,开发文档上限)
"""
import argparse
import hashlib
import os
import re
import random
import sys

# 复用 inject-loadlib 的单一真相(报错七:别处不要另写一份 smali 目录正则)
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # scripts/anti-diff → 仓库根


def _load_module(name: str, rel_path: str):
    import importlib.util
    path = os.path.join(_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_INJECT = _load_module('inject_loadlib', 'scripts/inject/inject-loadlib.py')
SMALI_DIR_RE = _INJECT.SMALI_DIR_RE

CLASS_MARK = '# nc-antidiff-applied v1'   # 已处理类的标记注释(幂等判定)

# ── 硬排除:系统类与框架依赖(与 stringenc SYSTEM_CLASS_PREFIXES 同型) ──
# 理由(与 encrypt-strings.py §100 同源):这些类不是要保护的产品代码,
# 反射/序列化/JNI 绑定库的任何文本扰动只有风险没有收益;攻击者对比时
# 这些类本来就在"第三方依赖原样"的预期内,不构成定位线索。
# 注:anti-diff 不改字符串/标识符,风险低于 stringenc,但 jsoup 这类
# "字符串即协议"的库在变换 C 下仍可能被启发式工具误报,统一排除省心。
SKIP_CLASS_PREFIXES = (
    'android.', 'androidx.', 'android.support.', 'com.android.',
    'com.google.android.', 'dalvik.', 'java.', 'javax.',
    'kotlin.', 'kotlinx.', 'org.jetbrains.',
    'org.apache.', 'org.json.', 'org.w3c.', 'org.xml.', 'sun.',
    'xcrash.',
    'okhttp3.', 'okio.', 'com.google.gson.', 'org.jsoup.',
    'org.commonmark.', 'io.ktor.', 'coil3.', 'moe.shizuku.',
)


_SMALI_DIR_PREFIX_RE = re.compile(r'^smali(?:_classes\d+)?/')


def _class_desc_from_path(rel_path):
    """smali 相对路径 → 类描述符(如 smali/com/demo/A.smali → Lcom/demo/A;)。

    rel_path 必含 smali/smali_classesN 目录层,先剥掉再换算(否则 'smali'
    会被当成包名,白名单永远匹配不上——实测踩坑);内部类 A$B 与外部类 A
    同属 com.demo. 前缀,按路径换算即可,无需读文件内容。"""
    no_ext = rel_path[:-len('.smali')] if rel_path.endswith('.smali') else rel_path
    no_ext = _SMALI_DIR_PREFIX_RE.sub('', no_ext)
    return 'L' + no_ext + ';'


def _is_skip_class(rel_path):
    desc = _class_desc_from_path(rel_path)
    # SKIP_CLASS_PREFIXES 是点号格式(androidx.),desc 是斜杠描述符
    # (Landroidx/...) → 前缀先转斜杠再匹配
    for p in SKIP_CLASS_PREFIXES:
        slash = 'L' + p.replace('.', '/')
        if desc.startswith(p) or desc.startswith(slash):
            return True
    return False

# ── 块重排安全:这些指令块"位置敏感",一律不许挪 ──────────────────────
# <init>/<clinit> 执行顺序与 .class 声明紧邻是 ART/验证器敏感区;带 .annotation
# 的块可能有注解处理器顺序依赖,都不挪。
_PIN_METHOD_NAMES = ('<init>', '<clinit>')

# 变换 C 第一条指令白名单已移除:新安全模型基于 ".locals ≥ 4 ⇒ v0..v3 必为
# 纯局部寄存器",与首指令类型无关(旧白名单在真实包上额外砍掉 16% 的方法,
# 如首指令 sget-object 的 getter,毫无必要)。

# 方法体内任何 try-catch 标记(出现即整方法跳过变换 C/E)
_TRY_RE = re.compile(r'^\s*\.catch(?:all)?\s', re.M)

# 匹配 smali 的 label 行与分支/填充指令里的 label 引用
_LABEL_DEF_RE = re.compile(r'^\s*(:[A-Za-z0-9_.$]+)\s*$')
_LABEL_REF_RE = re.compile(r'(?<![\w])(:[A-Za-z0-9_.$]+)\b')

# smali 字符串字面量:值里允许 \" 转义(报错二十二式教训:_LABEL_REF_RE 原先
# 对 const-string 行内的 ":xxx" 也做标签替换,把 jsoup CSS 选择器
# ":not(%s)"、Compose "CC(remember):MainActivity.kt#9igjgp" 等 1391 处
# 运行时功能性字符串当标签改了名。字符串内容属开发文档 §2.2 红线
# "不改字符串内容",必须在文本层替换前把引号内区间整段保护起来。)
_STRING_SPAN_RE = re.compile(r'"(?:[^"\\]|\\.)*"')


def _replace_outside_strings(line, fn):
    """对一行做替换,但跳过所有双引号字符串字面量内的区间。

    fn: 接收整行的替换函数(如 _LABEL_REF_RE.sub 的包装)。
    实现:先用 _STRING_SPAN_RE 找出全部字符串区间,把区间内容替换为占位符,
    对剩余部分做替换,再把原样内容放回。"""
    if '"' not in line:
        return fn(line)
    pieces = []
    protected = []
    last = 0
    for m in _STRING_SPAN_RE.finditer(line):
        pieces.append(line[last:m.start()])
        protected.append(m.group(0))
        pieces.append('\x00%d\x00' % (len(protected) - 1))
        last = m.end()
    pieces.append(line[last:])
    masked = ''.join(pieces)
    out = fn(masked)
    def _unmask(mm):
        return protected[int(mm.group(1))]
    return re.sub(r'\x00(\d+)\x00', _unmask, out)


def _is_label_token(tok: str) -> bool:
    """过滤掉 :array_0 这类被 packed-switch-data 用的伪标签名冲突之外,
    普通分支标签统一视为可重命名。"""
    return tok.startswith(':')


# ── 标签重命名(变换 A)──────────────────────────────────────────────

def _rename_labels(method_lines, rng):
    """对单个方法的行列表做标签重命名;返回新行列表。

    只处理方法体内的行(不含 .method/.end method 边界),不碰
    packed-switch-data / sparse-switch-data 里引用的 label 引用行
    (这些引用行里的 :label 必须与新名同步,所以统一重命名映射)。"""
    # 收集本方法内所有被"引用"的标签名(goto/if-* / packed-switch 等)
    # 报错三十二之二(重放实证):.local/.end local/.restart local 调试行里
    # 引号外的类型描述符形如 `"$scope":Lkotlinx/coroutines/...;`,冒号后的
    # `:Lkotlinx` 会被 _LABEL_REF_RE 当标签引用收进映射并整体改名 → 描述符
    # 被破坏,回编报 "Invalid text '/'"。调试行永远不含真标签,整行跳过。
    _LOCAL_DEBUG_RE = re.compile(r'^\s*\.(?:end local|restart local|local)\b')
    refs = set()
    defs = set()
    for ln in method_lines:
        m = _LABEL_DEF_RE.match(ln)
        if m:
            defs.add(m.group(1))
        if _LOCAL_DEBUG_RE.match(ln):
            continue  # .local 调试行:只可能是类型描述符,不收集
        # 指令行里的 label 引用(goto :x / if-eqz v0, :x / .packed-switch 后的目标等)
        # 只收"行内出现的、以冒号开头的 token",且不是字符串里的内容
        # smali 标签引用只出现在分支指令与 .packed-switch/.sparse-switch/.array-data 的目标行
        for m2 in _LABEL_REF_RE.finditer(ln):
            tok = m2.group(1)
            # 排除误伤:字符串字面量里的冒号(如 "http://")已被上面
            # 行级正则限定在行内,且 label token 不会出现在引号内,因为
            # smali 字符串里出现 ":" 后面必跟非标签字符;但保险起见,
            # 只接受"以 : 开头、后接标签字符"的完整 token
            if _is_label_token(tok):
                refs.add(tok)
    # 只重命名"既被定义又被引用"的本方法私有标签;纯定义无人引用的也改
    # (baksmali 会生成一堆 :cond_0 / :goto_0,有些是死标签,也统一改名)
    all_labels = sorted(defs | refs)
    if not all_labels:
        return method_lines, 0
    # 确定性随机名:nc 前缀 + 种子驱动短 hash,保证全方法内唯一
    used = set()
    mapping = {}
    for old in all_labels:
        # 生成 6 位 hex,冲突时加长(极小概率)
        while True:
            suffix = ''.join(rng.choice('0123456789abcdef') for _ in range(6))
            new = ':nc' + suffix
            if new not in used:
                used.add(new)
                break
        mapping[old] = new
    out = []
    for ln in method_lines:
        def _sub(m):
            tok = m.group(1)
            return mapping.get(tok, tok)
        def _do(s):
            return _LABEL_REF_RE.sub(_sub, s)
        # 字符串字面量内的 ":xxx" 不是标签,必须原样保留(红线:不改字符串)
        # .local 调试行整行原样保留(报错三十二之二:引号外是类型描述符,
        # 不是标签,替换会破坏 `:Lkotlinx/...;` 形态的描述符)
        if _LOCAL_DEBUG_RE.match(ln):
            out.append(ln)
            continue
        out.append(_replace_outside_strings(ln, _do))
    return out, len(mapping)


# ── 类内块重排(变换 B)──────────────────────────────────────────────

def _split_member_blocks(lines):
    """把类文件行列表切成:头部(直到第一个 .method/.field 之前) +
    member 块列表 + 尾部(通常为空,smali 文件以 .end 结尾的块在最后)。

    member 块:连续的一段,属于某个 .method...end method 或 .field 声明组。
    简化模型:按顶层(缩进 0)的指令边界切。这里按 smali 文件结构处理:
      - .method 起,到配对的 .end method 止 → 一个块
      - 其余顶层行(.field / .annotation 外层的 .class/.super/.implements/
        .source)各自成"锚行",锚行不参与重排
    """
    header = []       # .class/.super/.implements/.source/.field 之外的前置行
    blocks = []       # list of (kind, lines)  kind in {'method','field','other'}
    i = 0
    n = len(lines)
    # 先把头部:.class/.super/.implements/.source 这些必须在最前面
    while i < n:
        s = lines[i].strip()
        if s.startswith('.method') or s.startswith('.field'):
            break
        header.append(lines[i])
        i += 1
    # 其余按块切
    while i < n:
        s = lines[i].strip()
        if s.startswith('.method'):
            j = i + 1
            while j < n and not lines[j].strip().startswith('.end method'):
                j += 1
            # 包含 .end method 这一行
            blocks.append(('method', lines[i:j + 1]))
            i = j + 1
        elif s.startswith('.field'):
            # .field 可能是单行声明,也可能带 .annotation 子块以 .end field 结束
            # (kotlinx.serialization 等生成代码必现;当单行处理会把 .end field
            #  之后的文件内容切断 → 回编报 "missing EOF at '.end field'")
            j = i + 1
            closed = False
            while j < n:
                nxt = lines[j].strip()
                if nxt.startswith('.end field'):
                    closed = True
                    j += 1
                    break
                if nxt.startswith('.method') or nxt.startswith('.field'):
                    break  # 单行形态:下一个顶层成员已开始
                j += 1
            blocks.append(('field', lines[i:j]))
            i = j
        else:
            # 其他顶层行(理论上不该有,保险起见单块)
            blocks.append(('other', [lines[i]]))
            i += 1
    return header, blocks


def _block_has_annotation(block_lines):
    return any(ln.strip().startswith('.annotation') for ln in block_lines)


def _method_is_pinned(block_lines):
    """方法块是否"不许动":<init>/<clinit> 或 含 .annotation 的块。"""
    first = block_lines[0].strip() if block_lines else ''
    for name in _PIN_METHOD_NAMES:
        if (' ' + name + '(') in first:
            return True
    for ln in block_lines:
        if ln.strip().startswith('.annotation'):
            return True
    return False


def _reorder_blocks(blocks, rng):
    """对 member 块做确定性重排;pinned 的块钉在原地(保持原相对顺序与位置)。

    简化策略:把所有"可动"的块(非 pinned)洗入它们原来占据的位置槽,
    pinned 块留在原位。这样 <init>/<clinit> 与带注解块的位置完全不变,
    其余块的相对顺序被随机打乱——diff 视角即"文件大段顺序不同"。"""
    movable_idx = [i for i, (kind, blk) in enumerate(blocks)
                   if kind in ('method', 'field')
                   and not _block_has_annotation(blk)
                   and not (kind == 'method' and _method_is_pinned(blk))]
    # 语义锚(与 dex 语义无关、只是"更像原编译产物"的保守约束):
    # javac/kotlinc/R8 的产物里构造函数(<init>/<clinit>)基本都在所有方法
    # 最前;若重排后某个普通方法块落到了 pinned 构造函数之前,diff 工具会
    # 一眼看出"被重排过"。做法:把所有落在首个 pinned 方法块**之前**的
    # movable 槽直接判为不可动(钉住原位),只用剩下的槽洗牌——
    # 这样 pinned 方法之前只可能出现 field(正常编译产物),绝不可能出现方法。
    first_pin = None
    for i, (kind, blk) in enumerate(blocks):
        if kind == 'method' and _method_is_pinned(blk):
            first_pin = i
            break
    if first_pin is not None:
        movable_idx = [i for i in movable_idx if i > first_pin]
    if len(movable_idx) < 2:
        return blocks, 0
    movable = [blocks[i] for i in movable_idx]
    rng.shuffle(movable)
    out = list(blocks)
    for k, i in enumerate(movable_idx):
        out[i] = movable[k]
    return out, len(movable_idx)


# ── 方法入口垃圾指令(变换 C)────────────────────────────────────────

def _method_first_code_index(method_lines):
    """返回方法体内"第一条真实指令"的行号(跳过 .registers/.locals/.param/
    .prologue/.line/标签/注释,以及**完整的 .annotation 块**)。

    报错二十二式教训:.annotation...end annotation 是方法内的注解子块
    (MethodParameters/Signature 等),块体是注解元素不是指令;旧实现只
    按"跳过点开头行"推进,把垃圾指令插进了注解块中间 → smali 汇编报
    "missing EQUAL"。必须整体跳过配对的 .annotation...end annotation。"""
    depth = 0
    for i, ln in enumerate(method_lines):
        s = ln.strip()
        if depth > 0:
            if s.startswith('.annotation'):
                depth += 1
            elif s.startswith('.end annotation'):
                depth -= 1
            continue
        if not s:
            continue
        if s.startswith('.annotation'):
            depth = 1
            continue
        if s.startswith('.'):
            # .registers/.locals/.param/.prologue/.line 等,仍跳过
            continue
        if s.startswith('#'):
            continue
        if _LABEL_DEF_RE.match(ln):
            continue
        return i
    return -1


def _method_registers(method_lines):
    for ln in method_lines:
        s = ln.strip()
        if s.startswith('.registers'):
            parts = s.split()
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                return -1
    return -1


def _method_locals_count(method_lines):
    """返回 .locals N 的 N;.registers 模式返回 -1。

    报错二十二式教训:真实 APK(kotlinc/R8 产物)几乎 100% 用 .locals
    (抽样 206503 处 .locals vs 0 处 .registers),旧代码只认 .registers
    且要求 ≥5,导致变换 C 在真实包上**一个方法都没命中**。
    .locals 模式下参数是 pN = v(N+idx),v0..v3 只要 N ≥ 4 就是纯局部
    寄存器;.registers 模式下 v0 可能是参数(this),低端寄存器不可安全
    覆盖 → 一律跳过(真实包零损失)。"""
    for ln in method_lines:
        s = ln.strip()
        if s.startswith('.locals'):
            parts = s.split()
            try:
                return int(parts[1])
            except (IndexError, ValueError):
                return -1
        if s.startswith('.registers'):
            return -1
    return -1


# 参数槽计数单一真相(报错七/红线 7):count_param_slots/max_param_index
# 抽到 scripts/lib/lib-smali-params.py,anti-diff 独占该实现
# (历史上 light-obf 也曾共用;该模块 2026-09 已下线删除),
# 严禁在本文件再写副本或 fork 逻辑(报错七:单一真相)。
_PARAMS_LIB = _load_module('lib_smali_params', 'scripts/lib/lib-smali-params.py')
count_param_slots = _PARAMS_LIB.count_param_slots
max_param_index = _PARAMS_LIB.max_param_index


def _count_param_slots(method_sig):
    """兼容别名(报错七:本文件历史调用点统一走 lib 单一真相)。"""
    return count_param_slots(method_sig)


def _max_param_index(method_lines):
    """兼容别名(报错七:本文件历史调用点统一走 lib 单一真相)。"""
    return max_param_index(method_lines)


def _bump_locals(method_lines, method_sig=None):
    """把 .locals N < 4 的方法提升到 4,返回(新行列表, 是否提升)。

    动机(防对比覆盖增强):.locals 0/1 的方法没有(或只有 1 个)局部
    寄存器,变换 C(垃圾指令写 v0..v3)与变换 D(局部寄存器置换)都
    无法覆盖。真实包实测:37 方法中 20 个是 .locals 0/1 ——占 54%,
    是覆盖率的最大短板。

    安全性:smali 的 pN 是虚拟参数名,汇编器按 `.locals N` 把 p0 映射到
    v(N + 参数序号)。把 N 从 0/1 提到 4 只是把参数整体平移到更高的物理
    寄存器,方法寄存器总数增加,但:
      - 指令引用一律写 pN → baksmali/smali 往返自动重映射,指令无需改动;
      - v0..v3 成为纯局部寄存器(无初值,只能先写后读——变换 C 的
        const/4 纯写形态天然满足);
      - 验证器对寄存器总数无上限约束(≤65536),只增不减;
      - 若方法含 /range {p0 .. pK} 指令,提升后 range 端点物理位置平移,
        smali 层仍写 pN/smali 自动换算,回编正确。

    注意:必须**同时**满足"方法无 try-catch"(变换 C/D 的共用门槛,
    在调用方保证);含 .registers 的方法不适用(参数在低端,不可平移)。

    报错三十四(真实包回编炸 `Invalid register: v16. Must be between
    v0 and v15`):参数整体平移有**编码上限**——提升后最大参数物理号
    = 4 + 槽总数 - 1,dalvik 多数指令格式的寄存器槽是 4-bit(上限 v15;
    iget/iget-object 是 22c、move 系是 12x、and-int/lit16 是 22b 的
    4-bit 槽等)。真实包实证:TaskEntity.copy$default(静态,13 参数槽
    含 1 个 wide)原 .locals 0、p12=v12 合法;提升后 p12=v16 →
    and-int/lit16 p12 回编即炸。修复:参数槽总数 > 12(提升后最大物理
    号必 > v15)的方法一律不提升,签名解析失败也跳过(宁缺勿滥);
    同时用方法体实际引用的最大 pN 做双保险兜底。
    """
    for i, ln in enumerate(method_lines):
        s = ln.strip()
        if s.startswith('.locals'):
            parts = s.split()
            try:
                n = int(parts[1])
            except (IndexError, ValueError):
                return method_lines, False
            if n >= 4:
                return method_lines, False
            # 报错三十四硬门槛:提升后最大参数物理号 ≤ 15
            # 静态:slots 个参数 → 最大 p{slots-1} 物理 = 4 + slots - 1
            # 非静态:含 this,签名槽数已 +1,同公式
            # method_lines[0] 是 body 第一行(.method 行已被调用方剥掉),
            # 签名需回溯调用方上下文——这里从"调用方约定的块结构"拿不到,
            # 改为在 _process_method_block 传签名进来(见其调用点)。
            slots = _count_param_slots(method_sig) if method_sig else None
            if slots is None or slots < 1:
                return method_lines, False
            # 双保险:方法体实际引用的 pN 序号上界(签名解析万一漏算时兜底;
            # wide 槽偏移已含在签名槽数里,这里直接取两者最大)
            seen = _max_param_index(method_lines)
            if seen >= slots:
                seen = seen + 1  # 兜底形态:按序号近似,保守加 1
            else:
                seen = slots
            if 4 + seen - 1 > 15:
                return method_lines, False
            # 检查方法体是否有 vN 字面引用(vN 引用 .locals 提升后语义
            # 不变——vN 仍是低 N 个局部寄存器,编号不漂移;但要防止
            # 引用了不存在的局部寄存器之外的怪形态,保守:vN 引用存在
            # 且编号 < N 的,提升后依然安全,因为 vN 编号不变)
            out = list(method_lines)
            out[i] = re.sub(r'^(\s*\.locals\s+)\d+', r'\g<1>4', ln)
            return out, True
        if s.startswith('.registers'):
            return method_lines, False
    return method_lines, False


def _inject_junk_at_entry(method_lines, rng, max_per_method):
    """满足全部硬条件时,在方法入口插 1~max_per_method 条垃圾指令。

    安全模型(.locals 模式,真实包 100% 形态):
      - v0..v3 是纯局部寄存器(Dalvik/ART 验证器强制:局部寄存器被读之前
        必有写,方法开头覆盖它们不影响任何路径的语义);
      - 参数在 pN(= 高端寄存器),完全不触碰;
      - 覆盖后原有指令逐条不动 → try-catch 边界内的寄存器状态也不受影响
        (但保守起见含 try 的方法仍跳过,见硬条件 1)。"""
    # 硬条件 1:不能有 try-catch(保守:避免验证器对边界寄存器状态的重校验)
    joined = '\n'.join(method_lines)
    if _TRY_RE.search(joined):
        return method_lines, 0
    # 硬条件 2:.locals ≥ 4(v0..v3 全部是局部寄存器);
    # .registers 模式返回 -1,直接跳过(低端寄存器可能是参数,不可覆盖)
    n_locals = _method_locals_count(method_lines)
    if n_locals < 4:
        return method_lines, 0
    # 定位第一条真实指令:插在它之前(所有声明行之后)
    idx = _method_first_code_index(method_lines)
    if idx < 0:
        return method_lines, 0
    ins = _junk_ins(rng, rng.randint(1, max_per_method))
    # 插在第一条真实指令之前
    new_lines = method_lines[:idx] + ins + method_lines[idx:]
    return new_lines, len(ins)


# ── 变换 E:条件反转 + 跳转链(阶段 2)──────────────────────────────

# 条件零值分支(22t 格式,寄存器 + 标签)
_COND_Z_RE = re.compile(r'^(\s*)(if-eqz|if-nez|if-ltz|if-gez|if-gtz|if-lez)\s+(v\d+|p\d+)\s*,\s*(:[A-Za-z0-9_.$]+)\s*$')
# 条件双值分支(22t 格式)
_COND_2RE = re.compile(r'^(\s*)(if-eq|if-ne|if-lt|if-ge|if-gt|if-le)\s+(v\d+|p\d+)\s*,\s*(v\d+|p\d+)\s*,\s*(:[A-Za-z0-9_.$]+)\s*$')

_Z_INVERSE = {
    'if-eqz': 'if-nez', 'if-nez': 'if-eqz',
    'if-ltz': 'if-gez', 'if-gez': 'if-ltz',
    'if-gtz': 'if-lez', 'if-lez': 'if-gtz',
}
_2_INVERSE = {
    'if-eq': 'if-ne', 'if-ne': 'if-eq',
    'if-lt': 'if-ge', 'if-ge': 'if-lt',
    'if-gt': 'if-le', 'if-le': 'if-gt',
}

# return 指令形态:return-void / return[-wide|-object] vX
_RETURN_RE = re.compile(r'^\s*return(?:-void|-wide|-object)?(?:\s+(v\d+|p\d+))?\s*$')


def _invert_conditionals(method_lines, rng, max_per_method):
    """变换 E:方法内条件分支反折(确定性选择,非全量)。

    改写:
      if-eqz vX, :L   →   if-nez vX, :nc新
                          goto :L
                        :nc新
    原目标标签的定义行不动(可能被多个分支引用);新标签名走种子驱动
    确定性随机,与其余变换一致。落进 dex 的是 1 条真实 goto 指令。"""
    # 逐行扫描,收集可反折的分支(带行号)
    candidates = []
    n = len(method_lines)
    for i, ln in enumerate(method_lines):
        m = _COND_Z_RE.match(ln) or _COND_2RE.match(ln)
        if not m:
            continue
        target = m.groups()[-1]
        # fall-through 恰为跳转目标:反折产生 goto :target 紧跟 :target
        # 定义,纯绕路且模式明显 → 跳过
        if i + 1 < n and method_lines[i + 1].strip() == target + ':':
            continue
        candidates.append(i)
    if not candidates:
        return method_lines, 0
    n_flip = min(len(candidates), rng.randint(1, max_per_method))
    picks = set(rng.sample(candidates, n_flip))
    used_names = set()
    out = []
    flips = 0
    for i, ln in enumerate(method_lines):
        if i not in picks:
            out.append(ln)
            continue
        m = _COND_Z_RE.match(ln) or _COND_2RE.match(ln)
        if not m:
            out.append(ln)
            continue
        groups = m.groups()
        op = groups[1]
        while True:
            new_lab = ':nc' + ''.join(rng.choice('0123456789abcdef') for _ in range(6))
            if new_lab not in used_names:
                used_names.add(new_lab)
                break
        if op in _2_INVERSE:
            indent, op2, a, b, target = groups
            inverse = _2_INVERSE[op2]
            out.append(f'{indent}{inverse} {a}, {b}, {new_lab}')
        else:
            indent, opz, a, target = groups
            inverse = _Z_INVERSE[opz]
            out.append(f'{indent}{inverse} {a}, {new_lab}')
        out.append(f'{indent}goto {target}')
        # 新标签定义行不带尾冒号(smali 3.x 解析器对 ":label:" 尾冒号形态
        # 在"后续紧跟指令"时解析炸:报 no viable alternative;真实
        # baksmali 产物 100% 无尾冒号,保持同构)
        out.append(f'{indent}{new_lab}')
        flips += 1
    return out, flips


def _insert_before_returns(method_lines, rng, max_per_method):
    """变换 C 强化:每个 return 指令前插 1~max_per_method 条垃圾指令。

    排除被 return 读取的寄存器(return vX / return-wide vX 占 v 与 v+1);
    return-void 不读任何寄存器,全部 v0..v3 可用。插在 return 前的指令
    从方法入口可达,反编译器(baksmali)不会丢弃 → 真实落进 dex。"""
    out = []
    inserted = 0
    # 硬条件:.locals ≥ 4 才能保证 v0..v3 全是纯局部寄存器。
    # 真实包教训(首次回编往返验证抓出):漏掉此门槛时,.locals 2 的方法
    # 里 v2/v3 是参数寄存器(p0/p1),垃圾指令直接覆盖 this/参数 → 语义
    # 被破坏。与入口插桩共用同一安全模型。
    if _method_locals_count(method_lines) < 4:
        return method_lines, 0
    for ln in method_lines:
        m = _RETURN_RE.match(ln)
        if m:
            reg = m.group(1)
            if reg is None:
                # return-void:不读任何寄存器,v0..v3 全部可写
                pool = _junk_pool()
            elif reg.startswith('v'):
                # vN:return 读取 vN(ban 掉);return-wide 还读伴生 vN+1。
                # 历史教训:此处曾把集合方向写反(排除"其余全部"导致插的
                # 恰恰全是返回寄存器,直接覆盖返回值),probe 复测抓出。
                banned = {reg}
                if '-wide' in ln:
                    banned.add('v' + str(int(reg[1:]) + 1))
                pool = _junk_pool(banned)
            else:
                # pN 形态只是 baksmali 的参数视图,反编译产物中 return
                # 始终以 vN 出现;防御性兜底:全部封禁(只剩 const 之外的
                # 空池 → 不插),等价于跳过该处
                pool = []
            ins = _junk_ins(rng, rng.randint(1, max_per_method), pool)
            out.extend(ins)
            inserted += len(ins)
        out.append(ln)
    return out, inserted


def _junk_pool(banned=frozenset()):
    """构造垃圾指令池:只写 v0..v3 局部寄存器,排除 banned。

    报错三十二(真实包 classes.dex 闪退实证):池中原含 `move r, r` 自赋值
    ——move 会**读取**源寄存器,而 ".locals ≥ 4" 只保证 v0..v3 是局部寄存器,
    **不保证已初始化**:方法入口处它们可以从未被写过(dex 层 13 处实证)。
    ART verifier 读到未初始化寄存器直接拒绝整个方法 → VerifyError 秒闪退。
    修复:垃圾指令只保留 const/4 纯写形态(const 对目标寄存器是"先定义后
    使用",不读任何源寄存器);move 自赋值彻底移除,并加断言防回归。"""
    pool = []
    for i in range(4):
        r = f'v{i}'
        if r in banned:
            continue
        pool.append(f'    const/4 {r}, 0x0')
        pool.append(f'    const/4 {r}, 0x1')
    return pool


def _junk_ins(rng, count, pool=None):
    """从池中确定性随机选 count 条垃圾指令。"""
    if pool is None:
        pool = _junk_pool()
    count = min(count, len(pool))
    return [rng.choice(pool) for _ in range(count)]


# ── 变换 F:恒等算术重编码(零损耗)─────────────────────────────────

# 仅匹配 shl-int/lit8 的 22b 三操作数形态:目标 vA、源 vB、移位量 #+CC。
# 恒等对应:mul-int/lit8 vA, vB, 2^k(22b 同为 4 字节;32 位补码语义下
# vB << k ≡ vB × 2^k,含负数与溢出回绕,数学恒等)。R8 强度削减把"乘 2
# 的幂"规约成 shl,故 baksmali 产物只含 shl 形态,mul 重编码不可消除。
# 注意不能写成 \bshl-int/lit8\b 一类宽匹配:lit16/2addr 是别的编码格式,
# 行数/字节不同,互转就不再等长(报错三十五同族教训:形态相邻≠形态等价)。
# 历史教训(报错三十七):本变换首版曾把 add-int/lit8 ⇄ rsub-int/lit8
# 当作"语义恒等"——实际 rsub 的运算方向是 CC − vB(立即数是被减数,
# androguard rsubintlit8: BinaryExpressionLit(Op.SUB, cst, var_b)),改写
# 后算术结果反号,真实包必崩。22b 三操作数形态里 vA = vB + x 的单指令
# 恒等替代只有 add 自身,不存在正确的 rsub 对应 → 整体换成 shl⇄mul。
_SHL_LIT8_RE = re.compile(
    r'^(\s*)shl-int/lit8\s+(v\d+|p\d+)\s*,\s*(v\d+|p\d+)\s*,\s*(-?0x[0-9a-fA-F]+)\s*$')


def _reencode_shl_mul(method_lines, rng):
    """变换 F:shl-int/lit8 vA, vB, k → mul-int/lit8 vA, vB, 2^k(单向)。

    22b 格式互转,4 字节等长;vB << k ≡ vB × 2^k(32 位补码,数学恒等)。
    仅当移位量 k ∈ 0x1..0x6 时无条件全量改写(2^k ≤ 0x40,落回 mul 的
    8 位字面量域);k=0 恒等于 ×1(R8 已消)与 k>6(2^k 超域)与移位量为
    负的防御性形态(baksmali 不产出)一律原样保留。寄存器/标签/字符串
    一概不动,无需 _replace_outside_strings 保护(立即数在行尾,不在
    引号内)。rng 为签名兼容占位(旧版按概率抽改,现全量改写)。
    返回(新行列表, 改写条数)。"""
    out = []
    n = 0
    for ln in method_lines:
        m = _SHL_LIT8_RE.match(ln)
        if m:
            indent, dst, src, imm = m.groups()
            k = int(imm, 16)
            if 0x1 <= k <= 0x6:
                out.append(f'{indent}mul-int/lit8 {dst}, {src}, {1 << k:#x}')
                n += 1
            else:
                out.append(ln)
        else:
            out.append(ln)
    return out, n


# ── 变换 D:局部寄存器重编号(阶段 2 增强)──────────────────────────

# wide(64 位)寄存器指令:寄存器对 (vN, vN+1) 构成不可拆分单元
# 报错三十五:曾漏 move-result-wide(与 move-wide 前缀不同,不被其覆盖)与
# cmpg-double/cmpl-double —— 这三类完全不被识别,其宽对整段漏保护。
_WIDE_INS_RE = re.compile(
    r'^\s*(?:const-wide|move-wide|move-result-wide|return-wide|'
    r'add-long|sub-long|mul-long|div-long|rem-long|and-long|or-long|xor-long|'
    r'shl-long|shr-long|ushr-long|neg-long|long-to-(?:int|float|double)|'
    r'double-to-(?:int|float|long)|int-to-long|int-to-double|float-to-long|'
    r'float-to-double|cmp-long|cmpg-double|cmpl-double|'
    r'add-double|sub-double|mul-double|div-double|rem-double|neg-double|'
    r'aget-wide|aput-wide|sget-wide|sput-wide|iget-wide|iput-wide)')

# 64 位操作数判定表(用于 _wide_operand_bases)
_WIDE_ARITH = re.compile(r'^(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-(long|double)$')
_WIDE_ARITH_2ADDR = re.compile(r'^(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr)-(long|double)/2addr$')
_WIDE_TO = re.compile(r'^(long|double)-to-(int|float|long|double)$')
_INT_FLOAT_TO_WIDE = re.compile(r'^(int|float)-to-(long|double)$')

# invoke 行:op {寄存器列表}, 方法引用(参数描述符)返回类型
_INVOKE_RE = re.compile(
    r'^\s*(invoke-[a-z0-9/]+)\s+\{([^}]*)\}\s*,\s*[^\s(]+\(([^)]*)\)')


def _param_slot_list(desc):
    """把参数描述符展开为槽列表,如 '(JLjava/lang/String;D)V' → [2, 1, 2]。

    invoke 指令的寄存器列表按参数**槽**顺序排列,wide 参数(J/D)占 2 槽且
    两个寄存器必须相邻。用于定位 invoke 传入的 wide 寄存器对(报错三十五之四)。"""
    out = []
    i = 0
    n = len(desc)
    while i < n:
        c = desc[i]
        if c in ' \t':
            i += 1          # baksmali 参数描述符含空格分隔符,必须跳过
            continue
        if c == '[':
            while i < n and desc[i] == '[':
                i += 1
            if i < n and desc[i] == 'L':
                while i < n and desc[i] != ';':
                    i += 1
            i += 1
            out.append(1)
        elif c == 'L':
            while i < n and desc[i] != ';':
                i += 1
            i += 1
            out.append(1)
        elif c in 'JD':
            out.append(2)
            i += 1
        else:
            out.append(1)
            i += 1
    return out


def _collect_invoke_wide_pairs(line):
    """返回 invoke 指令传入的 wide 参数寄存器对集合。

    报错三十五之四:invoke 的寄存器列表按参数槽排列,`invoke-static {v8, v9},
    Ljava/lang/Math;->pow(DD)D` 中 (v8,v9) 是 double 的宽对,必须整体置换。
    变换 D 只逐 token 替换寄存器号,不识别这种宽对 → 高低半被拆散 →
    被调方收到错位的 64 位值 / verifier 读未定义寄存器。真实包实证:
    简盒原包有数千处 invoke wide 对被拆散(如 `invoke-static {v4, v0},
    Long;->valueOf(J)` 读断裂宽对)。
    /range 形态由 _collect_range_blocks 整体锁定,这里跳过。"""
    m = _INVOKE_RE.match(line)
    if not m:
        return set()
    op = m.group(1)
    if '/range' in op:
        return set()
    # 保留 token 的**位置**(含 pN 占位)——re.findall(r'\bv\d+') 会把 pN 丢掉
    # 导致后续参数错位,产出 (v7, v4) 这类非连续假对(真实包实证)。
    toks = re.findall(r'\b([vp]\d+)\b', m.group(2))
    slots = _param_slot_list(m.group(3))
    idx = 0 if 'static' in op else 1   # 非 static 第 0 个寄存器是 receiver(1 槽)
    pairs = set()
    for s in slots:
        if idx >= len(toks):
            break
        if s == 2 and idx + 1 < len(toks):
            t1, t2 = toks[idx], toks[idx + 1]
            # 两个成员都是 vN 才是参与置换的局部宽对;pN 区不置换,跳过
            if t1[0] == 'v' and t2[0] == 'v':
                a = int(t1[1:])
                if int(t2[1:]) == a + 1:
                    pairs.add((a, a + 1))
        idx += s
    return pairs



def _wide_operand_bases(name, regs):
    """返回该指令中**全部** 64 位操作数的基址集合(含 dst 与所有 src)。

    报错三十五:旧 _collect_wide_pairs 只登记 regs[0](首操作数),因此
      * move-result-wide v2   → 目标宽对 (2,3) 完全漏(且不在 _WIDE_INS_RE)
      * add-long v4, v0, v2   → 两个 src 宽对 (0,1)/(2,3) 全漏
    漏保护的宽对被变换 D 当普通 single 单元独立置换 → 64 位值高低半拆到
    不相邻寄存器 → ART verifier 读未定义寄存器 → VerifyError 秒闪退。
    """
    n = len(regs)
    if n == 0:
        return set()
    bases = set()
    # ── dst 是 64 位 ──
    if name.startswith(('move-result-wide', 'move-wide', 'const-wide',
                        'iget-wide', 'aget-wide', 'sget-wide')):
        bases.add(regs[0])
    elif _WIDE_ARITH.match(name) or _WIDE_ARITH_2ADDR.match(name):
        bases.add(regs[0])
    elif name in ('neg-long', 'neg-double'):
        bases.add(regs[0])
    elif _INT_FLOAT_TO_WIDE.match(name) or name == 'double-to-long':
        bases.add(regs[0])
    # ── src 是 64 位 ──
    if name.startswith('move-wide'):
        if n >= 2:
            bases.add(regs[1])
    elif name == 'return-wide':
        bases.add(regs[0])
    elif _WIDE_ARITH.match(name):
        for i in (1, 2):
            if i < n:
                bases.add(regs[i])
    elif _WIDE_ARITH_2ADDR.match(name):
        bases.add(regs[0])          # /2addr 的 dst 即 src
    elif name in ('neg-long', 'neg-double'):
        if n >= 2:
            bases.add(regs[1])
    elif name in ('cmp-long', 'cmpg-double', 'cmpl-double'):
        for i in (1, 2):
            if i < n:
                bases.add(regs[i])
    elif _WIDE_TO.match(name):
        if n >= 2:
            bases.add(regs[1])
    elif name.startswith(('iput-wide', 'aput-wide', 'sput-wide')):
        bases.add(regs[0])
    return bases

# 寄存器 token:vN / pN(替换时只匹配独立 token,防止 v1 误伤 v11)
_REG_TOKEN_RE = re.compile(r'(?<![\w.$-])([vp]\d+)(?![\w.$-])')
# 范围形态 {v1 .. v4} 的端点(换算后仍是连续区间,直接替换端点即可)
_RANGE_REG_RE = re.compile(r'(\{[^}]*\})')


def _collect_wide_pairs(method_lines):
    """收集方法内所有 wide 寄存器对(vN 与 vN+1)。

    wide 指令的寄存器对必须整体置换(两个成员绑在同一编号组内),
    否则 64 位值的低/高半会落在不相邻的寄存器上 → 语义破坏。

    报错三十五:旧实现只取每条 wide 指令的 regs[0],导致
      * `move-result-wide v2` 的目标宽对 (2,3) 完全不被登记(且该指令名
        不在旧 _WIDE_INS_RE 里,整条指令被无视);
      * `add-long v4, v0, v2` 的两个 src 宽对 (0,1)/(2,3) 全漏。
    漏保护的宽对随后被 _permute_registers 当普通 single 单元独立置换,
    64 位值高低半被拆到不相邻寄存器 → ART verifier 读未定义寄存器 →
    VerifyError 秒闪退(真实包实证:简盒闪退包 94 处读前未定义,原包 1 处)。
    现改用 _wide_operand_bases:按指令语义取出**全部** 64 位操作数基址。"""
    pairs = set()
    for ln in method_lines:
        s = ln.strip()
        if not s or s.startswith(('#', ':', '.')):
            continue
        if s.startswith('invoke'):
            # 报错三十五之四:invoke 传入的 wide 参数对也要整体保护
            pairs |= _collect_invoke_wide_pairs(ln)
            continue
        m = re.match(r'^([a-z0-9][a-z0-9/._$-]*)', s)
        if not m:
            continue
        name = m.group(1)
        regs = [int(x) for x in re.findall(r'\bv(\d+)\b', s)]
        if not regs:
            continue
        for b in _wide_operand_bases(name, regs):
            pairs.add((b, b + 1))
    return pairs


def _collect_range_blocks(method_lines):
    """收集 /range 指令的连续寄存器区间列表 [(start, end), ...]。

    dalvik 的 /range 形态(如 invoke-static/range {v2 .. v7})要求寄存器
    **连续且升序**。真实包里区间大量两两重叠(实测单文件 31 区间 60+ 处
    重叠),"区间整体互换"不可行。策略:区间成员**全部锁定不动**,
    只置换区间外的寄存器(报错三十三之二)。"""
    blocks = []
    for ln in method_lines:
        s = ln.strip()
        if s.startswith('#') or not s or s.startswith('.'):
            continue
        if '/range' not in s:
            continue
        regs = [int(x) for x in re.findall(r'\bv(\d+)\b', s)]
        if len(regs) >= 2:
            a, b = min(regs), max(regs)
            blocks.append((a, b))
    return blocks


def _collect_low_reg_set(method_lines):
    """收集 4-bit 寄存器指令(35c invoke / 12x /2addr / 11n const/4 等)
    涉及的全部寄存器号集合。

    dalvik 编码:4-bit 槽只能寻址 v0..v15。非 /16、非 /from16、非 /range
    形态的指令,其寄存器操作数全部按 4-bit(或 8-bit 低段)编码——保守起见,
    凡不带 16 位后缀的指令,寄存器号一律要求 ≤15。置换必须保证这些寄存器
    映射后仍在 0..15 内,否则回编报 `Invalid register: vNN. Must be between
    v0 and v15`(真实包实测:报错三十三)。

    注:当前 _permute_registers 采用更保守的"整个 v0..v15 划入低域"策略
    (因为 baksmali 会把 /16 形态优化回短形态,静态判断不完备),本函数
    保留为低域精细化的备用分析器,暂未被调用。"""
    low = set()
    for ln in method_lines:
        s = ln.strip()
        if s.startswith('#') or not s or s.startswith('.'):
            continue
        # 16 位形态:寄存器号可到 255,不参与低组约束
        if '/16' in s or '/from16' in s or '/range' in s:
            continue
        if '/2addr' in s or re.match(r'^\s*(move|move-object|const/4)\s', s) \
                or 'invoke' in s or s.startswith(('if-', 'packed-switch',
                                                  'sparse-switch', 'add-',
                                                  'sub-', 'mul-', 'div-',
                                                  'rem-')):
            low.update(int(x) for x in re.findall(r'\bv(\d+)\b', s))
    return low


def _permute_registers(method_lines, rng):
    """变换 D:方法内局部寄存器 v0..vN 做确定性随机置换。

    安全模型(报错三十二之教训延伸:寄存器类/区不变,只换编号):
      - 只动 .locals 形态的方法;.registers 模式(参数在低端)直接跳过
      - 置换对象:v0..v{locals-1} 全部局部寄存器(宽度 = max 使用编号+1
        与 .locals 取大,保证覆盖到所有使用点)
      - wide 对 (vN, vN+1) 作为整体单元参与置换(单元内两成员始终相邻)
      - 参数 pN 区不在置换范围(物理寄存器号不动,pN 名在 smali 层是
        固定映射,改了会把参数指到错误的物理位置)
      - 每条指令的寄存器操作数同步替换;标签/字符串/.locals 声明不动

    返回(新行列表, 是否发生置换)。"""
    # .locals 声明
    locals_line = None
    n_locals = -1
    for i, ln in enumerate(method_lines):
        s = ln.strip()
        if s.startswith('.locals'):
            parts = s.split()
            try:
                n_locals = int(parts[1])
                locals_line = i
            except (IndexError, ValueError):
                return method_lines, False
            break
        if s.startswith('.registers'):
            return method_lines, False  # .registers 模式:参数在低端,不可置换
    if locals_line is None or n_locals < 4:
        return method_lines, False

    # 扫描方法内实际使用的最大局部寄存器号(可能 > .locals-1,如 R8 产物)
    max_used = n_locals - 1
    for ln in method_lines:
        s = ln.strip()
        if s.startswith('#') or not s or s.startswith('.'):
            if s.startswith('.'):
                continue  # .locals/.param 行里的 pN/vN 不算使用
        regs = [int(x) for x in re.findall(r'\bv(\d+)\b', ln)]
        if regs:
            max_used = max(max_used, max(regs))
    # 置换空间:v0..v{max_used}
    if max_used < 1:
        return method_lines, False

    # wide 对:作为整体单元;range 区间成员全部锁定不动
    wide_pairs = _collect_wide_pairs(method_lines)
    range_blocks = _collect_range_blocks(method_lines)
    # 报错三十五之三:宽对高端成员可能从未在文本出现(如 `const-wide v2`
    # 只写 v2,伴生 v3 不出现)→ 置换空间上界必须覆盖宽对成员,否则该对会
    # 被下面的 `b <= max_used` 丢弃,只剩低半变 single 被单独置换 → 断裂。
    for _a, _b in wide_pairs:
        if _b > max_used:
            max_used = _b
    # 越过 16 位边界的 wide 对(低端受 4-bit 约束,高端不受)→ 放弃
    locked = set()
    for a, b in range_blocks:
        locked.update(range(a, b + 1))
    # 报错三十五之二:宽对之间共享寄存器(如 `move-wide v0, v1` 产生
    # (0,1) 与 (1,2))时无法让两对各自独立整体移动 → 涉及寄存器全部锁定
    # 不动(保守:宁可不置换,绝不可拆散)。
    _wl = sorted(wide_pairs)
    for _i in range(len(_wl)):
        _a, _b = _wl[_i]
        for _j in range(_i + 1, len(_wl)):
            _c, _d = _wl[_j]
            if _c > _b + 1:
                break
            if not (_b < _c or _d < _a):
                locked.update(range(min(_a, _c), max(_b, _d) + 1))
    # 4-bit 约束组:0..15 与 16..max_used 两个独立置换域(跨域置换会让
    # 4-bit 指令编码不下,报错三十三)
    # 域划分:0..15 低域(保守整段划入),16..max_used 高域;
    # range 区间成员、与区间重叠的 wide 对全部锁定
    low_domain = [r for r in range(min(max_used + 1, 16)) if r not in locked]
    high_domain = [r for r in range(16, max_used + 1) if r not in locked]
    # wide 对:与 range 区间重叠的 → 整对锁定;跨 16 位边界的 → 放弃置换
    free_pairs = []
    for a, b in wide_pairs:
        if a in locked or b in locked:
            locked.update((a, b))
            low_domain = [r for r in low_domain if r not in (a, b)]
            high_domain = [r for r in high_domain if r not in (a, b)]
        elif (a <= 15) != (b <= 15):
            return method_lines, False
        else:
            free_pairs.append((a, b))
    # 锁定 wide 对后要重算域(可能有成员刚被锁)
    low_domain = [r for r in low_domain if r not in locked]
    high_domain = [r for r in high_domain if r not in locked]
    units_by_domain = {'low': [], 'high': []}
    covered = set()
    for a, b in sorted(free_pairs):
        if b <= max_used and a not in covered:
            dom = 'low' if a <= 15 else 'high'
            units_by_domain[dom].append(('pair', a, b))
            covered.update((a, b))
    for dom, domain in (('low', low_domain), ('high', high_domain)):
        for r in domain:
            if r not in covered:
                units_by_domain[dom].append(('single', r, r))

    # 确定性随机置换:各域内单元洗牌(wide 对槽 ↔ wide 对,
    # 单寄存器槽 ↔ 单寄存器)
    mapping = {}
    for dom in ('low', 'high'):
        units = units_by_domain[dom]
        pairs = [u for u in units if u[0] == 'pair']
        singles = [u for u in units if u[0] == 'single']
        pair_slots = [u for u in units if u[0] == 'pair']
        single_slots = [u for u in units if u[0] == 'single']
        if len(pairs) != len(pair_slots) or len(singles) != len(single_slots):
            return method_lines, False
        rng.shuffle(pairs)
        rng.shuffle(singles)
        rng.shuffle(pair_slots)
        rng.shuffle(single_slots)
        for i, u in enumerate(pairs):
            mapping[u[1]] = pair_slots[i][1]
            mapping[u[1] + 1] = pair_slots[i][1] + 1
        for i, u in enumerate(singles):
            mapping[u[1]] = single_slots[i][1]

    # 恒等判定:全部编号未变则跳过
    if all(k == v for k, v in mapping.items()):
        return method_lines, False

    out = []
    for ln in method_lines:
        s = ln.strip()
        # .locals 声明行:数值不动(物理寄存器总数不变)
        # .param 行:参数名映射不动
        # .local/.end local 调试行:寄存器号跟指令同步(调试信息一致性),
        # 但报错三十二之二:这些行的描述符/名字部分不能动 → 只替换 vN token
        # 标签行(:label):无寄存器,不匹配
        if s.startswith('.locals') or s.startswith('.registers'):
            out.append(ln)
            continue
        if s.startswith('#') or not s:
            out.append(ln)
            continue

        def _sub(mm):
            tok = mm.group(1)
            if tok.startswith('p'):
                return tok  # 参数名 pN 不动(物理位置在置换范围外)
            num = int(tok[1:])
            new = mapping.get(num)
            return f'v{new}' if new is not None else tok

        out.append(_REG_TOKEN_RE.sub(_sub, ln))
    return out, True




def _method_name(block_lines):
    first = block_lines[0].strip() if block_lines else ''
    # .method ... name(args)ret
    m = re.search(r'\s([A-Za-z0-9_.$<>]+)\(', first)
    return m.group(1) if m else ''


def _method_is_native(block_lines):
    return any(' native ' in ln or ln.rstrip().endswith(' native')
               for ln in block_lines[:1])


def _process_method_block(block_lines, rng, max_per_method, max_cond_flip,
                          enable_f=False):
    """对一个 .method 块做 A(+C+E+F)。返回(新块, 改动计数)。"""
    changes = 0
    lines = block_lines
    # 变换 A:标签重命名(<init>/<clinit> 跳过)
    name = _method_name(lines)
    if name not in _PIN_METHOD_NAMES:
        # 只处理方法体(去掉 .method 行与 .end method 行)
        body = lines[1:-1]
        # 方法级 try 门槛:含 try-catch 的方法一律不做 E/C(标签重命名 A
        # 仍做,它不增删指令、不改偏移)。真实包抽样:含 try 方法占相当
        # 比例,R8 优化后的 catch 块边界与寄存器状态耦合,保守跳过。
        has_try = bool(_TRY_RE.search('\n'.join(body)))
        new_body, n = _rename_labels(body, rng)
        if n:
            lines = [lines[0]] + new_body + [lines[-1]]
            changes += n
        if not has_try and not _method_is_native(lines):
            # 变换 C0:.locals < 4 提升到 4(为 C/D 扩大覆盖面;.locals 0/1
            # 的方法在真实包占 54%,提升后才有局部寄存器可插垃圾/可置换)
            body = lines[1:-1]
            new_body, nb = _bump_locals(body, lines[0])
            if nb:
                lines = [lines[0]] + new_body + [lines[-1]]
                changes += 1
            # 变换 D:局部寄存器重编号(在 E/C 之前:E/C 插入的垃圾指令
            # 用 v0..v3 局部寄存器,若在 D 之后再插,v0..v3 依然指向局部区,
            # 安全;D 先做能让 E/C 的新指令也落在置换后的坐标系,增加噪声)
            body = lines[1:-1]
            new_body, nd = _permute_registers(body, rng)
            if nd:
                lines = [lines[0]] + new_body + [lines[-1]]
                changes += 1
            # 变换 F:恒等算术重编码(shl ⇄ mul,22b 等长等语义,零膨胀;
            # 放在 D 之后——D 改寄存器号,F 只看操作数形态互不干扰。
            # 流水线固定传 --enable-f(原 antidiff.reencode 子复选框已下线,
            # 变换 F 并入模块本体;CLI 开关保留,直跑脚本时仍可显式控制)
            if enable_f:
                body = lines[1:-1]
                new_body, nf = _reencode_shl_mul(body, rng)
                if nf:
                    lines = [lines[0]] + new_body + [lines[-1]]
                    changes += nf
            # 变换 E:条件反折(在标签改名之后做:新标签不在 mapping 里,
            # 原目标标签引用已同步改写;fall-through 判定基于新标签名,一致)
            body = lines[1:-1]
            new_body, ne = _invert_conditionals(body, rng, max_cond_flip)
            if ne:
                lines = [lines[0]] + new_body + [lines[-1]]
                changes += ne
            # 变换 C 强化:return 前插垃圾指令(固定 1 条,用户拍板 2026-09:
            # "返回前插一条就可以了"——原 1~max_per_method 随机上限砍到 1,
            # 体积收益优先;返回寄存器 ban 名单/纯写池安全模型不变)
            body = lines[1:-1]
            new_body, nr = _insert_before_returns(body, rng, 1)
            if nr:
                lines = [lines[0]] + new_body + [lines[-1]]
                changes += nr
            # 变换 C:入口垃圾指令(已下线,用户拍板 2026-09:"方法开头插
            # 1~3 条没什么必要"——return 前插桩已打破"只插方法开头"的可
            # 识别模式(README 变换 C+ 的动机),入口桩删去不影响全红效果,
            # 且省一半以上垃圾指令体积;函数保留供 CLI --max-per-method
            # 消费端兼容,调用点移除)
            # body = lines[1:-1]
            # new_body, n2 = _inject_junk_at_entry(body, rng, max_per_method)
            # if n2:
            #     lines = [lines[0]] + new_body + [lines[-1]]
            #     changes += n2
    return lines, changes


# ── 类文件级处理 ───────────────────────────────────────────────────

def process_file(path, rng, max_per_method, max_cond_flip=3, enable_f=False):
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read()
    if CLASS_MARK in text:
        return 0, 0, 0, True  # 已处理,幂等跳过
    lines = text.splitlines()
    header, blocks = _split_member_blocks(lines)

    total_a = 0
    total_c = 0
    new_blocks = []
    for kind, blk in blocks:
        if kind == 'method':
            new_blk, ch = _process_method_block(blk, rng, max_per_method,
                                                max_cond_flip, enable_f)
            # 拆分 A/C 计数由 _process_method_block 内部合并,这里只记总
            new_blocks.append((kind, new_blk))
            total_a += ch  # 合并计数(标签数+垃圾指令数),报告用
        else:
            new_blocks.append((kind, blk))
    # 变换 B:块重排
    reordered, n_moved = _reorder_blocks(new_blocks, rng)

    # 组装:header + 标记注释 + 重排后的块
    out = list(header)
    # 在 header 末尾(通常是 .source 或最后一行前置声明之后)插标记
    out.append(CLASS_MARK)
    for kind, blk in reordered:
        out.extend(blk)
    new_text = '\n'.join(out)
    if text.endswith('\n'):
        new_text += '\n'
    if new_text != text:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(new_text)
    return total_a, 0, n_moved, False


# ── 种子 ──────────────────────────────────────────────────────────

def derive_seed(root):
    """SHA-256(全部 smali 的 相对路径+内容) → 16 字节种子。"""
    h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for fn in sorted(filenames):
            if not fn.endswith('.smali'):
                continue
            p = os.path.join(dirpath, fn)
            rel = os.path.relpath(p, root)
            h.update(rel.encode('utf-8'))
            h.update(b'\0')
            with open(p, 'rb') as f:
                h.update(f.read())
            h.update(b'\0')
    return h.digest()[:16]


def collect_smali_files(root):
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        if not SMALI_DIR_RE.match(os.path.basename(dirpath)) and \
           not any(SMALI_DIR_RE.match(d) for d in dirnames):
            # 仍可能是 smali 下的子包目录,继续走
            pass
        for fn in filenames:
            if fn.endswith('.smali'):
                files.append(os.path.join(dirpath, fn))
    return files


def main(argv):
    ap = argparse.ArgumentParser(description='anti-diff 防对比混淆(MVP)')
    ap.add_argument('decompiled', help='apktool 解包目录')
    ap.add_argument('--seed-hex', default='', help='固定随机种子(hex)')
    ap.add_argument('--level', type=int, default=1, choices=[1],
                    help='变换等级(目前只有 1 = MVP)')
    ap.add_argument('--max-per-method', type=int, default=3,
                    help='变换 C 单方法/单 return 最多插入条数(默认 3)')
    ap.add_argument('--max-cond-flip', type=int, default=3,
                    help='变换 E 单方法最多反折条件分支数(默认 3,阶段 2)')
    ap.add_argument('--enable-f', action='store_true', default=False,
                    help='启用变换 F(shl⇄mul 恒等重编码;流水线已固定传入——'
                         '原 antidiff.reencode 子复选框已下线,变换 F 并入模块本体;'
                         'CLI 开关保留供直接命令行调用时显式控制,默认关)')
    args = ap.parse_args(argv)

    root = os.path.abspath(args.decompiled)
    if not os.path.isdir(root):
        print(f'❌ 解包目录不存在: {root}', file=sys.stderr)
        return 1

    if args.seed_hex:
        seed = bytes.fromhex(args.seed_hex)
    else:
        seed = derive_seed(root)
    rng = random.Random(seed)

    files = collect_smali_files(root)
    if not files:
        print('⚠️ 未找到任何 .smali 文件', file=sys.stderr)
        return 0

    n_files = 0
    n_skipped = 0
    n_excluded = 0
    total_ac = 0
    total_moved = 0
    for p in sorted(files):
        rel = os.path.relpath(p, root)
        if _is_skip_class(rel):
            n_excluded += 1
            continue
        a, c, moved, skipped = process_file(p, rng, args.max_per_method,
                                            args.max_cond_flip, args.enable_f)
        if skipped:
            n_skipped += 1
            continue
        n_files += 1
        total_ac += a
        total_moved += moved

    print(f'✅ anti-diff 完成: 处理 {n_files} 个类'
          f'({n_skipped} 个已处理跳过,'
          f' {n_excluded} 个系统/依赖类白名单排除),'
          f' 标签/垃圾指令/条件反折改动 {total_ac} 处,'
          f' 块重排移动 {total_moved} 块')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
