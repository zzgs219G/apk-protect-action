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
  C 方法入口垃圾指令(谨慎版):仅当方法同时满足全部硬条件才插 1~3 条
      - 不是 <init>/<clinit>
      - 不是 native(dcc 抽走的,无方法体,天然跳过)
      - 方法体内没有任何 .catchall/.catch(try-catch 边界禁止动)
      - .registers ≥ 5(留足余量)
      - 第一条真实指令是 const*/move*(纯赋值,插桩前后寄存器语义不变)
    插入条只用 const/4 + move 这类无害指令,且只用已存在的寄存器编号,
    不改 .registers 值(否则可能撞 try 边界/参数区)。

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

# ── 块重排安全:这些指令块"位置敏感",一律不许挪 ──────────────────────
# <init>/<clinit> 执行顺序与 .class 声明紧邻是 ART/验证器敏感区;带 .annotation
# 的块可能有注解处理器顺序依赖,都不挪。
_PIN_METHOD_NAMES = ('<init>', '<clinit>')

# 变换 C 第一条指令白名单(纯赋值类,插桩前后寄存器状态语义不变)
_ENTRY_SAFE_RE = re.compile(
    r'^\s*(const(?:/4|/16|/high16)?|const-string(?:/jumbo)?|move(?:/from16|/16)?'
    r'|move-object(?:/from16|/16)?)\s')

# 方法体内任何 try-catch 标记(出现即整方法跳过变换 C)
_TRY_RE = re.compile(r'^\s*\.catch(?:all)?\s', re.M)

# 匹配 smali 的 label 行与分支/填充指令里的 label 引用
_LABEL_DEF_RE = re.compile(r'^\s*(:[A-Za-z0-9_.$]+)\s*$')
_LABEL_REF_RE = re.compile(r'(?<![\w])(:[A-Za-z0-9_.$]+)\b')


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
    refs = set()
    defs = set()
    for ln in method_lines:
        m = _LABEL_DEF_RE.match(ln)
        if m:
            defs.add(m.group(1))
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
        out.append(_LABEL_REF_RE.sub(_sub, ln))
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
    """返回方法体内"第一条真实指令"的行号(跳过 .registers/.locals/.param/.prologue/.line/标签/注释)。"""
    for i, ln in enumerate(method_lines):
        s = ln.strip()
        if not s:
            continue
        if s.startswith('.'):
            # 仍可能是 .registers/.locals/.param/.prologue/.line —— 都跳过
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


def _inject_junk_at_entry(method_lines, rng, max_per_method):
    """满足全部硬条件时,在方法入口插 1~max_per_method 条垃圾指令。"""
    # 硬条件 1:不能有 try-catch
    joined = '\n'.join(method_lines)
    if _TRY_RE.search(joined):
        return method_lines, 0
    # 硬条件 2:.registers ≥ 5
    regs = _method_registers(method_lines)
    if regs < 5:
        return method_lines, 0
    # 硬条件 3:第一条真实指令必须是白名单赋值类
    idx = _method_first_code_index(method_lines)
    if idx < 0:
        return method_lines, 0
    if not _ENTRY_SAFE_RE.match(method_lines[idx]):
        return method_lines, 0
    # 选要插的指令:只用 const/4 + move,寄存器只用低编号(必在 .registers 内)
    # v0/v1 是局部变量区最低端,任何方法都有(因为 regs≥5),插桩安全
    pool = [
        '    const/4 v0, 0x0',
        '    const/4 v1, 0x0',
        '    const/4 v2, 0x0',
        '    const/4 v3, 0x0',
        '    move v0, v0',
        '    move v1, v1',
        '    move v2, v2',
        '    move v3, v3',
    ]
    n_ins = rng.randint(1, max_per_method)
    ins = [rng.choice(pool) for _ in range(n_ins)]
    # 插在第一条真实指令之前
    new_lines = method_lines[:idx] + ins + method_lines[idx:]
    return new_lines, n_ins


# ── 方法级处理 ─────────────────────────────────────────────────────

def _method_name(block_lines):
    first = block_lines[0].strip() if block_lines else ''
    # .method ... name(args)ret
    m = re.search(r'\s([A-Za-z0-9_.$<>]+)\(', first)
    return m.group(1) if m else ''


def _method_is_native(block_lines):
    return any(' native ' in ln or ln.rstrip().endswith(' native')
               for ln in block_lines[:1])


def _process_method_block(block_lines, rng, max_per_method):
    """对一个 .method 块做 A(+C)。返回(新块, 改动计数)。"""
    changes = 0
    lines = block_lines
    # 变换 A:标签重命名(<init>/<clinit> 跳过)
    name = _method_name(lines)
    if name not in _PIN_METHOD_NAMES:
        # 只处理方法体(去掉 .method 行与 .end method 行)
        body = lines[1:-1]
        new_body, n = _rename_labels(body, rng)
        if n:
            lines = [lines[0]] + new_body + [lines[-1]]
            changes += n
        # 变换 C:入口垃圾指令(native 方法没有方法体,天然不在此)
        if not _method_is_native(lines):
            body = lines[1:-1]
            new_body, n2 = _inject_junk_at_entry(body, rng, max_per_method)
            if n2:
                lines = [lines[0]] + new_body + [lines[-1]]
                changes += n2
    return lines, changes


# ── 类文件级处理 ───────────────────────────────────────────────────

def process_file(path, rng, max_per_method):
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
            new_blk, ch = _process_method_block(blk, rng, max_per_method)
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
                    help='变换 C 单方法最多插入条数(默认 3)')
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
    total_ac = 0
    total_moved = 0
    for p in sorted(files):
        a, c, moved, skipped = process_file(p, rng, args.max_per_method)
        if skipped:
            n_skipped += 1
            continue
        n_files += 1
        total_ac += a
        total_moved += moved

    print(f'✅ anti-diff 完成: 处理 {n_files} 个类'
          f'({n_skipped} 个已处理跳过),'
          f' 标签/垃圾指令改动 {total_ac} 处,'
          f' 块重排移动 {total_moved} 块')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
