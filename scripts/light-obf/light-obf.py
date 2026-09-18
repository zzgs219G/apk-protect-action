#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""light-obf.py — 轻量混淆模块(阶段 1+2: 变换 D 标识符 / B 数字混淆 / A 指令替换)。

设计文档: docs/开发文档-light-obf.md (v3)。零方法新增、预算制膨胀,
只做 smali 层等价变换,性能代价与变换点数成正比(红线 1~8 全文见文档 §3.2)。

变换 D(标识符,§4 变换 D):
  ① .method/.field private 声明行;② 全部 smali 文件里对该成员的
  `Ldesc;->name(` / `Ldesc;->name:` 引用;③ access$ 桥体内引用(②的自然
  结果,桥名本身不改,§7.2)。改名不碰字符串字面量(沿用 anti-diff 的
  _replace_outside_strings 掩码机制)。

变换 B(数字混淆,§4 变换 B,--flags 含 b 才启用):
  目标类方法内 |值|≥0x200 的 const/16|const 拆成深链:
    const/16 vN, A ; const/4 vT, s1 ; add-int vN,vN,vT ; const/4 vT, s2 ;
    add-int vN,vN,vT      (每处 +4 条,计入预算;A=v-s1-s2, s∈[-8,7]\\{0})
  jadx 只折叠同语句纯常量,跨语句变量链不折叠 → 必须人工求值。
  临时寄存器只走 .locals 提升路线(红线 7):new_locals + max_param_index ≤ 15
  (lib-smali-params 公共计数,单一真相);方法体出现 v 记法参数引用即放弃
  (提升会错位,报错三十四同型防线);.registers 方法/无 .locals 行/宽对
  (const-wide)/循环/try-catch/<init>/<clinit>/native/annotation 方法一律不做。

变换 A(指令替换,§4 变换 A 的 lit 变体形态,--flags 含 a 才启用):
  mul-int/litX #2^k ⇄ shl-int/litX #k。同一指令宽度(lit8/lit16 值域逐个
  校验,红线 8)、不搬寄存器、零膨胀。
  ⚠️ dex 22b/22s 不存在 sub-int/lit8(减立即数 = rsub-int/lit8 且计算方向
  imm-vB 语义反向)→ add⇄sub 等值重编码形态不存在,实测 smali 汇编拒绝。
  恒等对(xor 0)与需新寄存器的形态未实现(宁缺勿滥)。

门槛(§5.3/§5.4):≤10 units 只做 D;11~16 只做 A;≥17 开放 B;
  反向 goto/条件回边/switch 回指/try-catch 一律判含循环,只做 D(宁误判勿漏判);
  每方法 B≤2 处、A≤3 处、新增指令预算 min(insns×15%, 24)。
  B/A 做过的方法体插入 `# nc-lightobf-ba` 特征注释(不可逆提示,--clean 不移除;
  无类标记但检出该 token → fail-fast 拒绝二次处理,§5.1)。

硬排除(§7,规则写 ** 也不突破):
  Manifest 组件类及内部类 / R,R$,BuildConfig,databinding / 编译器合成符号
  (§7.2) / 反射 API 使用类 / 序列化注解类 / 含 native 方法的类 /
  `com.nc.` 桩包(EXTRA_SKIP_PREFIXES,§5.5 🔴1:防 StrDec GAMMA/SEED 被改 →
  全包字符串静默乱码) / 成员块带 .annotation 的成员(§7.1 的宁漏勿滥超集)。

--clean 语义(§5.1 方案 (b),必须向用户说明白):
  clean 只撤销变换 D(靠 --map 反查)并清除标记行;变换 B/A 本质不可逆,
  回滚唯一路径 = 重新解包原始 apk。clean 不是"完整回滚"。
  fail-fast:对"无本模块标记但检出 B/A 特征标记(nc-lightobf-ba)"的 smali
  拒绝处理并报错,绝不静默二次变换(防幂等破坏、逐轮膨胀)。

--charset unicode 当前不可用(P2 定案:encrypt-strings.py 的
  _FIELD_RE/_FIELD_STRING_LITERAL_RE 未同批更新,见开发文档 §11 附录);
  显式传入即 fail-fast,防静默降级无人知晓。

CLI 契约(§5.1,与 stringenc/anti-diff 同路线:apktool 解包目录 → 文本变换):
  light-obf.py <解包目录> <规则文件> [--seed HEX] [--classes FILE]
               [--flags d] [--map PATH]
  light-obf.py <解包目录> --clean --map PATH

规则文件:与 --stringenc 完全同语法(点号通配符,复用 rules-to-filter.py;
activity* 需 --classes 类列表,同 stringenc 由 make-filter-from-apk.py 产出)。

阶段状态(§6):变换 d(标识符) + b(数字混淆) + a(指令替换) 已实现;
变换 c 属阶段 3,--flags 传 c 即 fail-fast(未实施,绝不静默忽略勾选)。
"""

import argparse
import importlib.util
import json
import os
import random
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))          # scripts/light-obf → 仓库根


def _load_module(name: str, rel_path: str):
    """文件名带连字符/路径加载,同 anti-diff 复用 inject-loadlib 的先例。"""
    path = os.path.join(_ROOT, rel_path)
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── 单一真相复用(报错七:同一逻辑严禁各抄一份) ────────────────────────
#   SKIP_CLASS_PREFIXES / _split_member_blocks / _replace_outside_strings /
#   derive_seed  ← anti-diff(§5.5 名单复用)
#   class_rule_to_filter / expand_activity_keyword ← rules-to-filter(规则语法)
#   build_matchers / classify / class_desc_of ← encrypt-strings(规则匹配 +
#   'stub' 同型兜底 + .class 行解析)
_RULES = _load_module('rules_to_filter', 'scripts/filter/rules-to-filter.py')
_STRINGENC = _load_module('encrypt_strings', 'scripts/string-enc/encrypt-strings.py')
_ANTIDIFF = _load_module('anti_diff', 'scripts/anti-diff/anti-diff.py')
_PARAMS = _load_module('lib_smali_params', 'scripts/lib/lib-smali-params.py')

SKIP_CLASS_PREFIXES = _ANTIDIFF.SKIP_CLASS_PREFIXES   # 与 anti-diff 同一份名单(§5.5)
EXTRA_SKIP_PREFIXES = ('com.nc.',)                    # light-obf 特有追加(§5.5 🔴1)
CLASS_MARK = '# nc-lightobf-applied v1'               # 幂等标记(与 antidiff 各自独立判定)
BA_MARK_TOKEN = 'nc-lightobf-ba'                      # B/A 特征标记 token(clean fail-fast 锚)
ACTIVE_CHARSET = 'ascii'                              # P2 定案(开发文档 §11 附录)


# ── 变换 B/A(阶段 2,§4 变换 B/A + §5.3 循环检测 + §5.4 预算制) ────────

# B 候选常量下限:|v| < 0x100 本就可能是 lit8 形态,jadx 折叠面窄;只拆"看起来
# 是魔法数字"的 const/16|const(报错二十七 _fits 同型:拆出的中间值逐个校验值域)
_B_MIN_ABS = 0x200

_B_DECOMP_RE = re.compile(
    r'^([ \t]*)(const/16|const)\s+([vp]\d+)[\s,]+'
    r'(-?(?:0[xX][0-9a-fA-F]+|\d+))\s*$')

# A: lit 变体池(§4 变换 A v3 硬约束:池内只放"类型一致 + 位宽可容纳"的变体;
# 不搬寄存器、不换寄存器数——同 opcode 系 22b/22s 格式,仅立即数重编码)。
# ⚠️ dex 22b/22s 指令集没有 sub-int/lit8(减立即数 = rsub-int/lit8,计算
# imm - vB,语义反向不等价 add)——add⇄sub 等值重编码不存在,实测 apktool
# smali 汇编拒绝 sub-int/lit8。故池内唯一零风险形态 = mul(2^k)⇄shl(k)。
_A_LIT8_VAL_RE = re.compile(r'^([ \t]*)(mul-int/lit8)'
                            r'\s+([vp]\d+)\s*,\s*([vp]\d+)\s*,\s*(-?0[xX][0-9a-fA-F]+|-?\d+)\s*$')
_A_LIT16_VAL_RE = re.compile(r'^([ \t]*)(mul-int/lit16)'
                             r'\s+([vp]\d+)\s*,\s*([vp]\d+)\s*,\s*(-?0[xX][0-9a-fA-F]+|-?\d+)\s*$')

# §5.3 循环/保守跳过检测:宁误判勿漏判(漏判 = 循环体每迭代付代价,性能灾难)
_LOOP_BACK_GOTO_RE = re.compile(r'^[ \t]*goto(?:/16|/32)?\s+(:\S+)')

_LIT8_MIN, _LIT8_MAX = -128, 127            # lit8 有符号 8 位值域(22b 格式)
_LIT16_MIN, _LIT16_MAX = -32768, 32767      # lit16 有符号 16 位值域(22s 格式)
_BUDGET_RATIO = 0.15
_BUDGET_CAP = 24
_BUDGET_MIN = 4          # 低于此配额不值得做(一处 B 就要 +4 条)
_B_MAX_SITES = 2         # 每方法 B 处数上限(§5.4 热点分散)
_A_MAX_SITES = 3
_LOCALS_RE = re.compile(r'^[ \t]*\.locals\s+(\d+)\s*$')
_REGISTERS_RE = re.compile(r'^[ \t]*\.registers\s+(\d+)\s*$')
_BRANCH_RE = re.compile(r'^[ \t]*(?:if-[\w]+|packed-switch|sparse-switch)\s')
_LABEL_DEF_RE = re.compile(r'^[ \t]*(:\S+)')


def _parse_smali_int(tok):
    """smali 立即数 → int(支持 0x/负号/long 后缀剔除)。解析失败返回 None。"""
    t = tok.strip().rstrip('Ll')
    try:
        return int(t, 0)
    except ValueError:
        return None


def _method_insns_units(lines):
    """方法指令数(§5.4 预算基数):非 '.',非 '#',非空行;不计标签行。"""
    n = 0
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith('.') or s.startswith('#'):
            continue
        if s.startswith(':'):
            continue
        n += 1
    return n


def _looks_like_loop(body_lines):
    """§5.3 保守循环判定:宁误判勿漏判。
    ① 反向 goto(目标标签在 goto 之前定义);② if-*/switch 目标 ≤ 自身行号
    (条件回边/回指);③ try-catch 方法一律视为可能含循环(.catch/.catchall)。
    返回 (is_loop, reason)。"""
    label_line = {}
    for i, ln in enumerate(body_lines):
        m = _LABEL_DEF_RE.match(ln)
        if m:
            label_line.setdefault(m.group(1), i)
    for i, ln in enumerate(body_lines):
        s = ln.strip()
        if s.startswith('.catch'):
            return True, 'try-catch(保守)'
        m = _LOOP_BACK_GOTO_RE.match(ln)
        if m and m.group(1) in label_line and label_line[m.group(1)] <= i:
            return True, '反向 goto'
        if _BRANCH_RE.match(ln):
            m2 = re.search(r'(:\S+)', ln)
            if m2 and m2.group(1) in label_line and label_line[m2.group(1)] <= i:
                return True, '条件回边/回指'
    return False, ''


def _split_int(value):
    """B 拆解:把 value 分解成 3 段和 (s1 + s2 + rest),s1/s2 ∈ [-8,7]\\{0}
    且 rest 落回 const/16 值域。取 s1/s2 尽量小绝对值(随机化由上层 rng 决定
    备选顺序)。无解返回 None。"""
    from itertools import permutations
    for s1, s2 in permutations((d for d in range(-7, 8) if d != 0), 2):
        rest = value - s1 - s2
        if _LIT16_MIN <= rest <= _LIT16_MAX and rest != 0:
            return s1, s2
    return None


def _b_decompose(content_lines, rng, quota, tmp_reg):
    """变换 B:方法体行列表 → (新行列表, 处数, 新增指令数)。
    每处:const/16 vN, V → const/16 vN, rest + [const/4 vT, s ; add-int vN,vN,vT]×2
    (+4 条)。vT = tmp_reg(调用方按红线 7 确定的提升后临时寄存器)。"""
    out = []
    sites = added = 0
    i = 0
    n = len(content_lines)
    while i < n:
        ln = content_lines[i]
        if sites < quota:
            m = _B_DECOMP_RE.match(ln)
            if m:
                indent, op, vreg, valtok = m.groups()
                val = _parse_smali_int(valtok)
                split = _split_int(val) if val is not None else None
                if split is not None:
                    s1, s2 = split
                    if rng.random() < 0.5:
                        s1, s2 = s2, s1
                    rest = val - s1 - s2
                    rest_s = hex(rest) if rest >= 0 else str(rest)
                    out.append(indent + op + ' ' + vreg + ', ' + rest_s)
                    out.append(indent + 'const/4 ' + tmp_reg + ', ' + str(s1))
                    out.append(indent + 'add-int ' + vreg + ', ' + vreg + ', ' + tmp_reg)
                    out.append(indent + 'const/4 ' + tmp_reg + ', ' + str(s2))
                    out.append(indent + 'add-int ' + vreg + ', ' + vreg + ', ' + tmp_reg)
                    sites += 1
                    added += 4
                    i += 1
                    continue
        out.append(ln)
        i += 1
    return out, sites, added


def _a_lit_swap(ln, rng, quota_left):
    """变换 A 单行:lit8/lit16 立即数等值重编码(不搬寄存器,红线 8)。
    返回 (新行或 None, 处数, 新增指令数=0)。"""
    m = _A_LIT8_VAL_RE.match(ln)
    lit16 = False
    if not m:
        m = _A_LIT16_VAL_RE.match(ln)
        lit16 = True
    if not m or quota_left <= 0:
        return None, 0, 0
    indent, op, vdst, vsrc, valtok = m.groups()
    val = _parse_smali_int(valtok)
    if val is None:
        return None, 0, 0
    lo, hi = (_LIT16_MIN, _LIT16_MAX) if lit16 else (_LIT8_MIN, _LIT8_MAX)
    cands = []
    if op.startswith('mul'):
        p = -val if val < 0 else val
        if p > 0 and (p & (p - 1)) == 0:
            k = p.bit_length() - 1
            # mul-int/lit8 #2^k ⇄ shl-int/lit8 #k:同为 int、22b/22s 同格式,
            # 2^k ≤ 128(lit8)/32768(lit16) 时 k ≤ 7/15 落在 lit 值域内
            cands.append(('shl-int/lit8' if not lit16 else 'shl-int/lit16', k))
    if not cands:
        return None, 0, 0
    newop, newval = cands[rng.randrange(len(cands))]
    if not lit16 and not (lo <= newval <= hi):
        return None, 0, 0
    if lit16 and not (lo <= newval <= hi):
        return None, 0, 0
    return (indent + newop + ' ' + vdst + ', ' + vsrc + ', ' + str(newval)), 1, 0


def _try_transform_method(block, rng, want_b, want_a):
    """对单个方法块尝试 B/A(全部门槛不满足即原样返回,宁缺勿滥)。
    返回 (block, b_sites, a_sites, changed)。"""
    first = block[0].strip()
    # 构造器/native/<init>/<clinit>/带 .annotation 的方法不做(§5.4/§7)
    if (' constructor' in first or ' native ' in first
            or '<init>(' in first or '<clinit>()' in first):
        return block, 0, 0, False
    if any(ln.strip().startswith('.annotation') for ln in block):
        return block, 0, 0, False
    # 必须第二行就是 .locals(无 .locals 行/.registers 方法不做,保守)
    m_locals = _LOCALS_RE.match(block[1]) if len(block) > 1 else None
    if m_locals is None:
        return block, 0, 0, False
    old_locals = int(m_locals.group(1))
    body = block[1:-1]                       # 去 .method 与 .end method 行
    # §5.3:判定可能含循环 → 只做变换 D,跳过 B/A(宁误判勿漏判)
    is_loop, _reason = _looks_like_loop(body)
    if is_loop:
        return block, 0, 0, False
    # §5.4 预算门槛:≤10 units 只做 D;11~16 只做 A lit 变体;≥17 开放 B
    units = _method_insns_units(block)
    if units <= 10:
        return block, 0, 0, False
    do_a = want_a and units > 10
    do_b = want_b and units > 16
    if do_b:
        # 红线 7 原文:4 + 参数槽总数 - 1 ≤ 15 才允许 .locals 提升
        slots = _PARAMS.count_param_slots(first)
        if slots is None or slots < 0 or (4 + slots - 1 > 15):
            do_b = False
        # 报错三十四防线:提升后参数物理号平移,最高参数号 = old_locals + slots
        # - 1(非 static 首参 this 占 p0)……保守统一按 old_locals + slots ≤ 15 校验
        elif old_locals + slots > 15:
            do_b = False
        else:
            # 方法体若存在 vN 记法且 N ≥ old_locals(= baksmali 用 v 记法直写
            # 参数物理号的形态),提升 .locals 后参数平移 → vN 错位。只要有一个
            # 此类引用即放弃(p 记法由 smali 编译器自动重映射,安全)
            for ln in body[1:]:
                st = ln.strip()
                if not st or st.startswith('.') or st.startswith('#'):
                    continue
                for num in re.findall(r'(?<![\w])v(\d+)\b', ln):
                    if int(num) >= old_locals:
                        do_b = False
                        break
                if not do_b:
                    break
    b_sites = a_sites = 0
    if do_b:
        budget = min(int(units * _BUDGET_RATIO), _BUDGET_CAP)
        quota = min(_B_MAX_SITES, budget // 4)      # 每处 +4 条(§4 变换 B)
        tmp_reg = 'v' + str(old_locals)             # 提升后新空闲寄存器 = 原 .locals 号
        body, b_sites, added = _b_decompose(body, rng, quota, tmp_reg)
        if b_sites:
            indent = body[0][:len(body[0]) - len(body[0].lstrip())]
            body[0] = indent + '.locals ' + str(old_locals + 1)
    if do_a:
        a_quota = _A_MAX_SITES
        body2 = []
        for ln in body:
            new_ln, cnt, _ = _a_lit_swap(ln, rng, a_quota)
            if new_ln is not None:
                body2.append(new_ln)
                a_sites += cnt
                a_quota -= cnt
            else:
                body2.append(ln)
        body = body2
    if not b_sites and not a_sites:
        return block, 0, 0, False
    # B/A 特征标记:插在 .end method 前一行(不可逆提示;clean 不移除;
    # 无类标记时检出该 token → fail-fast 拒绝二次处理,§5.1)
    indent = block[-1][:len(block[-1]) - len(block[-1].lstrip())]
    new_block = [block[0]] + body + [indent + '# ' + BA_MARK_TOKEN, block[-1]]
    return new_block, b_sites, a_sites, True


def _apply_ba_to_class(content, rng, want_b, want_a, rel):
    """对一个类做变换 B/A(§4/§5.3/§5.4)。变换 D 已先跑(类头有 CLASS_MARK)。
    返回 (新文本, b_sites, a_sites)。"""
    lines = content.split('\n')
    out = []
    b_total = a_total = 0
    i = 0
    n = len(lines)
    while i < n:
        s = lines[i].strip()
        if not s.startswith('.method'):
            out.append(lines[i])
            i += 1
            continue
        j = i + 1
        while j < n and not lines[j].strip().startswith('.end method'):
            j += 1
        block, b, a, changed = _try_transform_method(
            lines[i:j + 1], rng, want_b, want_a)
        b_total += b
        a_total += a
        out.extend(block)
        i = j + 1
    return '\n'.join(out), b_total, a_total


# ── 成员名硬排除(§7.2 编译器合成符号 + Java 序列化协议) ──────────────
_SYNTH_NAME_SUBSTR = ('$r8$', '$i$a$', '$i$f$', '$lambda$', '$$')
_SYNTH_NAME_PREFIX = ('access$', '$-')
_SYNTH_NAME_EXACT = frozenset((
    'Companion', 'getInstance', 'DefaultImpls',
    'serialVersionUID', 'writeObject', 'readObject', 'readResolve', 'writeReplace',
))

# 反射高危形态(§7):类内容出现这些 token → 整类跳过(保守:目标成员无法
# 静态识别,宁可漏混淆)
_REFLECT_MARKERS = (
    'getDeclaredField', 'getDeclaredFields', 'getDeclaredMethod',
    'getDeclaredMethods', 'getDeclaredConstructor', 'Class;->forName(',
)

# 序列化注解类(§7,与 stringenc 硬排除名单对齐):整类跳过
_SERIALIZATION_ANNOTATIONS = (
    'Lkotlinx/serialization/Serializable;',
    'Lcom/google/gson/annotations/',
    'Lcom/fasterxml/jackson/annotation/',
    'Landroidx/room/',
)

# 成员声明行解析:.method/.field 后是空白分隔的 flag token(private/static/
# final/synthetic/constructor/bridge...),最后一个 token 就是名字。
_METHOD_DECL_RE = re.compile(r'^(\.method\s+(?:[\w$-]+\s+)*)([^\s(]+)\(')
_FIELD_DECL_RE = re.compile(r'^(\.field\s+(?:[\w$-]+\s+)*)([^\s:]+):')

# 跨文件引用扫描:取一个文件里出现的全部类描述符(引用形态 `Ldesc;->`)
_REF_DESC_RE = re.compile(r'(L[^;\s"()]+;)->')

# Manifest 组件声明(apktool 解包后是文本 AXML;组件名 = 各组件标签的
# android:name 属性。误把 <queries> 里的引用类当组件排除只是漏混淆,无害)
_MANIFEST_COMPONENT_RE = re.compile(
    r'<(?:application|activity|activity-alias|service|receiver|provider)\b'
    r'[^>]*?android:name="([^"]+)"', re.S)


def parse_manifest_components(decompiled_dir):
    """AndroidManifest.xml → 组件类描述符集合(含内部类判定的原始名)。"""
    mp = os.path.join(decompiled_dir, 'AndroidManifest.xml')
    names = set()
    if not os.path.isfile(mp):
        return names
    with open(mp, encoding='utf-8', errors='replace') as fp:
        text = fp.read()
    for m in _MANIFEST_COMPONENT_RE.finditer(text):
        names.add(m.group(1))
    return names


def _manifest_desc_set(decompiled_dir):
    descs = set()
    for name in parse_manifest_components(decompiled_dir):
        desc = 'L' + name.replace('.', '/') + ';'
        descs.add(desc)
    return descs


def _is_synthetic_name(name):
    """§7.2 边界清单:$r8$/$i$a$/$i$f$/$lambda$/$$/access$/$-/Companion/
    getInstance/DefaultImpls/序列化协议名。命中即不改。"""
    if name in _SYNTH_NAME_EXACT:
        return True
    if name.startswith(_SYNTH_NAME_PREFIX):
        return True
    return any(s in name for s in _SYNTH_NAME_SUBSTR)


def _gen_name(rng, old, taken):
    """ascii 路线新名:保留首字符 + '~' + 6 位 hex(探针 P2 已验证该形态
    对 _FIELD_RE/_FIELD_STRING_LITERAL_RE 均 HIT,§11 附录)。类内唯一。"""
    base = old[0] if (old[0].isalpha() or old[0] in '_$') else 'a'
    while True:
        cand = base + '~' + ''.join(rng.choice('0123456789abcdef') for _ in range(6))
        if cand not in taken and cand != old:
            return cand


class _Renames:
    """单个类的改名表(方法与字段是 dex 两个命名空间,分表防串改)。"""

    def __init__(self):
        self.methods = {}
        self.fields = {}

    def empty(self):
        return not self.methods and not self.fields

    def all_pairs(self):
        return list(self.methods.items()) + list(self.fields.items())


def _collect_renames(content, rng):
    """扫描单个类的 member 块 → 改名表。只改 smali 层明确 private 的成员
    (§7.1:public/protected 一律不改,Kotlin protected 编译成 public 自动被
    挡住);成员块带 .annotation 的不改(§7.1 名单的宁漏勿滥超集);合成名
    不改(§7.2);<init>/<clinit>/native 不改。"""
    header, blocks = _ANTIDIFF._split_member_blocks(content.split('\n'))
    del header
    # 先收集全部现有成员名,保证新名类内唯一(防覆盖)
    existing = set()
    for kind, blk in blocks:
        m = (_METHOD_DECL_RE if kind == 'method' else _FIELD_DECL_RE).match(blk[0].strip())
        if m:
            existing.add(m.group(2))
    ren = _Renames()
    taken = set(existing)
    for kind, blk in blocks:
        first = blk[0].strip()
        m = (_METHOD_DECL_RE if kind == 'method' else _FIELD_DECL_RE).match(first)
        if not m:
            continue
        flags, name = m.group(1), m.group(2)
        if ' private ' not in flags + ' ':
            continue
        if _is_synthetic_name(name):
            continue
        if kind == 'method':
            if name in ('<init>', '<clinit>'):
                continue
            if ' native ' in flags:
                continue
        # 成员块带任何 .annotation → 不改(@JvmName/@PublishedApi/
        # @VisibleForTesting/序列化注解等的保守超集,§7.1)
        if any(ln.strip().startswith('.annotation') for ln in blk):
            continue
        new = _gen_name(rng, name, taken)
        taken.add(new)
        if kind == 'method':
            ren.methods[name] = new
        else:
            ren.fields[name] = new
    return ren


def _apply_desc_renames(text, desc, ren, is_own):
    """对一个文件施加某类的改名(②引用全库 + ①声明仅 own 文件)。

    返回 (new_text, refs, decls):refs/decls 是 {old: 替换条数}。
    引用替换走字符串掩码(字符串字面量里的 `Ldesc;->name(` 不碰)。
    声明行锚定 .method/.field 行首 + flag token,不会命中字符串。"""
    refs = {old: 0 for old, _ in ren.all_pairs()}
    decls = {old: 0 for old, _ in ren.all_pairs()}
    out = []
    for ln in text.split('\n'):
        if is_own:
            s = ln.lstrip()
            indent = ln[:len(ln) - len(s)]
            m = None
            if s.startswith('.method'):
                m = _METHOD_DECL_RE.match(s)
            elif s.startswith('.field'):
                m = _FIELD_DECL_RE.match(s)
            if m and ' private ' in m.group(1) + ' ':
                old = m.group(2)
                new = ren.methods.get(old) if s.startswith('.method') else ren.fields.get(old)
                if new is not None:
                    out.append(indent + s[:m.start(2)] + new + s[m.end(2):])
                    decls[old] += 1
                    continue
        for old, new in ren.methods.items():
            pat = desc + '->' + old + '('
            if pat in ln:
                cnt = [0]

                def _sub(seg, pat=pat, new=new, cnt=cnt):
                    cnt[0] += seg.count(pat)
                    return seg.replace(pat, desc + '->' + new + '(')

                ln = _ANTIDIFF._replace_outside_strings(ln, _sub)
                refs[old] += cnt[0]
        for old, new in ren.fields.items():
            pat = desc + '->' + old + ':'
            if pat in ln:
                cnt = [0]

                def _sub(seg, pat=pat, new=new, cnt=cnt):
                    cnt[0] += seg.count(pat)
                    return seg.replace(pat, desc + '->' + new + ':')

                ln = _ANTIDIFF._replace_outside_strings(ln, _sub)
                refs[old] += cnt[0]
        out.append(ln)
    return '\n'.join(out), refs, decls


def _insert_mark(lines):
    for i, ln in enumerate(lines):
        s = ln.strip()
        if s.startswith('.method') or s.startswith('.field'):
            return lines[:i] + [CLASS_MARK] + lines[i:]
    return lines + [CLASS_MARK]


def _build_ann_re(ba_token):
    return re.compile(
        r'^(\.annotation)[^\n]*\n(?:(?!\.end annotation)[^\n]*\n)*?.*[ \t]'
        + re.escape(ba_token), re.M)


_BA_ANN_RE = _build_ann_re(BA_MARK_TOKEN)


def _ba_orphan_check(content, rel):
    """fail-fast(§5.1):无本模块标记但检出 B/A 特征标记 → 拒绝处理。
    防止 clean 后重跑把 B/A 已变换的代码当"未处理类"二次变换。
    普通行含 token 判"曾做过 B/A"(强断言);仅 .annotation 值/枚举行含
    token 判"非相关名字"(用户义务:该名字不得再入混淆面)。"""
    has_token = BA_MARK_TOKEN in content
    if not has_token:
        return
    if CLASS_MARK in content:
        return
    if _BA_ANN_RE.search(content):
        # 仅 .annotation 值/枚举行含 token(如恰好同名的方法名)→ 判为
        # "非相关名字"(用户义务:该名字不得再入混淆面),不触发 fail-fast;
        # smali 代码行含 token(曾做过 B/A)才拦。
        body_wo_ann = _BA_ANN_RE.sub('', content)
        if BA_MARK_TOKEN not in body_wo_ann:
            return
    raise SystemExit(
            f'❌ {rel}: 检出 light-obf 变换 B/A 特征标记({BA_MARK_TOKEN})但无类标记。\n'
            f'   该代码已被不可逆变换(变换 B/A),当前 smali 不能再次处理,否则幂等破坏、\n'
            f'   产物逐轮膨胀。请从 fresh unpack(重新解包原始 apk)重新开始整个流程。')


def _class_skip_reason(content, desc, manifest_descs, includes, excludes):
    """返回 None = 可处理;否则返回跳过原因字符串(§7 硬排除 + 规则匹配)。"""
    dot = desc[1:-1].replace('/', '.')
    verdict = _STRINGENC.classify(dot, desc, includes, excludes)
    if verdict != 'target':
        return 'rules-' + verdict
    for p in EXTRA_SKIP_PREFIXES:
        if desc.startswith('L' + p.replace('.', '/')):
            return 'extra-skip'
    for d in manifest_descs:
        if desc == d or desc.startswith(d[:-1] + '$'):
            return 'manifest'
    simple = desc[:-1].rsplit('/', 1)[-1]
    if simple == 'R' or simple.startswith('R$') or simple == 'BuildConfig':
        return 'generated'
    if '/databinding/' in desc:
        return 'generated'
    for mk in _REFLECT_MARKERS:
        if mk in content:
            return 'reflect'
    for a in _SERIALIZATION_ANNOTATIONS:
        if a in content:
            return 'serialization'
    if re.search(r'^\.method[^\n]*\bnative\b', content, re.M):
        return 'native'
    return None


def collect_smali_files(root):
    files = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in sorted(filenames):
            if fn.endswith('.smali'):
                files.append(os.path.join(dirpath, fn))
    return sorted(files)


def run_apply(args, root):
    if not args.rules:
        raise SystemExit('❌ 缺少规则文件(标识符混淆必须明确范围,不做自动兜底)')
    if not os.path.isfile(args.rules):
        raise SystemExit(f'❌ 规则文件不存在: {args.rules}')
    if args.charset != ACTIVE_CHARSET:
        raise SystemExit(
            f'❌ --charset {args.charset} 当前不可用(P2 定案:encrypt-strings.py 的'
            f' _FIELD_RE/_FIELD_STRING_LITERAL_RE 未同批更新,启用前提见开发文档'
            f' §11 附录 / §5.2 消费者清单)。当前生效字符集: {ACTIVE_CHARSET}')
    for ch in args.flags.replace(',', ''):
        if ch not in ('d', 'b', 'a'):
            raise SystemExit(
                f'❌ 变换 {ch.upper()} 属于阶段 3/未实现(开发文档 §6)。'
                f'当前支持 --flags d,b,a。绝不静默忽略未实现的勾选。')
    want_b = 'b' in args.flags.replace(',', '')
    want_a = 'a' in args.flags.replace(',', '')
    classes_file = args.classes if args.classes and os.path.isfile(args.classes) else None
    includes, excludes, _activity = _STRINGENC.build_matchers(args.rules, classes_file)
    if args.seed:
        seed = bytes.fromhex(args.seed)
    else:
        seed = _ANTIDIFF.derive_seed(root)
    files = collect_smali_files(root)
    if not files:
        print('⚠️ 未找到任何 .smali 文件')
        return 0
    manifest_descs = _manifest_desc_set(root)

    # ── pass 1: 分类 + 收集改名表 ──────────────────────────────────
    all_renames = {}          # desc -> (_Renames, own_rel)
    skip_counts = {}
    n_marked = 0
    for path in files:
        rel = os.path.relpath(path, root)
        with open(path, encoding='utf-8') as fp:
            content = fp.read()
        _ba_orphan_check(content, rel)
        if CLASS_MARK in content:
            n_marked += 1
            continue
        desc = _STRINGENC.class_desc_of(content)
        if not desc:
            continue
        reason = _class_skip_reason(content, desc, manifest_descs, includes, excludes)
        if reason:
            skip_counts[reason] = skip_counts.get(reason, 0) + 1
            continue
        rng = random.Random(seed.hex() + '|' + desc)
        ren = _collect_renames(content, rng)
        all_renames[desc] = (ren, rel)

    # ── pass 2: 全库施加(引用跨文件;声明仅在 own 文件)+ 幂等标记 ──
    total_methods = total_fields = 0
    total_refs = 0
    total_b = total_a = 0
    n_written = 0
    own_by_rel = {}
    for desc, (ren, own_rel) in all_renames.items():
        # own 标记对所有 target 类生效(含无 private 成员、ren 为空的类):
        # 标记是幂等锚,漏标会让下次重跑把这些类当"未处理类"再收集一遍,
        # 且 --map 会被写入空条目、把真实 map 覆盖成空表(实测踩坑,冒烟 ③)
        own_by_rel[own_rel] = desc
        total_methods += len(ren.methods)
        total_fields += len(ren.fields)
    for path in files:
        rel = os.path.relpath(path, root)
        with open(path, encoding='utf-8') as fp:
            text = fp.read()
        new_text = text
        own_desc = own_by_rel.get(rel)
        present = set(_REF_DESC_RE.findall(text))
        if own_desc is not None:
            present.add(own_desc)
        present &= set(all_renames)
        n_before = len(new_text)
        file_refs = 0
        for desc in sorted(present):
            ren, _own_rel = all_renames[desc]
            if ren.empty():
                continue
            new_text, refs, _decls = _apply_desc_renames(new_text, desc, ren, desc == own_desc)
            file_refs += sum(refs.values())
        if file_refs:
            total_refs += file_refs
        if own_desc is not None:
            new_text = '\n'.join(_insert_mark(new_text.split('\n')))
            # 变换 B/A(阶段 2,§4):只在 own(= 规则命中、D 已标记)的类上做。
            # B/A 不跨类,幂等由类标记保证(重跑时 marked 类在 pass 1 已整体跳过)
            b_cnt = a_cnt = 0
            if want_b or want_a:
                ba_rng = random.Random(seed.hex() + '|ba|' + own_desc)
                new_text, b_cnt, a_cnt = _apply_ba_to_class(
                    new_text, ba_rng, want_b, want_a, rel)
                total_b += b_cnt
                total_a += a_cnt
        if new_text != text:
            # 行数守恒(变换 D 只做 token 级替换,绝不增删行):
            # 原 len 断言在 old 名长于 8 字符新名时必炸 —— 真实包实测复现:
            # GitHubDispatcher.smali getGithubClient(15字符) → a~xxxxxx(8字符)。
            # "防误删"由 _verify_conservation 的引用计数守恒兜底;
            # own 文件额外允许 +1 行 = _insert_mark 的幂等标记行;
            # B/A 开启时额外允许:每方法 1 行 BA 特征标记 + B 每处 4 行(常量
            # 拆解,§4 变换 B 的形态行数);其余增删行即 assert(防误删防线)
            delta = new_text.count('\n') - text.count('\n')
            expected = (1 if own_desc is not None else 0)
            if own_desc is not None and (want_b or want_a):
                expected += (new_text.count('# ' + BA_MARK_TOKEN)
                             - text.count('# ' + BA_MARK_TOKEN))
                expected += 4 * b_cnt
            assert delta == expected, rel
            with open(path, 'w', encoding='utf-8') as fp:
                fp.write(new_text)
            n_written += 1
    # 构建期守恒断言(§4/§6):old 名引用必须全量消失、new 名计数与 old 计数
    # 1:1 守恒(含声明行)。违反 = 变换不完整,fail-fast(宁炸勿静默半改)。
    _verify_conservation(files, all_renames)

    if args.map_path:
        # 幂等重跑(全部 marked skip)时 all_renames 为空 → map 为空表。
        # 此时【不得】覆盖旧 map:clean 的反查依据是"当年首次变换"的映射,
        # 被空表覆盖会让 clean 丢掉全部还原能力(实测踩坑:冒烟 ③ 复现)。
        if all_renames and (not os.path.isfile(args.map_path)
                            or os.path.getsize(args.map_path) == 0):
            _write_map(args.map_path, all_renames)
        elif all_renames:
            # 同一解包目录上换 seed 重跑且已有非空 map:拒绝覆盖(fail-fast),
            # 防 map 与实际改名状态错位(clean 反查依据必须与当前 smali 一致)
            raise SystemExit(
                f'❌ --map 指向已存在的非空文件({args.map_path}),且本次运行有新的改名。\n'
                f'   map 是 --clean 撤销变换 D 的反查依据,静默覆盖会让 clean 还原到'
                f'错误的名字。请换一个 map 路径,或先 --clean 再重跑。')

    skip_s = ', '.join(f'{k}={v}' for k, v in sorted(skip_counts.items())) or '无'
    print(f'✅ light-obf 完成: 目标类 {len(all_renames)} 个(已标记 {n_marked} 个幂等跳过),'
          f' 改名 方法{total_methods}/字段{total_fields}, 引用更新 {total_refs} 处,'
          f' 变换B {total_b} 处, 变换A {total_a} 处,'
          f' 写盘 {n_written} 文件, 排除: {skip_s}')
    print(f'   字符集: {ACTIVE_CHARSET}(unicode 未启用,P2 定案见开发文档 §11 附录)')
    return 0


def _write_map(map_path, all_renames):
    """map = clean 撤销变换 D 的反查依据(§5.1/§9.4)。"""
    entries = []
    for desc, (ren, _rel) in sorted(all_renames.items()):
        for old, new in sorted(ren.methods.items()):
            entries.append({'class': desc, 'kind': 'method', 'old': old, 'new': new})
        for old, new in sorted(ren.fields.items()):
            entries.append({'class': desc, 'kind': 'field', 'old': old, 'new': new})
    with open(map_path, 'w', encoding='utf-8') as fp:
        json.dump(entries, fp, ensure_ascii=False, indent=1)


def _conservation_counts(files, pats):
    """全库统计 (old_pat, new_pat) 对的命中数。

    计数必须在掩码回调内部做(与 _apply_desc_renames 同一机制):
    _replace_outside_strings 的【返回值】会把字符串字面量原样回填,而字面量
    里的 `Ldesc;->name(` 形态按设计保留明文(红线 5 不改字符串)——在返回值上
    count 会把字面量误计入守恒断言(实测踩坑:冒烟⑦的 const-string 字面量
    引起误报 fail-fast)。回调收到的 seg 才是字面量已保护的内容。"""
    old_cnt = new_cnt = 0
    for path in files:
        with open(path, encoding='utf-8') as fp:
            text = fp.read()
        for ln in text.split('\n'):
            for old_pat, new_pat in pats:
                if old_pat not in ln and new_pat not in ln:
                    continue

                def _count(seg, o=old_pat, n=new_pat):
                    nonlocal old_cnt, new_cnt
                    old_cnt += seg.count(o)
                    new_cnt += seg.count(n)
                    return seg

                _ANTIDIFF._replace_outside_strings(ln, _count)
    return old_cnt, new_cnt


def _verify_conservation(files, all_renames):
    """引用计数守恒断言(§4 变换 D/§6 阶段 1):改名后全库对 old 形态的引用
    必须为 0(全量替换),new 形态计数 = 替换前的 old 计数(1:1 守恒)。
    违反 = 变换不完整 → SystemExit fail-fast(宁炸勿静默半改)。"""
    pats = []
    for desc, (ren, _own) in all_renames.items():
        for old, new in ren.methods.items():
            pats.append((desc + '->' + old + '(', desc + '->' + new + '('))
        for old, new in ren.fields.items():
            pats.append((desc + '->' + old + ':', desc + '->' + new + ':'))
    if not pats:
        return
    old_cnt, new_cnt = _conservation_counts(files, pats)
    if old_cnt != 0 or new_cnt != old_cnt + new_cnt:
        # old_cnt != 0 → 有漏改;数学恒等兜底(new 永不小于 old)
        raise SystemExit(
            f'❌ 引用计数守恒断言失败: old 形态残留 {old_cnt} 处'
            f'(应为 0)。变换不完整,已停止 —— 请检查引用扫描正则(§4 变换 D)。')


def run_clean(args, root):
    """clean(§5.1 方案 (b)):只撤销变换 D(--map 反查)并清标记。
    B/A 不恢复(本质不可逆);B/A 特征标记残留即 fail-fast。"""
    if not args.map_path or not os.path.isfile(args.map_path):
        raise SystemExit(
            '❌ --clean 必须提供当年运行时写入的 --map 文件(改名反查的唯一依据)。\n'
            '   clean 只撤销变换 D(标识符),不是完整回滚;变换 B/A 不可逆,\n'
            '   回滚唯一路径 = 重新解包原始 apk(开发文档 §5.1 方案 (b))。')
    with open(args.map_path, encoding='utf-8') as fp:
        entries = json.load(fp)
    grouped = {}
    for e in entries:
        ren = grouped.setdefault(e['class'], _Renames())
        if e['kind'] == 'method':
            ren.methods[e['new']] = e['old']      # 反查: new → old
        else:
            ren.fields[e['new']] = e['old']
    files = collect_smali_files(root)
    n_restored = 0
    n_marks_removed = 0
    for path in files:
        rel = os.path.relpath(path, root)
        with open(path, encoding='utf-8') as fp:
            text = fp.read()
        _ba_orphan_check(text, rel)
        new_text = text
        present = set(_REF_DESC_RE.findall(new_text))
        own = {d for d in grouped if CLASS_MARK in new_text}
        for desc in sorted(present & set(grouped) | own):
            ren = grouped[desc]
            if ren.empty():
                continue
            new_text, _refs, _decls = _apply_desc_renames(new_text, desc, ren, desc in own)
        if CLASS_MARK in new_text:
            new_text = '\n'.join(
                ln for ln in new_text.split('\n') if ln.strip() != CLASS_MARK)
            n_marks_removed += 1
        if new_text != text:
            with open(path, 'w', encoding='utf-8') as fp:
                fp.write(new_text)
            n_restored += 1
    print(f'✅ light-obf clean 完成: 恢复/清理 {n_restored} 文件, 移除标记 {n_marks_removed} 个')
    print('   注意: 只撤销了变换 D;若曾开启变换 B/A,其指令仍在(不可逆),')
    print('   完整回滚请从 fresh unpack 重新开始(开发文档 §5.1)。')
    return 0


def main(argv):
    ap = argparse.ArgumentParser(
        prog='light-obf.py',
        description='轻量混淆(变换 D 标识符 / B 数字混淆 / A 指令替换, ascii 路线)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            '--clean 语义(重要): clean 只撤销变换 D(标识符改名,靠 --map 反查),\n'
            '  不是完整回滚;变换 B/A 不可逆,完整回滚 = 重新解包原始 apk。\n'
            '--charset unicode 当前不可用(P2 定案,见开发文档 §11 附录),传了即报错。\n'
            '--flags 支持任意 d/b/a 组合(如 dab);c 属阶段 3 未实现,传了即报错。'))
    ap.add_argument('decompiled', help='apktool 解包目录')
    ap.add_argument('rules', nargs='?', help='类名规则文件(点号通配符,与 --stringenc 同语法)')
    ap.add_argument('--seed', default='', help='固定随机种子(hex);缺省由 smali 内容派生')
    ap.add_argument('--classes', default='', help='activity* 展开用的类列表文件(同 stringenc)')
    ap.add_argument('--charset', default=ACTIVE_CHARSET, choices=['ascii', 'unicode'])
    ap.add_argument('--flags', default='d', help='启用变换(组合 d/b/a;默认 d)')
    ap.add_argument('--map', dest='map_path', default='',
                    help='改名映射输出路径(JSON);--clean 时作为反查依据必填')
    ap.add_argument('--clean', action='store_true',
                    help='撤销变换 D 并清标记(需 --map;不是完整回滚,见 epilog)')
    args = ap.parse_args(argv)
    root = os.path.abspath(args.decompiled)
    if not os.path.isdir(root):
        print(f'❌ 解包目录不存在: {root}', file=sys.stderr)
        return 1
    if args.clean:
        return run_clean(args, root)
    return run_apply(args, root)


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
