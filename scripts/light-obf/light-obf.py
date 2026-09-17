#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""light-obf.py — 轻量混淆模块(阶段 1: 变换 D 标识符混淆,ascii 路线)。

设计文档: docs/开发文档-light-obf.md (v3)。零方法新增、零膨胀(字符串表除外),
只做 smali 层明确 private 成员改名,性能代价 = 0(红线 1~8 全文见文档 §3.2)。

改名范围(变换 D,§4):
  ① .method/.field private 声明行;② 全部 smali 文件里对该成员的
  `Ldesc;->name(` / `Ldesc;->name:` 引用;③ access$ 桥体内引用(②的自然
  结果,桥名本身不改,§7.2)。改名不碰字符串字面量(沿用 anti-diff 的
  _replace_outside_strings 掩码机制)。

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

阶段状态(§6):仅变换 d(标识符)已实现;--flags 传 b/a/c 即 fail-fast
(阶段 2/3 未实施,绝不静默忽略用户勾选)。
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

SKIP_CLASS_PREFIXES = _ANTIDIFF.SKIP_CLASS_PREFIXES   # 与 anti-diff 同一份名单(§5.5)
EXTRA_SKIP_PREFIXES = ('com.nc.',)                    # light-obf 特有追加(§5.5 🔴1)
CLASS_MARK = '# nc-lightobf-applied v1'               # 幂等标记(与 antidiff 各自独立判定)
BA_MARK_TOKEN = 'nc-lightobf-ba'                      # 阶段 2 B/A 特征标记 token(clean fail-fast 锚)
ACTIVE_CHARSET = 'ascii'                              # P2 定案(开发文档 §11 附录)


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
        if ch != 'd':
            raise SystemExit(
                f'❌ 变换 {ch.upper()} 属于阶段 2/3,尚未实现(开发文档 §6)。'
                f'当前仅支持 --flags d。绝不静默忽略未实现的勾选。')
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
        if new_text != text:
            assert len(new_text) >= n_before, rel   # 改名只增不减(防误删)
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
        description='轻量混淆(阶段 1: 变换 D 标识符混淆, ascii 路线)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            '--clean 语义(重要): clean 只撤销变换 D(标识符改名,靠 --map 反查),\n'
            '  不是完整回滚;变换 B/A 不可逆,完整回滚 = 重新解包原始 apk。\n'
            '--charset unicode 当前不可用(P2 定案,见开发文档 §11 附录),传了即报错。\n'
            '--flags 当前仅支持 d(变换 B/A/C 属阶段 2/3,未实现,传了即报错)。'))
    ap.add_argument('decompiled', help='apktool 解包目录')
    ap.add_argument('rules', nargs='?', help='类名规则文件(点号通配符,与 --stringenc 同语法)')
    ap.add_argument('--seed', default='', help='固定随机种子(hex);缺省由 smali 内容派生')
    ap.add_argument('--classes', default='', help='activity* 展开用的类列表文件(同 stringenc)')
    ap.add_argument('--charset', default=ACTIVE_CHARSET, choices=['ascii', 'unicode'])
    ap.add_argument('--flags', default='d', help='启用变换(当前仅 d;默认 d)')
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
