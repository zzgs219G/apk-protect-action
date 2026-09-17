#!/usr/bin/env python3
"""dex-info.py — AI 复用的 DEX 结构查看/对比工具（纯 stdlib，零依赖）

背景：AI 分析 dex 对比时不应每次重写解析脚本。本工具是仓库内的
标准入口，AI 接到 dex 分析任务时**先用它**，不要从零造轮子。

用法:
  python3 dex-info.py summary <a.dex>              # 总览: 表规模+类/方法统计
  python3 dex-info.py methods <a.dex> [--limit N]  # 全部方法: 类名/方法名/寄存器/指令数
  python3 dex-info.py strings <a.dex> [--only-new] # 字符串表
  python3 dex-info.py diff <a.dex> <b.dex>         # 两 dex 的结构+字符串差异

实现要点(踩过的坑，改这里先读):
  - header 表偏移: string_ids@0x38 type_ids@0x40 proto_ids@0x48
    field_ids@0x50 method_ids@0x58 class_defs@0x60 (size u32 + off u32)
  - method_id/field_id 布局: u16 + u16 + u32 = 8 字节(不是 12!)
  - proto_id: u32 shorty + u32 return_type + u32 params_off = 12 字节
  - class_data 里 field_idx/method_idx 是 **uleb 增量(diff)**，必须累加，
    直接当绝对索引用会得到错误的方法名(历史 bug: 满屏同名方法是这个假象)
  - code_item 头: registers u16, ins u16, outs u16, tries u16,
    debug_info_off u32, insns_size u32 —— 共 16 字节，insns 从 +16 开始
"""
import struct
import sys

def uleb(d, q):
    r = 0; s = 0
    while True:
        b = d[q]; q += 1
        r |= (b & 0x7f) << s; s += 7
        if not b & 0x80:
            return r, q

class Dex:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        if d[:4] != b'dex\n':
            raise ValueError(f"not a dex file: {path}")
        # 各 id 表: (size, off)
        self.tab = {n: struct.unpack_from('<II', d, o)
                    for n, o in [('string', 0x38), ('type', 0x40), ('proto', 0x48),
                                 ('field', 0x50), ('method', 0x58), ('class', 0x60)]}
        self.str_off = self.tab['string'][1]
        self.typ_off = self.tab['type'][1]

    def string(self, idx):
        so, = struct.unpack_from('<I', self.d, self.str_off + idx * 4)
        p = so
        _, p = uleb(self.d, p)          # uleb128 长度前缀
        end = self.d.find(b'\x00', p)
        return self.d[p:end].decode('utf-8', 'replace')

    def type_str(self, idx):
        ti, = struct.unpack_from('<I', self.d, self.typ_off + idx * 4)
        return self.string(ti)

    def method_sig(self, idx):
        cls, _proto, name = struct.unpack_from('<HHI', self.d, self._moff(idx))
        return f"{self.type_str(cls)}->{self.string(name)}"

    def field_sig(self, idx):
        cls, typ, name = struct.unpack_from('<HHI', self.d, self._foff(idx))
        return f"{self.type_str(cls)}.{self.string(name)}:{self.type_str(typ)}"

    def _moff(self, idx):
        _, off = self.tab['method']; return off + idx * 8
    def _foff(self, idx):
        _, off = self.tab['field']; return off + idx * 8

    def classes(self):
        """yield (class_name, fields[(idx,acc)], methods[(idx,acc,code_off)])"""
        cnt, off = self.tab['class']
        d = self.d
        for i in range(cnt):
            cd = off + i * 32
            cls_idx, = struct.unpack_from('<I', d, cd)
            cdo, = struct.unpack_from('<I', d, cd + 24)
            name = self.type_str(cls_idx)
            fields, methods = [], []
            if cdo:
                q = cdo
                sf, q = uleb(d, q); inf_, q = uleb(d, q)
                dm, q = uleb(d, q); vm, q = uleb(d, q)
                idx = 0
                for _ in range(sf + inf_):          # encoded_field: idx 是增量
                    diff, q = uleb(d, q); acc, q = uleb(d, q)
                    idx += diff; fields.append((idx, acc))
                idx = 0
                for _ in range(dm + vm):            # encoded_method: idx 是增量
                    diff, q = uleb(d, q); acc, q = uleb(d, q); code_off, q = uleb(d, q)
                    idx += diff; methods.append((idx, acc, code_off))
            yield name, fields, methods

    def code_stats(self, code_off):
        """返回 (registers, insns_units, tries) 或 None(抽象/native)"""
        d = self.d
        if code_off == 0:
            return None
        regs, ins, outs, tries = struct.unpack_from('<HHHH', d, code_off)
        insns_sz, = struct.unpack_from('<I', d, code_off + 12)
        return regs, insns_sz, tries


def _printable(b):
    s = b.decode('utf-8', 'replace')
    return ''.join(c if c.isprintable() else f'\\u{ord(c):04x}' for c in s)

def cmd_summary(path):
    dx = Dex(path)
    n_cls = n_meth = n_meth_code = 0
    insn_total = 0
    biggest = (0, '')
    for cname, _, methods in dx.classes():
        n_cls += 1
        for idx, acc, co in methods:
            n_meth += 1
            st = dx.code_stats(co)
            if st:
                n_meth_code += 1
                insn_total += st[1]
                if st[1] > biggest[0]:
                    biggest = (st[1], dx.method_sig(idx))
    for k, (sz, _) in dx.tab.items():
        print(f"{k:>8}_ids: {sz}")
    print(f"  classes: {n_cls}   methods: {n_meth} (with code: {n_meth_code})")
    print(f"  insns units total: {insn_total}")
    print(f"  biggest method: {biggest[1]} ({biggest[0]} units)")

def cmd_methods(path, limit):
    dx = Dex(path)
    shown = 0
    for cname, _, methods in dx.classes():
        for idx, acc, co in methods:
            st = dx.code_stats(co)
            if st:
                regs, isz, tries = st
                print(f"{cname} -> {dx.string(_name_idx(dx, idx))}"
                      f"  regs={regs} insns={isz} tries={tries} acc={acc:#x}")
                shown += 1
                if limit and shown >= limit:
                    return

def _name_idx(dx, method_idx):
    cls, _p, name = struct.unpack_from('<HHI', dx.d, dx._moff(method_idx))
    return name

def cmd_strings(path, only_new, other=None):
    dx = Dex(path)
    ssz, _ = dx.tab['string']
    strs = [dx.string(i) for i in range(ssz)]
    if only_new and other:
        d2 = Dex(other)
        s2, _ = d2.tab['string']
        old = {d2.string(i) for i in range(s2)}
        strs = [s for s in strs if s not in old]
    for s in strs:
        print(_printable(s.encode()))

def cmd_diff(a, b):
    da, db = Dex(a), Dex(b)
    print(f"── id 表规模对比 (a={a} / b={b}) ──")
    for k in da.tab:
        sa, _ = da.tab[k]; sb, _ = db.tab[k]
        mark = ' ←' if sa != sb else ''
        print(f"  {k:>8}: {sa:>5} / {sb:>5}{mark}")
    print("── b 中新增的字符串(前 60) ──")
    sa_sz, _ = da.tab['string']; sb_sz, _ = db.tab['string']
    old = {da.string(i) for i in range(sa_sz)}
    n = 0
    for i in range(sb_sz):
        s = db.string(i)
        if s not in old:
            print(f"  + {_printable(s.encode())}")
            n += 1
            if n >= 60:
                print("  ...(截断)")
                break
    print("── 方法数对比 ──")
    for tag, d in (('a', da), ('b', db)):
        cnt = sum(len(ms) for _, _, ms in d.classes())
        print(f"  {tag}: {cnt} methods")

def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__); sys.exit(1)
    cmd = argv[0]
    if cmd == 'summary':
        cmd_summary(argv[1])
    elif cmd == 'methods':
        lim = int(argv[argv.index('--limit') + 1]) if '--limit' in argv else 0
        cmd_methods(argv[1], lim)
    elif cmd == 'strings':
        on = '--only-new' in argv
        other = argv[-1] if on and len(argv) > 3 else None
        cmd_strings(argv[1], on, other)
    elif cmd == 'diff':
        cmd_diff(argv[1], argv[2])
    else:
        print(__doc__); sys.exit(1)

if __name__ == '__main__':
    main()
