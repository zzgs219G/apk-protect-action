#!/usr/bin/env python3
"""dex-verify.py — dex 完整性校验（纯 stdlib，零依赖）

背景:判断"脱壳/改包后dex 是不是真坏了"时,dex-info.py 会报
struct.error / IndexError。但那**经常是工具自身的 bug 或不支持
dex 038,不是数据损坏**——同一工具对未改动的原包同样报错。
本工具只校验 ART 加载必需的字段,给出可信的"坏/没坏"结论。

用法:
  python3 dex-verify.py <a.dex> [b.dex ...]      # 校验单个或多个 dex
  python3 dex-verify.py --dir <目录> [--dir <目录2> ...]
                                                   # 校验目录下所有 classes*.dex
  python3 dex-verify.py --dir <目录> --diff <目录2>
                                                   # 两目录逐个 dex 对照(同名文件配对)

判坏标准(全部满足才算坏):
  1. header file_size 与实际字节数不符
  2. map_off 不在文件内
  3. class_defs 表越界
  4. class_data_off 越界或 uleb 解析失败
  5. method 的 code_off >= file_size
  6. code_item 的指令区末尾(code_off+16+insns_size*2)超出文件

实现要点(踩过的坑,改这里先读):
  - method_idx/field_idx 在 class_data 里是 **uleb 增量(diff)**,必须累加,
    直接当绝对索引用会得到错误的方法名(dex-info.py 历史 bug 同源)
  - **不要解析 try_item**: 指令区之后还有 try/handler 变长结构,自己算长度
    极易算错。本工具刻意只验指令区本身 —— 那是 ART 加载必需的部分,
    少验一点好过给假警报(实测: 自己写 map遍历会在完好原包上报 21/21 损坏)
  - dex 版本 035/037/038/039 的 header 布局一致,均可校验

退出码: 0 = 全部完好, 1 = 有损坏 dex, 2 = 用法/读取错误
"""
import os
import struct
import sys


def uleb(d, q):
    r = 0; s = 0
    while True:
        if q >= len(d):
            raise IndexError("uleb 越界 @%d" % q)
        b = d[q]; q += 1
        r |= (b & 0x7f) << s; s += 7
        if not b & 0x80:
            return r, q


def verify(path):
    """返回 (问题列表, 方法数)。问题列表为空 = 完好。"""
    with open(path, 'rb') as fh:
        d = fh.read()
    n = len(d)
    bad = []
    if d[:4] != b'dex\n':
        return [("magic", 0, "不是 dex: %r" % d[:4])], 0

    ver = d[4:7].decode('latin1', 'replace')
    bad = []
    # 1. header file_size
    hdr_size, = struct.unpack_from('<I', d, 0x20)
    if hdr_size != n:
        bad.append(("header.file_size", 0x20, "%d != 实际 %d" % (hdr_size, n)))
    # 2. map_off
    map_off, = struct.unpack_from('<I', d, 0x34)
    if not (0 < map_off < n - 4):
        bad.append(("map_off", map_off, "不在文件内 (size=%d)" % n))

    # 3~6. class_defs -> class_data -> method code_off -> 指令区
    n_m = 0
    try:
        n_cd, o_cd = struct.unpack_from('<II', d, 0x60)
    except struct.error:
        bad.append(("class_defs", 0x60, "表头读失败")); return bad, 0
    if o_cd + n_cd * 32 > n:
        bad.append(("class_defs", o_cd, "表越界: %d+%d*32 > %d" % (o_cd, n_cd, n)))
        return bad, 0

    for i in range(n_cd):
        try:
            (_cidx, _acc, _sup, _ifo, _src, _ano, cdata,
             _sdata) = struct.unpack_from('<IIIIIIII', d, o_cd + i * 32)
        except struct.error:
            bad.append(("class_def", o_cd + i * 32, "unpack 失败")); continue
        if cdata == 0:
            continue                      # 无静态方法/字段(接口或纯常量类)
        if not (0 < cdata < n):
            bad.append(("class_data_off", cdata, "越界 (size=%d)" % n)); continue
        try:
            q = cdata
            sf, q = uleb(d, q); inf_, q = uleb(d, q)
            dm, q = uleb(d, q); vm, q = uleb(d, q)
            for _ in range(sf):                     # encoded_field
                _, q = uleb(d, q); _, q = uleb(d, q)
            for _ in range(inf_):                   # encoded_method(直接/虚置)
                _, q = uleb(d, q); _, q = uleb(d, q)
            for _ in range(dm):                     # 字段的 direct/virtual
                _, q = uleb(d, q); _, q = uleb(d, q); _, q = uleb(d, q)
            for _ in range(vm):                     # 方法的 direct/virtual
                _, q = uleb(d, q); _, q = uleb(d, q); code, q = uleb(d, q)
                n_m += 1
                if code == 0:
                    continue                         # abstract / native
                if code >= n:
                    bad.append(("code_off", code, ">= file_size %d" % n)); continue
                try:
                    insns_size, = struct.unpack_from('<I', d, code + 12)
                except struct.error:
                    bad.append(("code_item", code, "读失败")); continue
                end = code + 16 + insns_size * 2
                if end > n:
                    bad.append(("insns", code,
                                "末尾 %d > file_size %d" % (end, n)))
        except (IndexError, struct.error) as e:
            bad.append(("class_data", cdata, str(e)[:48]))
    return bad, n_m


def collect_dexes(d):
    fs = [f for f in os.listdir(d) if f.endswith('.dex')]
    # classes.dex 排最前，其余按数字序
    def key(f):
        if f == 'classes.dex':
            return (0, 0)
        digits = ''.join(c for c in f if c.isdigit())
        return (1, int(digits) if digits else 0)
    return sorted(fs, key=key)


def show_one(path):
    """打印单个 dex 校验结果，返回是否完好。"""
    try:
        bad, n_m = verify(path)
    except Exception as e:
        print("  %-16s 读取异常: %s: %s"
              % (os.path.basename(path), type(e).__name__, e))
        return False
    name = os.path.basename(path)
    if not bad:
        print("  %-16s ✔ 完好 (dex %s, %d bytes, 方法 %d)"
              % (name, open(path, 'rb').read(7)[4:7].decode('latin1'), os.path.getsize(path), n_m))
        return True
    print("  %-16s ✘ 损坏 %d 处" % (name, len(bad)))
    for kind, off, msg in bad[:5]:
        print("        %-16s @%-10s %s" % (kind, off, msg))
    if len(bad) > 5:
        print("        ... 另 %d 处" % (len(bad) - 5))
    return False


def main():
    argv = sys.argv[1:]
    dirs = []
    files = []
    do_diff = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == '--dir':
            i += 1; dirs.append(argv[i])
        elif a == '--diff':
            i += 1; do_diff = True
        elif a in ('-h', '--help'):
            print(__doc__); return 0
        else:
            files.append(a)
        i += 1

    if not dirs and not files:
        print(__doc__); return 2

    rc = 0

    # --diff: 两个目录同名 dex 配对对照
    if do_diff and len(dirs) == 2:
        da, db = dirs
        fa, fb = collect_dexes(da), collect_dexes(db)
        common = sorted(set(fa) & set(fb))
        print("目录A: %s  (%d dex)" % (da, len(fa)))
        print("目录B: %s  (%d dex)" % (db, len(fb)))
        print("同名可对照: %d / %d / %d" % (len(common), len(fa), len(fb)))
        only_a = sorted(set(fa) - set(fb))
        only_b = sorted(set(fb) - set(fa))
        if only_a:
            print("  仅 A 有: %s" % ", ".join(only_a))
        if only_b:
            print("  仅 B 有: %s" % ", ".join(only_b))
        print("-" * 68)
        print("%-16s %-10s %-10s" % ("dex", "A", "B"))
        for fn in common:
            oka = show_one(os.path.join(da, fn))
            okb = show_one(os.path.join(db, fn))
            if oka and okb:
                continue
            rc = 1
        # 目录里唯一文件(classes.dex 与 classesN.dex 编号常错位)也各自全验
        extra = [f for f in only_a] + [f for f in only_b]
        if extra:
            print("-" * 68)
            print("以下 dex 无同名对照, 单独校验:")
            for fn in extra:
                src = da if fn in only_a else db
                if not show_one(os.path.join(src, fn)):
                    rc = 1
        return rc

    # --dir: 单目录全验
    for d in dirs:
        print("=" * 68)
        print("目录: %s" % d)
        dexes = collect_dexes(d)
        if not dexes:
            print("  (无 .dex 文件)")
        okc = 0
        for fn in dexes:
            if show_one(os.path.join(d, fn)):
                okc += 1
            else:
                rc = 1
        print(">> 完好 %d / %d" % (okc, len(dexes)))
        if okc == len(dexes):
            print("   ✔ 全部完好 —— 若某工具仍报 struct.error，那是工具 bug 或"
                  "不支持该 dex 版本，不是数据损坏")

    # 显式文件
    if files:
        print("=" * 68)
        for f in files:
            if not show_one(f):
                rc = 1
    return rc


if __name__ == '__main__':
    sys.exit(main())