#!/usr/bin/env python3
"""patch-debuggable.py — 二进制 AXML 原位改写 android:debuggable（强制 false）。

背景（逆向分析报告 v2 §8 F-11 的直接修复）：
  报告原文："debuggable=true + extractNativeLibs=true → so 落盘可直接替换、
  可 run-as 读写应用目录。虽然后续校验会拦，但给了攻击者替换+观察的便利。"

  实测确认该问题存在：测试 APK 的 Manifest 里 debuggable=true。
  release 产物必须是 false —— 否则：
    · `run-as <pkg>` 可进入应用私有目录、读写、dump 内存
    · 调试器可直接 attach（绕过我们那套 ptrace/PR_SET_DUMPABLE 的前提）
    · `adb shell am set-debug-app` 等工具链全线可用

⚠️ 与 patch-extractnativelibs.py 的关键差异：属性**可能不存在**。
  extractNativeLibs 是流水线自己设的（必然存在），而 debuggable 是原 App
  可写可不写 —— AXML 里没有该属性时，其语义就是"false"（Android 默认值）。
  因此本脚本在"属性不存在"时返回【成功且无需改写】，而不是报错。
  这与 extractNativeLibs 的处置相反，原因就在这里：两者缺省语义不同。

  反例（为什么不能照抄）：若照搬"属性不存在即报错"，绝大多数正常 App
  都会构建失败 —— 因为它们本来就不写 debuggable。

实现：
  - BOOLEAN 属性（type=0x12）原位等尺寸改写 data 字段，不重建 AXML、
    不改任何偏移，文件大小不变。
  - 幂等：已是 false 直接跳过。

用法：
    patch-debuggable.py <解包目录>/AndroidManifest.xml
退出码: 0=已改写 / 已是 false / 属性不存在（三者都算成功）
        1=解析失败或类型异常（不可恢复）
"""
import struct
import sys

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
ATTR_TYPE_BOOLEAN = 0x12
STRING_POOL_UTF8_FLAG = 0x100


def _iter_chunks(data):
    """遍历 AXML 顶层 chunk，yield (offset, type, size)。"""
    off = 8  # 跳过 ResXMLTree_header(8)
    n = len(data)
    while off + 8 <= n:
        ctype, _hsize, csize = struct.unpack_from('<HHI', data, off)
        if csize < 8 or off + csize > n:
            break
        yield off, ctype, csize
        off += csize


def _parse_string_pool(data, off):
    """解析字符串池，返回 (utf8: bool, strings: list[str])。"""
    _ctype, _hsize, _size = struct.unpack_from('<HHI', data, off)
    strcount, _stylecount, flags = struct.unpack_from('<III', data, off + 8)
    strstart, _stylestart = struct.unpack_from('<II', data, off + 20)
    utf8 = bool(flags & STRING_POOL_UTF8_FLAG)
    offsets = struct.unpack_from(f'<{strcount}I', data, off + 28)
    base = off + strstart
    strings = []
    for o in offsets:
        p = base + o
        if utf8:
            _u16len = data[p]; p += 1
            if _u16len & 0x80:
                _u16len = ((_u16len & 0x7F) << 8) | data[p]; p += 1
            n = data[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p]; p += 1
            strings.append(data[p:p + n].decode('utf-8', 'replace'))
        else:
            n = data[p] | (data[p + 1] << 8); p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | (data[p] | (data[p + 1] << 8)); p += 2
            strings.append(data[p:p + n * 2].decode('utf-16-le', 'replace'))
    return utf8, strings


def patch_manifest(path):
    """把 application/debuggable 强制改为 false。
    返回 (changed: int, msg: str)。属性不存在时 changed=0 且不算错误。"""
    with open(path, 'rb') as fp:
        data = bytearray(fp.read())

    if data[:4] != b'\x03\x00\x08\x00':
        raise ValueError('不是二进制 AXML（头 4 字节应为 03 00 08 00）')

    pool = None
    for off, ctype, _size in _iter_chunks(data):
        if ctype == RES_STRING_POOL_TYPE:
            pool = _parse_string_pool(data, off)
            break
    if pool is None:
        raise ValueError('AXML 中未找到字符串池')
    _utf8, strings = pool

    name_idx = None
    for i, s in enumerate(strings):
        if s == 'debuggable':
            name_idx = i
            break
    if name_idx is None:
        # 字符串池里没有这个属性名 → manifest 根本没写 debuggable
        # → 语义等价于 false（Android 默认）→ 无需改写，返回成功
        return 0, '字符串池无 debuggable 条目（未设置 = 默认 false，无需改写）'

    hits = []
    for off, ctype, _size in _iter_chunks(data):
        if ctype != RES_XML_START_ELEMENT_TYPE:
            continue
        base = off + 16
        attr_start, attr_size, attr_count = struct.unpack_from('<HHH', data, base + 8)
        if attr_size < 20:
            raise ValueError(f'attribute 结构异常: attr_size={attr_size}')
        abase = off + 16 + attr_start
        for k in range(attr_count):
            ao = abase + k * attr_size
            _ns, aname, _raw = struct.unpack_from('<III', data, ao)
            tsize, _res0, ttype, tdata = struct.unpack_from('<HBBI', data, ao + 12)
            if aname == name_idx:
                hits.append((ao, ttype, tdata, tsize))

    if not hits:
        # 字符串池有该名字但没有元素真正使用它（罕见：池里残留），
        # 同样视为"未设置"→ 默认 false
        return 0, 'debuggable 未被任何元素使用（默认 false，无需改写）'

    changed = 0
    for ao, ttype, tdata, _tsize in hits:
        data_off = ao + 16   # ns(4)+name(4)+raw(4)+size(2)+res0(1)+type(1)+data(4)
        if ttype != ATTR_TYPE_BOOLEAN:
            raise ValueError(
                f'debuggable 类型异常: type=0x{ttype:02x}（应为 BOOLEAN 0x12）'
                f' —— 不重建 AXML，宁失败也不产出错包')
        if tdata != 0:
            struct.pack_into('<I', data, data_off, 0)
            changed += 1
        # tdata == 0 已是 false，幂等跳过

    if changed:
        with open(path, 'wb') as fp:
            fp.write(data)
    return changed, f'{changed} 处改写（共 {len(hits)} 处该属性）'


def _main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    path = sys.argv[1]
    try:
        changed, msg = patch_manifest(path)
    except (ValueError, OSError) as e:
        print(f'❌ {e}', file=sys.stderr)
        return 1
    if changed:
        print(f'✅ debuggable → false: {msg}')
    else:
        print(f'ℹ️ debuggable 无需改写: {msg}')
    return 0


if __name__ == '__main__':
    sys.exit(_main())
