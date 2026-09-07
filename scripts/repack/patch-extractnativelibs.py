#!/usr/bin/env python3
"""patch-extractnativelibs.py — 二进制 AXML 原位改写 extractNativeLibs(可复用基础模块)。

背景(报错五的修复,详见 docs/流程文档.md):
  apktool `d -r` 模式解包时,顶层 AndroidManifest.xml 若保持二进制(去掉
  --force-manifest),build 会原样拷回,产物才是合法 AXML。但二进制 manifest
  无法用 sed 改文本属性 —— 本脚本直接解析 AXML 的 START_ELEMENT 属性结构,
  把 <application> 的 android:extractNativeLibs 在原位从 false 改写为 true。

实现要点:
  - BOOLEAN 属性(false=0x12/data=0x00000000, true=0x12/data=0xFFFFFFFF),
    原位等尺寸改写,文件大小与所有偏移不变,无需重建字符串池。
  - 若属性不存在,在 <application> 的 attribute 数组末尾"借用"一个空闲槽位
    是不可行的(需扩容重排所有偏移),此时退化为报错退出(方案红线:
    不重建 AXML,宁可失败也不产出错包)。
  - 幂等:已是 true 时直接跳过。

用法:
    patch-extractnativelibs.py <解包目录>/AndroidManifest.xml
退出码: 0=已改写或已是 true; 1=解析失败/属性不存在等不可恢复错误
"""
import struct
import sys

RES_STRING_POOL_TYPE = 0x0001
RES_XML_START_ELEMENT_TYPE = 0x0102
ATTR_TYPE_BOOLEAN = 0x12
STRING_POOL_UTF8_FLAG = 0x100


def _parse_string_pool(data, off):
    """解析字符串池,返回 (utf8: bool, strings: list[str])。"""
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
            # u16len(可能 2 字节) + u8 len + 数据
            _u16len = data[p]; p += 1
            if _u16len & 0x80:
                _u16len = ((_u16len & 0x7F) << 8) | data[p]; p += 1
            n = data[p]; p += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | data[p]; p += 1
            strings.append(data[p:p + n].decode('utf-8', 'replace'))
        else:
            n = struct.unpack_from('<H', data, p)[0]; p += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from('<H', data, p)[0]
                p += 2
            strings.append(data[p:p + 2 * n].decode('utf-16-le', 'replace'))
    return utf8, strings


def _iter_chunks(data):
    off = 8  # 跳过文件头(ResChunk_header)
    while off + 8 <= len(data):
        ctype, _hsize, size = struct.unpack_from('<HHI', data, off)
        if size < 8 or off + size > len(data):
            return
        yield off, ctype, size
        off += size


def patch_manifest(path):
    """把 path 指向的二进制 AXML 的 application/extractNativeLibs 改为 true。
    返回 (changed: bool, message: str)。文件不存在/非 AXML 抛异常。"""
    with open(path, 'rb') as fp:
        data = bytearray(fp.read())

    if data[:4] != b'\x03\x00\x08\x00':
        raise ValueError('不是二进制 AXML(头 4 字节应为 03 00 08 00)')

    # 1. 找字符串池,建立 name -> 索引 反查
    pool = None
    for off, ctype, size in _iter_chunks(data):
        if ctype == RES_STRING_POOL_TYPE:
            pool = _parse_string_pool(data, off)
            break
    if pool is None:
        raise ValueError('AXML 中未找到字符串池')
    _utf8, strings = pool
    name_idx = None
    for i, s in enumerate(strings):
        if s == 'extractNativeLibs':
            name_idx = i
            break
    if name_idx is None:
        raise ValueError('字符串池中无 extractNativeLibs 条目'
                         '(极少见的精简 manifest,暂不支持新增属性)')

    # 2. 找所有 START_ELEMENT,在其中定位 name 索引 == name_idx 的 attribute
    NO_INDEX = 0xFFFFFFFF
    hits = []  # (attr 绝对偏移, type, data)
    for off, ctype, size in _iter_chunks(data):
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
        raise ValueError('manifest 中不存在 extractNativeLibs 属性'
                         '(原包没写该属性;需新增属性必须重建 AXML,超出本脚本职责)')

    changed = 0
    for ao, ttype, tdata, _tsize in hits:
        data_off = ao + 16  # attribute: ns(4)+name(4)+raw(4)+size(2)+res0(1)+type(1)+data(4)
        if ttype == ATTR_TYPE_BOOLEAN and tdata == 0:
            struct.pack_into('<I', data, data_off, 0xFFFFFFFF)
            changed += 1
        elif ttype == ATTR_TYPE_BOOLEAN and tdata != 0:
            pass  # 已是 true,幂等
        else:
            raise ValueError(f'extractNativeLibs 类型异常: type=0x{ttype:02x} data=0x{tdata:08x}')

    if changed:
        with open(path, 'wb') as fp:
            fp.write(data)
    return changed, f'{changed} 处改写(共 {len(hits)} 处该属性)'


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
        print(f'✅ extractNativeLibs → true: {msg}')
    else:
        print(f'ℹ️ extractNativeLibs 已是 true,跳过: {msg}')
    return 0


if __name__ == '__main__':
    sys.exit(_main())
