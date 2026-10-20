#!/usr/bin/env python3
"""mk_manifest.py — 生成最小二进制 AndroidManifest.xml(AXML)测试夹具。

背景:inject-javacheck 的宿主冒烟需要二进制 AXML;本机(ARM)aapt2 是 x86 ELF
跑不了,apktool b 不可用。按 AXML 规范手工编码最小 manifest(UTF-8 字符串池),
生成后立即用 dcc 内置 AXMLPrinter 解析自检(自检不过 = 生成器有 bug,fail-fast)。
属性名直接入字符串池(AXMLPrinter.getAttributeName 优先读池内名字,
resource map 缺失不影响)。

用法: python3 mk_manifest.py <输出路径> [包名]
"""
import re
import struct
import sys

NS_ANDROID = 'http://schemas.android.com/apk/res/android'

# 字符串池(顺序即索引,显式列出保证确定性)
STRINGS = [
    'manifest',                                # 0
    'package',                                 # 1
    'com.test.jc',                             # 2  (占位,运行时替换)
    'versionCode',                             # 3
    '1',                                       # 4
    'versionName',                             # 5
    '1.0',                                     # 6
    'android',                                 # 7
    NS_ANDROID,                                # 8
    'application',                             # 9
    'label',                                   # 10
    'JC',                                      # 11
    'name',                                    # 12
    'com.test.jc.App',                         # 13 (占位)
    'activity',                                # 14
    'com.test.jc.MainActivity',                # 15 (占位)
    'exported',                                # 16
    'true',                                    # 17
    'intent-filter',                           # 18
    'action',                                  # 19
    'android.intent.action.MAIN',              # 20
    'category',                                # 21
    'android.intent.category.LAUNCHER',        # 22
    'com.test.jc.Secondary',                   # 23 (占位,第二个 LAUNCHER)
]
IDX = {s: i for i, s in enumerate(STRINGS)}
_CUR_IDX = IDX          # build_manifest 运行时替换为"当前池"索引(包名等可变串)


def _enc_len(v):
    """UTF-8 池长度编码:<0x80 单字节;否则两字节(高位标记 + 低 8 位)。"""
    if v < 0x80:
        return bytes([v])
    return bytes([0x80 | (v >> 8), v & 0xFF])


def build_string_pool(strings):
    data = b''
    offsets = []
    for s in strings:
        offsets.append(len(data))
        b = s.encode('utf-8')
        data += _enc_len(len(s)) + _enc_len(len(b)) + b + b'\x00'
    while len(data) % 4:
        data += b'\x00'
    strings_start = 28 + 4 * len(strings)
    chunk_size = strings_start + len(data)
    head = struct.pack('<HHIIIIII', 0x0001, 28, chunk_size,
                       len(strings), 0, 0x100, strings_start, 0)
    return head + b''.join(struct.pack('<I', o) for o in offsets) + data


def _xml_node(node_type, lineno, payload):
    size = 16 + len(payload)
    return (struct.pack('<HHI', node_type, 16, size)
            + struct.pack('<II', lineno, 0xFFFFFFFF) + payload)


def _attr(name, raw=None, dtype=0x03, data=0, android_ns=True):
    ns_i = IDX[NS_ANDROID] if android_ns else 0xFFFFFFFF
    raw_i = _CUR_IDX[raw] if raw is not None else 0xFFFFFFFF
    return (struct.pack('<III', ns_i, _CUR_IDX[name], raw_i)
            + struct.pack('<HBBI', 8, 0, dtype, data))


def _start_element(lineno, elem, attrs):
    payload = struct.pack('<II', 0xFFFFFFFF, _CUR_IDX[elem])
    payload += struct.pack('<HHHHHH', 20, 20, len(attrs), 0, 0, 0)
    return _xml_node(0x0102, lineno, payload + b''.join(attrs))


def _end_element(lineno, elem):
    return _xml_node(0x0103, lineno, struct.pack('<II', 0xFFFFFFFF, _CUR_IDX[elem]))


def build_manifest(package, app_class, launcher1, launcher2):
    # 占位索引 2/13/15/23 分别对应 4 个可替换串
    remap = {IDX['com.test.jc']: package,
             IDX['com.test.jc.App']: app_class,
             IDX['com.test.jc.MainActivity']: launcher1,
             IDX['com.test.jc.Secondary']: launcher2}
    pool_strings = [remap.get(i, s) for i, s in enumerate(STRINGS)]
    pool = build_string_pool(pool_strings)
    global _CUR_IDX
    _CUR_IDX = {s: i for i, s in enumerate(pool_strings)}

    body = _xml_node(0x0100, 1, struct.pack('<II', IDX['android'], IDX[NS_ANDROID]))
    body += _start_element(2, 'manifest', [
        _attr('package', package, android_ns=False),
        _attr('versionCode', '1', dtype=0x10, data=1),
        _attr('versionName', '1.0'),
    ])
    body += _start_element(3, 'application', [
        _attr('label', 'JC'),
        _attr('name', app_class),
    ])
    body += _start_element(4, 'activity', [
        _attr('name', launcher1),
        _attr('exported', 'true', dtype=0x12, data=0xFFFFFFFF),
    ])
    body += _start_element(5, 'intent-filter', [])
    body += _start_element(6, 'action', [_attr('name', 'android.intent.action.MAIN')])
    body += _end_element(7, 'action')
    body += _start_element(8, 'category',
                           [_attr('name', 'android.intent.category.LAUNCHER')])
    body += _end_element(9, 'category')
    body += _end_element(10, 'intent-filter')
    body += _end_element(11, 'activity')
    body += _start_element(12, 'activity', [
        _attr('name', launcher2),
        _attr('exported', 'true', dtype=0x12, data=0xFFFFFFFF),
    ])
    body += _start_element(13, 'intent-filter', [])
    body += _start_element(14, 'action', [_attr('name', 'android.intent.action.MAIN')])
    body += _end_element(15, 'action')
    body += _start_element(16, 'category',
                           [_attr('name', 'android.intent.category.LAUNCHER')])
    body += _end_element(17, 'category')
    body += _end_element(18, 'intent-filter')
    body += _end_element(19, 'activity')
    body += _end_element(20, 'application')
    body += _end_element(21, 'manifest')
    body += _xml_node(0x0101, 22, struct.pack('<II', IDX['android'], IDX[NS_ANDROID]))

    total = 8 + len(pool) + len(body)
    return struct.pack('<HHI', 0x0003, 8, total) + pool + body


def self_check(path, package, app_class, launcher1):
    """生成即自检:必须能被 AXMLPrinter 解析出全部关键信息,否则 fail-fast。"""
    import os
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(
        os.path.abspath(__file__)), '..', '..', '..', '..', 'tools', 'Dex2C')))
    from androguard.core.bytecodes.axml import AXMLPrinter
    with open(path, 'rb') as fp:
        raw = fp.read()
    assert raw[:4] == b'\x03\x00\x08\x00', f'AXML 魔数不对: {raw[:4].hex()}'
    xml = AXMLPrinter(raw).get_xml()
    if isinstance(xml, bytes):
        xml = xml.decode('utf-8', 'replace')
    assert f'package="{package}"' in xml, f'package 解析失败:\n{xml}'
    assert f'android:name="{app_class}"' in xml, f'application name 解析失败:\n{xml}'
    assert f'android:name="{launcher1}"' in xml, f'activity name 解析失败:\n{xml}'
    assert xml.count('android.intent.category.LAUNCHER') >= 2, 'LAUNCHER 数量不对'
    return xml


def main():
    out = sys.argv[1]
    package = sys.argv[2] if len(sys.argv) > 2 else 'com.test.jc'
    app_class = sys.argv[3] if len(sys.argv) > 3 else f'{package}.App'
    launcher1 = sys.argv[4] if len(sys.argv) > 4 else f'{package}.MainActivity'
    launcher2 = sys.argv[5] if len(sys.argv) > 5 else f'{package}.Secondary'
    data = build_manifest(package, app_class, launcher1, launcher2)
    with open(out, 'wb') as fp:
        fp.write(data)
    xml = self_check(out, package, app_class, launcher1)
    print(f'✅ AXML 夹具已生成并自检通过: {out} ({len(data)} bytes)')
    print('--- AXMLPrinter 解析预览 ---')
    print(xml)


if __name__ == '__main__':
    main()
