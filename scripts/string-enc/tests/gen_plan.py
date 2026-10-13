"""P3 双端对拍 —— Python 侧参考实现(只含算法,不含任何加密脚本依赖)。

用途:证明 §3.3 的 splitmix64 密钥流在 Python 与 Java 两侧逐字节一致。
Java 侧用编译好的真实桩类 StrDec(反射调用 keyByte/mix64/d),不是"另一份等价代码"。
"""
import base64
import json
import sys

MASK64 = (1 << 64) - 1
GAMMA = 0x9E3779B97F4A7C15
M1 = 0xBF58476D1CE4E5B9
M2 = 0x94D049BB133111EB


def _mix(z: int) -> int:
    z = (z ^ (z >> 30)) & MASK64
    z = (z * M1) & MASK64
    z = (z ^ (z >> 27)) & MASK64
    z = (z * M2) & MASK64
    return (z ^ (z >> 31)) & MASK64


def key_byte(seed: int, i: int) -> int:
    """密钥流第 i 个字节,O(1) 现算(与 StrDec.java 的 keyByte 对应)。"""
    w = _mix((seed + (i >> 3) * GAMMA) & MASK64)
    return (w >> ((i & 7) * 8)) & 0xFF


def encrypt_payload(seed: int, offset: int, plain: bytes) -> str:
    """明文 → Base64( offset_be24 || cipher ),与桩 d() 对应。"""
    head = bytes(((offset >> 16) & 0xFF, (offset >> 8) & 0xFF, offset & 0xFF))
    cipher = bytes(b ^ key_byte(seed, offset + k) for k, b in enumerate(plain))
    return base64.b64encode(head + cipher).decode('ascii')


# ── 对拍样本(§8.1: 空串/ASCII/中文/emoji 代理对/最长串/转义) ──────────
def build_samples():
    samples = []
    samples.append((''))                                   # 空串
    samples.append(('hello world'))                        # 纯 ASCII
    samples.append(('https://api.example.com/v1/token'))   # 典型 URL
    samples.append(('中文测试:简盒加固'))                     # 中文(3 字节 UTF-8)
    samples.append(('emoji 🎉🚀 代理对'))                    # emoji(4 字节 UTF-8 / 代理对)
    samples.append(('混合 a中🎉z'))                          # 混合
    samples.append(('\n\t\r\b\f"\'\\'))                    # 各类转义字符
    samples.append(('x' * 5188))                           # 最长串(doc §2.2 A1)
    samples.append(('\u0000\u0001\u007f\u0080\uffff'))     # 边界码点
    samples.append(('Ｆｕｌｌｗｉｄｔｈ 全角'))                  # 全角
    return samples


def build_plan(only_seed=None):
    """生成对拍计划:每条样本一个 (seed, offset, plain_hex, payload) 用例。

    offset 刻意取非 8 对齐值与跨 64 位块边界值,锁定 `i>>>3` / `i&7` 的易错点。
    only_seed: 只生成该种子(16 位 hex)的用例 —— 全链对拍按种子分组时用。
    """
    cases = []
    seeds = [0x5EED000000000000, 0x0123456789ABCDEF,
             0xFFFFFFFFFFFFFFFF, 0x0000000000000001]
    if only_seed is not None:
        seeds = [int(only_seed, 16)]
    offsets = [0, 1, 7, 8, 9, 65535, 65536, 0xFFFFFF - 32]
    for seed in seeds:
        for sample in build_samples():
            plain = sample.encode('utf-8')
            for off in offsets:
                payload = encrypt_payload(seed, off, plain)
                cases.append({
                    'seed_hex': f'{seed:016x}',
                    'offset': off,
                    'plain_hex': plain.hex(),
                    'payload': payload,
                })
    # 单字节密钥流全扫:256 个连续位置,锁死字节序/位移方向
    for seed in seeds:
        for off in (0, 8, 1234567, 0xFFFFFF - 256):
            ks = bytes(key_byte(seed, off + k) for k in range(256))
            cases.append({
                'seed_hex': f'{seed:016x}',
                'offset': off,
                'plain_hex': '',
                'payload': '',
                'keystream_hex': ks.hex(),
            })
    return cases


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('out', nargs='?', default='plan.json')
    ap.add_argument('--seed', help='只生成该种子(16 位 hex)的用例')
    ns = ap.parse_args()
    cases = build_plan(ns.seed)
    with open(ns.out, 'w', encoding='utf-8') as fp:
        json.dump(cases, fp)
    print(f'✅ 对拍计划已生成: {len(cases)} 例 → {ns.out}')
