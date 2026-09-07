#!/usr/bin/env python3
"""extract_cert_fp.py — 从 APK 提取 v2/v3 签名证书的 SHA-256 指纹

不依赖 apksigner / keytool / build-tools，纯标准库解析 APK Signing Block：
  EOCD → 定位 Signing Block（magic "APK Sig Block 42"）→ 遍历 ID-value pairs
  → 取 v3 (0xf05368c0) 或 v2 (0x7109871a) 块 → 解析 signer 结构取第一张证书 DER
  → hashlib.sha256(der).hexdigest()

用法: extract_cert_fp.py <apk路径>
成功: stdout 输出 64 位小写十六进制指纹
失败: stderr 报错并 exit 1
"""
import hashlib
import struct
import sys

SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A
V3_BLOCK_ID = 0xF05368C0


def find_eocd(data: bytes) -> int:
    """从尾部 64KB+22 范围内找 EOCD（PK\\x05\\x06），返回其偏移。"""
    search_start = max(0, len(data) - 65557)
    # 从后往前找最后一个 EOCD（comment 里出现伪 EOCD 的概率极低，
    # 且标准做法就是取最后一个）
    pos = len(data) - 22
    while pos >= search_start:
        idx = data.rfind(b"PK\x05\x06", search_start, pos + 4)
        if idx < 0:
            break
        # 校验 comment 长度字段与实际文件尾一致，防误报
        comment_len = struct.unpack_from("<H", data, idx + 20)[0]
        if idx + 22 + comment_len == len(data):
            return idx
        pos = idx - 1
    raise ValueError("未找到 EOCD（不是合法 ZIP/APK 或文件不完整）")


def extract_cert_der(apk_path: str) -> bytes:
    with open(apk_path, "rb") as f:
        data = f.read()

    eocd_off = find_eocd(data)
    cd_off = struct.unpack_from("<I", data, eocd_off + 16)[0]
    if cd_off == 0 or cd_off == 0xFFFFFFFF:
        raise ValueError("ZIP 为空或 zip64（不支持）")
    if cd_off < 32 or cd_off > len(data):
        raise ValueError("central directory 偏移异常")

    # Signing Block 紧邻 central directory。AOSP 规范布局：
    #   [size-payload(8)][ID-value pairs...][size-total(8)][magic(16)]
    # 尾部 size-total 字段（cd_off-24 处）= pairs + 尾部 24 字节的长度，
    # 即整个块 = size-total + 头部 8 字节，块起点 = cd_off - size_total - 8。
    if data[cd_off - 16:cd_off] != SIG_BLOCK_MAGIC:
        raise ValueError("未找到 APK Signing Block（无 v2/v3 签名）")
    size_total = struct.unpack_from("<Q", data, cd_off - 24)[0]
    if size_total + 8 > cd_off:
        raise ValueError("Signing Block 大小异常")
    block_start = cd_off - 8 - size_total
    # 注：AOSP 建议头部 size-payload = size_total - 24，但部分签名工具
    # 两个字段写相同值，故不做强校验，块定位以尾部 size_total 为准。

    # 遍历 ID-value pairs，收集 v2/v3 块（v3 优先，其次 v2，证书内容相同）
    pairs_end = cd_off - 24
    pos = block_start + 8  # 跳过头部 size-payload
    block_value = None
    while pos + 12 <= pairs_end:
        pair_len = struct.unpack_from("<Q", data, pos)[0]  # 长度含 id(4)+value
        block_id = struct.unpack_from("<I", data, pos + 8)[0]
        if pair_len < 4 or pos + 8 + pair_len > pairs_end:
            break
        if block_id in (V2_BLOCK_ID, V3_BLOCK_ID):
            block_value = data[pos + 12: pos + 8 + pair_len]
            if block_id == V3_BLOCK_ID:
                break  # v3 优先
        pos += 8 + pair_len
    if block_value is None:
        raise ValueError("Signing Block 里没有 v2/v3 签名数据")

    # 解析 signer 结构（所有长度均为 uint32 LE 前缀，长度不含前缀自身）：
    #   block_value = [len signers 区][signer...]
    #   signer      = [len][signed_data][signatures][public_key] (v3 还有 [extra])
    #   signed_data = [len digests][digests][len certificates][cert...]
    def read_len_prefixed(buf: bytes, off: int):
        """读取一个 uint32-LE 长度前缀的字段，返回 (内容, 下一偏移)。"""
        if off + 4 > len(buf):
            raise ValueError("signer 结构越界")
        n = struct.unpack_from("<I", buf, off)[0]
        off += 4
        if off + n > len(buf):
            raise ValueError("signer 结构长度异常")
        return buf[off:off + n], off + n

    signers, _ = read_len_prefixed(block_value, 0)
    first_signer, _ = read_len_prefixed(signers, 0)
    signed_data, _ = read_len_prefixed(first_signer, 0)
    _digests, off = read_len_prefixed(signed_data, 0)
    certs, off = read_len_prefixed(signed_data, off)
    first_cert, _ = read_len_prefixed(certs, 0)
    if not first_cert:
        raise ValueError("证书为空")
    return first_cert


def main() -> int:
    if len(sys.argv) != 2:
        print(f"用法: {sys.argv[0]} <apk路径>", file=sys.stderr)
        return 1
    try:
        der = extract_cert_der(sys.argv[1])
    except (OSError, ValueError) as e:
        print(f"❌ 提取证书失败: {e}", file=sys.stderr)
        return 1
    print(hashlib.sha256(der).hexdigest())
    return 0


if __name__ == "__main__":
    sys.exit(main())
