#!/usr/bin/env python3
"""test_cert_fp.py — extract-cert-fp.py 回归测试(冻结模块护栏)

场景:
  A. 有 v2 Signing Block 的 APK → 指纹 == 构造时写入的证书指纹
  B. 无 Signing Block 的 APK    → exit 1,报"未找到 APK Signing Block"

方法: 用本脚本内置的最小构造器生成带固定证书 DER 的伪造 APK,
期望指纹由同一 DER 经 hashlib 计算得出,不依赖任何外部签名工具。
证书 DER 为硬编码字节(内容仅作哈希输入,无需是可解析的真证书——
extract-cert-fp.py 只对 DER 做整体 SHA-256,不解析证书内部结构)。
"""
import hashlib
import struct
import subprocess
import sys
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "sig-hash" / "extract-cert-fp.py"

# 固定证书 DER(仅作 SHA-256 输入)
CERT_DER = bytes(range(256)) * 2   # 512 字节确定性内容
EXPECTED_FP = hashlib.sha256(CERT_DER).hexdigest()

SIG_BLOCK_MAGIC = b"APK Sig Block 42"
V2_BLOCK_ID = 0x7109871A


def make_v2_block(cert: bytes) -> bytes:
    """构造最小合法 v2 signer 结构(长度前缀 uint32 LE,与 AOSP 规范一致)"""
    def lp(data: bytes) -> bytes:
        return struct.pack("<I", len(data)) + data

    # signed_data = [digests][certificates](自身需要再包一层 lp,extract 按
    # AOSP 规范把 signer 的第一个字段当作 length-prefixed 的 signed_data)
    signed_data = lp(lp(b"\x01\x02")) + lp(lp(cert))
    signatures = lp(lp(b"\x01\x03\x00" + b"\x00" * 40))  # 占位
    public_key = lp(b"\x00" * 64)                        # 占位
    signer = lp(signed_data) + signatures + public_key
    signers = lp(lp(signer))
    pair = struct.pack("<Q", 4 + len(signers)) + struct.pack("<I", V2_BLOCK_ID) + signers
    return pair


def build_apk(path: Path, with_v2: bool):
    """生成最小 zip;with_v2 时在 Central Directory 前插入 Signing Block 并修正 cd_off"""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00fake")
        z.writestr("classes.dex", b"dex\n035\x00")
        z.writestr("lib/arm64-v8a/libnc.so", b"\x7fELF" + b"\x00" * 16)
    raw = bytearray(path.read_bytes())
    if not with_v2:
        path.write_bytes(bytes(raw))
        return
    eocd = raw.rfind(b"PK\x05\x06")
    cd_off = struct.unpack_from("<I", raw, eocd + 16)[0]
    pair = make_v2_block(CERT_DER)
    size_total = len(pair) + 24
    block = struct.pack("<Q", size_total - 8) + pair \
        + struct.pack("<Q", size_total) + SIG_BLOCK_MAGIC
    raw[cd_off:cd_off] = block
    # 插入点在 EOCD 之前,EOCD 整体后移 len(block);cd_off 也要指向新 CD 位置
    struct.pack_into("<I", raw, eocd + 16 + len(block), cd_off + len(block))
    path.write_bytes(bytes(raw))


def run(apk: Path):
    return subprocess.run([sys.executable, str(SCRIPT), str(apk)],
                          capture_output=True, text=True)


def main() -> int:
    tmp = Path("/tmp/cert_fp_test")
    tmp.mkdir(exist_ok=True)
    fails = []

    # 场景 A: v2 签名块存在 → 指纹匹配
    a = tmp / "v2.apk"
    build_apk(a, with_v2=True)
    r = run(a)
    if r.returncode == 0 and r.stdout.strip() == EXPECTED_FP:
        print(f"✅ A: v2 块指纹匹配 {EXPECTED_FP[:16]}…")
    else:
        fails.append(f"A: rc={r.returncode} out={r.stdout.strip()!r} "
                     f"err={r.stderr.strip()!r} 期望={EXPECTED_FP}")

    # 场景 B: 无签名块 → 明确失败
    b = tmp / "nov2.apk"
    build_apk(b, with_v2=False)
    r = run(b)
    if r.returncode != 0 and "Signing Block" in r.stderr:
        print("✅ B: 无签名块正确报错")
    else:
        fails.append(f"B: rc={r.returncode} err={r.stderr.strip()!r}")

    for f in fails:
        print(f"❌ {f}", file=sys.stderr)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
