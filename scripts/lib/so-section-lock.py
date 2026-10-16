#!/usr/bin/env python3
"""so-section-lock.py — 把 so 的代码段加密锁死（构建期"锁箱"）

威胁模型：攻击者拿 libnc.so，用 IDA/Ghidra + LLM 静态分析。
作用：把标记过的代码段用 RC4 加密后写回 so 文件，磁盘上的段是密文。
      运行时由 libnc.so 自己解密（配套运行期"开箱"代码）。
      这不是防住，是推高 AI 静态分析的 token 消耗。

威胁由来（2026-12）：so 原本只有 -fvisibility=hidden/-Oz/strip 这类
编译瘦身，没有任何一层作用在【函数体可读性】上。XopProtector 的
.bitcode 自解密段是业界成熟做法，本脚本是其"锁箱"半边的等价实现。

与 XopProtector 的对应关系（照抄逻辑、改名以清晰）：
  Xop: PROTECTOR_ENCRYPT 宏 → SECTION(".bitcode")        本: __attribute__((section(SECTION_NAME)))
  Xop: packer/SoSectionEncryptor.java (Java + Gradle)    本: 本脚本 (Python，protect.sh 可直接调)
  Xop: packer/KeyLadder.java HKDF 派生                   本: hkdf_labels() 同 label 规则
  Xop: section_decrypt.cpp decrypt_section()             本: 由运行期 C 代码负责（另行抄）

用法：
  so-section-lock.py <输入.so> <输出.so> [--section .ncguard] [--dry-run]

设计约束：
  - size-preserving：加密后段长度不变（ELF 段大小固定，运行期原地解密）
  - 只加密自定义段（默认 .ncguard），不动 .text/.rodata 等标准段
  - 幂等：重复锁同一文件 = 二次加密（会毁数据），故默认拒绝已锁文件，
    用 --force 才强制（仅调试用）
"""
import argparse
import hashlib
import struct
import sys

# ── 常量契约（与运行期 C 代码共享，改这里必须同步改 C 侧）────────────
SECTION_NAME = '.ncguard'           # 加密代码段（Xop 用 .bitcode，改名避开指纹）
SLOT_NAME = '.nckey'                # 密钥槽段（Xop 用 .protwrap）
SLOT_MAGIC = b'NCKEYLOCK' + b'\x00' * 7      # 16 字节，打包器扫这个定位
XOR_KEY = bytes([0x5A, 0xC3, 0x11, 0x9E, 0xF0, 0x37, 0xB2, 0x6D])  # 与 LSGS 同源


class ElfError(Exception):
    pass


# ── ELF 解析（ELF64 小端 + ELF32 小端；arm64-v8a 是 64，armeabi-v7a 是 32）──
# 32 位布局差异：e_shoff 在 0x20、 Elf_Shdr 字段宽度从 8→4 字节
class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b'\x7fELF':
            raise ElfError('not an ELF file')
        if data[5] != 1:
            raise ElfError('only little-endian supported (got EI_DATA=%d)' % data[5])
        self.is64 = (data[4] == 2)
        if data[4] not in (1, 2):
            raise ElfError('unknown EI_CLASS=%d' % data[4])
        self.data = bytearray(data)

        if self.is64:
            (self.e_shoff,) = struct.unpack_from('<Q', self.data, 0x28)
            self.e_shentsize = struct.unpack_from('<H', self.data, 0x3A)[0]
            self.e_shnum = struct.unpack_from('<H', self.data, 0x3C)[0]
            self.e_shstrndx = struct.unpack_from('<H', self.data, 0x3E)[0]
            SH_FMT, SH_SIZE = '<IIQQQQIIQQ', 64
        else:
            (self.e_shoff,) = struct.unpack_from('<I', self.data, 0x20)
            self.e_shentsize = struct.unpack_from('<H', self.data, 0x2E)[0]
            self.e_shnum = struct.unpack_from('<H', self.data, 0x30)[0]
            self.e_shstrndx = struct.unpack_from('<H', self.data, 0x32)[0]
            SH_FMT, SH_SIZE = '<IIIIIIIIII', 40

        if self.e_shoff == 0 or self.e_shnum == 0:
            raise ElfError('ELF has no section header table')
        if self.e_shstrndx >= self.e_shnum:
            raise ElfError('e_shstrndx out of range')
        if self.e_shentsize != SH_SIZE:
            raise ElfError('unexpected e_shentsize=%d (want %d)' % (self.e_shentsize, SH_SIZE))

        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            f = struct.unpack_from(SH_FMT, self.data, off)
            if self.is64:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = f[:6]
            else:
                sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size = f[:6]
            self.sections.append(dict(name_off=sh_name, type=sh_type, flags=sh_flags,
                                      addr=sh_addr, offset=sh_offset, size=sh_size))
        stroff = self.sections[self.e_shstrndx]['offset']
        self._strtab = bytes(self.data[stroff:])
        for s in self.sections:
            end = self._strtab.find(b'\x00', s['name_off'])
            s['name'] = self._strtab[s['name_off']:end].decode('utf-8', 'replace')

    def find(self, name: str):
        for s in self.sections:
            if s['name'] == name:
                return s
        return None

    def require_shf_alloc(self, sec) -> None:
        SHF_ALLOC = 0x2
        if not (sec['flags'] & SHF_ALLOC):
            raise ElfError('section %s is not SHF_ALLOC; runtime cannot map it' % sec['name'])


# ── RC4（与 Xop crypto/rc4.c 同算法；size-preserving 流密码）────────
def rc4(key: bytes, data: bytes) -> bytes:
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


# ── HKDF-SHA256（与 Xop crypto/key_ladder.cpp 同 label 规则）───────
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac_sha256(salt, ikm)
    okm = b''
    t = b''
    counter = 1
    while len(okm) < length:
        t = hmac_sha256(prk, t + info + bytes([counter]))
        okm += t
        counter += 1
    return okm[:length]


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    block = 64
    if len(key) > block:
        key = hashlib.sha256(key).digest()
    key = key + b'\x00' * (block - len(key))
    o = bytes(b ^ 0x5C for b in key)
    i = bytes(b ^ 0x36 for b in key)
    return hashlib.sha256(o + hashlib.sha256(i + msg).digest()).digest()


def derive_app_keys(master: bytes, cert_sha256: bytes, package: str) -> dict:
    """HKDF 派生四把域密钥（label 规则与 Xop 一致，便于日后对拍）。"""
    out = {}
    for label, dom in (('nc-dex-v1', 'dex'), ('nc-insn-v1', 'insn'),
                       ('nc-so-v1', 'so'), ('nc-warm-v1', 'warm')):
        info = (label + package).encode('utf-8')
        out[dom] = hkdf_sha256(master, cert_sha256, info, 16)
    return out


# ── 锁箱主流程 ────────────────────────────────────────────────────
def lock(so_path: str, out_path: str, section: str, cert: bytes,
         package: str, force: bool, dry: bool) -> int:
    with open(so_path, 'rb') as f:
        raw = f.read()
    elf = Elf(raw)

    sec = elf.find(section)
    if sec is None:
        print('❌ 段 %s 不存在。先确认 C 代码用 __attribute__((section("%s"))) 标记了它。'
              % (section, section), file=sys.stderr)
        print('   现有段: %s' % ', '.join(s['name'] for s in elf.sections), file=sys.stderr)
        return 1

    slot = elf.find(SLOT_NAME)
    if slot is None:
        print('❌ 密钥槽段 %s 不存在（Xop 的 .protwrap 等价物）。' % SLOT_NAME, file=sys.stderr)
        return 1

    elf.require_shf_alloc(sec)

    if sec['size'] == 0:
        print('❌ 段 %s 长度为 0，没有代码可锁' % section, file=sys.stderr)
        return 1

    # 幂等保护：已锁文件（slot 含非零 wrapped）默认拒绝，防二次加密毁数据
    existing = bytes(elf.data[slot['offset'] + 16: slot['offset'] + 16 + 16])
    if any(existing):
        if not force:
            print('❌ %s 已被锁（密钥槽非零）。二次锁会毁数据。用 --force 强制执行（仅调试）。'
                  % so_path, file=sys.stderr)
            return 1
        print('⚠️ --force：对已锁文件强制二次加密', file=sys.stderr)

    # 派生 so 域密钥
    keys = derive_app_keys(b'\x11' * 32, cert, package)   # master 由打包侧注入，此处占位
    k_so = keys['so']

    plain = bytes(elf.data[sec['offset']: sec['offset'] + sec['size']])
    cipher = rc4(k_so, plain)

    if dry:
        print('[dry-run] 段 %s: %d 字节 → %d 字节（size-preserving=%s）'
              % (section, len(plain), len(cipher), len(plain) == len(cipher)))
        print('[dry-run] 密钥（hex）: %s' % k_so.hex())
        print('[dry-run] 未写文件')
        return 0

    # 写回密文（原地，长度不变）
    elf.data[sec['offset']: sec['offset'] + sec['size']] = cipher

    # 密钥槽：magic(16) + wrapped(16) = 32 字节，正好填满 .nckey 段（32B）
    # ⚠️ 切片窗口必须与 blob 等长：elf.data[a:b] = blob 若 len(blob) > b-a，
    # Python 会【插入】而非覆盖，把后续字节（段表/相邻段）顶坏。本人踩过。
    wrapped = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(k_so))
    blob = SLOT_MAGIC + wrapped
    assert len(blob) == slot['size'], \
        'blob %d != slot size %d' % (len(blob), slot['size'])
    elf.data[slot['offset']: slot['offset'] + len(blob)] = blob

    with open(out_path, 'wb') as f:
        f.write(bytes(elf.data))

    print('✅ 已锁: %s → %s' % (so_path, out_path))
    print('   段 %s: %d 字节已加密（size-preserving）' % (section, len(plain)))
    print('   密钥槽 %s: %d 字节' % (SLOT_NAME, len(blob)))
    print('   ⚠️ 运行期需配套"开箱"代码解密；没有它，这段代码不可执行')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='把 so 的代码段加密锁死（构建期锁箱）')
    ap.add_argument('input', help='输入 .so')
    ap.add_argument('output', help='输出 .so')
    ap.add_argument('--section', default=SECTION_NAME,
                    help='要锁的段名（默认 %s）' % SECTION_NAME)
    ap.add_argument('--cert-hex', default='',
                    help='证书 SHA-256（hex，32 字节）。留空则用占位（不安全）')
    ap.add_argument('--package', default='', help='包名（HKDF info 的一部分）')
    ap.add_argument('--force', action='store_true', help='允许对已锁文件二次加密（调试用）')
    ap.add_argument('--dry-run', action='store_true', help='只演示不写文件')
    args = ap.parse_args(argv)

    cert = bytes.fromhex(args.cert_hex) if args.cert_hex else b'\x00' * 32
    try:
        return lock(args.input, args.output, args.section, cert,
                    args.package, args.force, args.dry_run)
    except ElfError as e:
        print('❌ ELF 错误: %s' % e, file=sys.stderr)
        return 1
    except OSError as e:
        print('❌ 文件错误: %s' % e, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
