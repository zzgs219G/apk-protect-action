#!/usr/bin/env python3
"""so-section-lock.py — 把 so 的代码段加密锁死（构建期"锁箱"）

威胁模型：攻击者拿 libnc.so，用 IDA/Ghidra + LLM 静态分析。
作用：把标记过的代码段用 RC4 加密后写回 so 文件，磁盘上的段是密文。
      运行时由 libnc.so 自己解密（配套运行期"开箱"代码）。
      这不是防住，是推高 AI 静态分析的 token 消耗。

威胁由来（2026-12）：so 原本只有 -fvisibility=hidden/-Oz/strip 这类
编译瘦身，没有任何一层作用在【函数体可读性】上。XopProtector 的
.bitcode 自解密段是业界成熟做法，本脚本是其"锁箱"半边的等价实现。

2026-12 第二版追加 HMAC 完整性校验（.ncguard 从"改坏"升级为"检测到"）：
  对【密文】算 HMAC-SHA256，密钥用独立的 mac 域（label "nc-so-mac-v1"，
  绝不复用 so 域——复用等于"知道 RC4 密钥就能伪造 MAC"，校验形同虚设）。
  .nckey slot 布局（80 字节，改这里必须同步 C 侧 nc_guard_unlock.c）：
    [0:16]  magic        'NCKEYLOCK' + 7 个 0
    [16:32] wrapped_k_so   k_so ^ XOR_KEY
    [32:48] wrapped_k_mac  k_mac ^ XOR_KEY
    [48:80] expect_mac     HMAC-SHA256(k_mac, 密文)
  前 32 字节布局与旧版完全一致 → 旧 C 侧开箱代码仍能解出 k_so。

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
import math
import struct
import sys

# ── 常量契约（与运行期 C 代码共享，改这里必须同步改 C 侧）────────────
SECTION_NAME = '.ncguard'           # 加密代码段（Xop 用 .bitcode，改名避开指纹）
SLOT_NAME = '.nckey'                # 密钥槽段（Xop 用 .protwrap）
SLOT_MAGIC = b'NCKEYLOCK' + b'\x00' * 7      # 16 字节，打包器扫这个定位
XOR_KEY = bytes([0x7E, 0x31, 0xA5, 0x0D, 0xC8, 0x92, 0x4B, 0xF6])
# ⚠️ 2026-10-18 与 LSGS 彻底分离（原注释写"与 LSGS 同源"，是错的）：
# 同一把 8 字节密钥此前同时护三处 —— .ncguard 的 wrapped_k_so /
# wrapped_k_mac、.ncguard_head 的 wrapped_k_stub、以及 make-sig-log.py 的
# 中文日志 XOR 密文。而 LSGS 侧自己的注释就写着"不抗人工逆向"（它只是
# 打散 strings 扫描的纯 XOR）。共用的后果：破掉最脆的那套，强的一起破。
# 现在 nc_guard 侧用本常量，LSGS 侧保持原值不动，两把钥匙互不相关。

# ── 自解谜二级锁箱（2026-10-18，nc_guard_boot.c）──────────────────
# 把"开锁器本身"也锁进密文段，让静态攻击者不能直接读解锁逻辑。
#   HEAD_NAME    装 unlock 本体的段（ncg_head_unlock 及其私有函数）
#   STUB_SLOT    stub 的密钥槽（.text 里的明文 stub 靠它解出 head）
#   STUB_MAGIC   slot 前 8 字节，stub 判"是否已锁"用
# slot 布局（40 字节，与 nc_guard_boot.c 的 stub 逐字节一致）：
#   [ 0: 8) magic NCSTUBLK
#   [ 8:24) wrapped k_stub = k_stub ^ XOR_KEY
#   [24:28) stub_sh_addr —— .nckey_stub 段自身的链接期虚拟地址
#   [28:32) head_sh_addr —— .ncguard_head 段的链接期虚拟地址
#   [32:36) head_size    —— .ncguard_head 段字节数
#   [36:40) 预留（对齐与将来扩展）
#
# ⚠️ 2026-10-18 不存 entry_delta（入口符号 − 段起始偏移）：那需要从 .symtab
# 读符号地址，而 NDK ndk-build 默认 strip 符号表（CI 39074690534 实测因此
# fail-fast）。也不能靠"让 CI 不 strip"绕过——那会把 frida_port_probe /
# xposed_maps_probe 等探针名暴露进符号表，等于泄露检测意图。
# 改用 section header table：strip 只删 .symtab/.strtab，段表始终完整。
HEAD_NAME = '.ncguard_head'
STUB_SLOT = '.nckey_stub'
STUB_MAGIC = b'NCSTUBLK'


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
    """HKDF 派生五把域密钥（label 规则与 Xop 一致，便于日后对拍）。

    2026-12 追加 mac 域：它只参与"密文段是否被改过"的 HMAC 计算，
    绝不能与 so 域复用同一把钥匙——复用等于把 MAC 降级成"知道 RC4 密钥
    就能伪造"，完整性校验形同虚设。域分隔靠 label 前缀，convention 同 Xop。
    """
    out = {}
    for label, dom in (('nc-dex-v1', 'dex'), ('nc-insn-v1', 'insn'),
                       ('nc-so-v1', 'so'), ('nc-warm-v1', 'warm'),
                       ('nc-so-mac-v1', 'mac')):
        info = (label + package).encode('utf-8')
        out[dom] = hkdf_sha256(master, cert_sha256, info, 16)
    return out


# ── 锁箱主流程 ────────────────────────────────────────────────────
def apk_first_signer_cert_sha256(apk_path: str) -> bytes:
    """从 APK 提取第一签名者证书 DER 的 SHA-256（32 字节）。

    与 C 侧 nc_guard_key.c 的 ncg_apk_first_cert_der() 同规则（照抄 XopProtector
    crypto/apk_sign.cpp）：只读 EOCD + Central Directory + APK Signing Block
    （几十 KB 定点读，不读整个 APK）。v3(0xf05368c0) 优先，回退 v2(0x7109871a)。
    """
    import struct as _s  # noqa: F811  与模块级 struct 同模块，此处为可读性起别名
    with open(apk_path, 'rb') as f:
        f.seek(0, 2)
        fsize = f.tell()
        if fsize < 64:
            raise ElfError('APK 过小: %d' % fsize)
        # 1) EOCD：尾部前 64KB 反向找 PK\x05\x06
        search = max(0, fsize - 65557)
        pos = fsize - 22
        while pos >= search:
            f.seek(pos)
            eocd = f.read(22)
            if eocd[:4] == b'PK\x05\x06':
                break
            pos -= 1
        else:
            raise ElfError('未找到 EOCD')
        cd_off = _s.unpack('<I', eocd[16:20])[0]
        if cd_off < 32 or cd_off >= fsize:
            raise ElfError('CD 偏移非法: %d' % cd_off)
        # 2) Signing Block footer
        f.seek(cd_off - 24)
        footer = f.read(24)
        if len(footer) < 24:
            raise ElfError('footer 读失败')
        # 照抄 XopProtector crypto/apk_sign.cpp:21-22/198：
        #   kMagicLo = 0x20676953204b5041 ("APK Sig ")
        #   kMagicHi = 0x3234206b636f6c42 ("Block 42")
        # ⚠️ 必须校验两个 8 字节——我第一版只查了 "APK Sig Block "（14 字节，
        # 既漏了结尾 "42" 又比切片长），magic 永不匹配 → 真 APK 也提取失败。
        if footer[8:16] != b'APK Sig ' or footer[16:24] != b'Block 42':
            raise ElfError('非 APK Signing Block magic')
        block_size = _s.unpack('<Q', footer[:8])[0]
        if block_size < 24 or block_size + 8 > cd_off:
            raise ElfError('block_size 非法: %d' % block_size)
        # 3) 只读 block 进内存
        total = block_size + 8
        f.seek(cd_off - total)
        blk = f.read(total)
        if _s.unpack('<Q', blk[:8])[0] != block_size:
            raise ElfError('block size 不匹配')
        # 4) 遍历 id-value 对，找 v3/v2
        v3 = v2 = None
        i = 8
        while i + 12 <= len(blk):
            (pl,) = _s.unpack('<Q', blk[i:i + 8])
            i += 8
            if pl < 4 or i + pl > len(blk):
                break
            (bid,) = _s.unpack('<I', blk[i:i + 4])
            val = blk[i + 4:i + pl]
            if bid == 0xf05368c0:
                v3 = val
            elif bid == 0x7109871a:
                v2 = val
            i += pl
    der = _first_cert_der(v3) or _first_cert_der(v2)
    if der is None:
        raise ElfError('v3/v2 中均未找到证书 DER')
    return hashlib.sha256(der).digest()


def manifest_package(apk_path: str) -> str:
    """从 APK 的二进制 AndroidManifest.xml 取 package 属性（stdlib 实现，零依赖）。

    为什么不用 androguard：本脚本是"锁箱"单一职责，为拿一个包名把整个
    dcc 解压链（tools/dcc + sys.path hack）拖进来不划算。
    AXML 规范：XML 头(8) + string pool + element chunk；package 属性挂在
    <manifest> START_ELEMENT 上，值通常是 type=0x03(STRING) 的 pool 索引。
    """
    import struct as _s
    RES_STRING_POOL_TYPE = 0x0001
    RES_XML_START_ELEMENT_TYPE = 0x0102
    import zipfile
    with zipfile.ZipFile(apk_path) as z:
        raw = z.read('AndroidManifest.xml')
    if raw[:2] != b'\x03\x00':
        raise ElfError('非二进制 AXML（magic=%r）' % raw[:4])

    # 1) 收集 chunk
    off = 8
    chunks = {}
    while off + 8 <= len(raw):
        ctype, hsize, csize = _s.unpack_from('<HHI', raw, off)
        if csize < 8 or off + csize > len(raw):
            break
        chunks.setdefault(ctype, []).append((off, csize))
        off += csize
    pools = chunks.get(RES_STRING_POOL_TYPE, [])
    if not pools:
        raise ElfError('AXML 无 string pool')
    poff, psize = pools[0]

    # ResStringPool_header（相对 chunk 开头 poff）：
    #   0:type(2) 2:hsize(2) 4:size(4) 8:stringCount(4) 12:styleCount(4)
    #   16:flags(4) 20:stringsStart(4) 24:stylesStart(4)
    # ⚠️ stringsStart 是【相对 chunk 开头】的偏移，不是绝对地址
    string_count = _s.unpack_from('<I', raw, poff + 8)[0]
    flags = _s.unpack_from('<I', raw, poff + 16)[0]
    strings_start = _s.unpack_from('<I', raw, poff + 20)[0]
    is_utf8 = bool(flags & 0x100)

    pool = []
    sp = poff + strings_start
    for _i in range(string_count):
        if is_utf8:
            slen = raw[sp]; sp += 1
            if slen & 0x80:
                slen = ((slen & 0x7F) << 8) | raw[sp]; sp += 1
            pool.append(raw[sp:sp + slen].decode('utf-8', 'replace'))
            sp += slen + 1
        else:
            slen = raw[sp] | (raw[sp + 1] << 8); sp += 2
            if slen & 0x8000:
                slen = ((slen & 0x7FFF) << 16) | (raw[sp] | (raw[sp + 1] << 8)); sp += 2
            pool.append(raw[sp:sp + slen * 2].decode('utf-16-le', 'replace'))
            sp += slen * 2 + 2

    # 2) 找 <manifest> START_ELEMENT 的 package 属性
    # RES_XML_START_ELEMENT: ns(4) name(4) attrStart(2) attrSize(2)
    #                         attrCount(2) idIdx(2) classIdx(2) styleIdx(2)
    for eoff, _esize in chunks.get(RES_XML_START_ELEMENT_TYPE, []):
        # ResXML_tree_node: header(8) lineNumber(4) comment(4) → 16
        # ResXML_tree_attrExt: ns(4) name(4) attrStart(2) attrSize(2)
        #                       attrCount(2) idIdx(2) classIdx(2) styleIdx(2)
        # ⚠️ name 在 eoff+20（不是 +16——那是 comment 尾部，曾读成 -1 全不匹配）
        name_idx = _s.unpack_from('<i', raw, eoff + 20)[0]
        if not (0 <= name_idx < len(pool)) or pool[name_idx] != 'manifest':
            continue
        attr_start = _s.unpack_from('<H', raw, eoff + 24)[0]
        attr_size = _s.unpack_from('<H', raw, eoff + 26)[0]
        attr_count = _s.unpack_from('<H', raw, eoff + 28)[0]
        for i in range(attr_count):
            # ⚠️ attrStart 相对 attrExt 开头，需先跳过 16 字节 node header
            #    （漏了这 16 字节 → 属性名全错位成 1310740/-1，曾实测）
            ao = eoff + 16 + attr_start + i * attr_size
            aname = _s.unpack_from('<i', raw, ao + 4)[0]
            atype = raw[ao + 15]
            adata = _s.unpack_from('<I', raw, ao + 16)[0]
            if 0 <= aname < len(pool) and pool[aname] == 'package':
                if atype == 0x03 and 0 <= adata < len(pool):
                    return pool[adata]
                return ''
    raise ElfError('未找到 <manifest package=...>')


def _first_cert_der(scheme: bytes):
    """v2/v3 scheme block 里第一个 certificate 的 DER。

    scheme 布局：signer 列表长度(4字节,值=1居多) + [ signedData长度(4) + signedData
    + signedData长度(4,再写一次) + 证书数(4) + 各证书(长度(4)+DER) ]。
    这里从 signedData 尾部反推：signedData 的最后 4 字节是证书数，
    其后紧跟第一张证书的长度 + DER。"""
    if not scheme or len(scheme) < 12:
        return None
    i = 8
    while i + 12 <= len(scheme):
        sl = int.from_bytes(scheme[i:i + 4], 'little')
        i += 4
        if i + sl > len(scheme):
            break
        if sl >= 4:
            certs = int.from_bytes(scheme[i + sl - 4:i + sl], 'little')
            if certs > 0 and i + sl + 4 <= len(scheme):
                cl = int.from_bytes(scheme[i + sl:i + sl + 4], 'little')
                if 0 < cl <= len(scheme) - i - sl - 4:
                    return scheme[i + sl + 4:i + sl + 4 + cl]
        i += sl
    return None


def shannon_entropy(data: bytes) -> float:
    """香农熵（bits/byte）。用于验证"加密真的生效了"。

    RC4 输出是伪随机流，熵必然接近 8.0（实测 .ncguard_head 约 7.4、
    .ncguard 视内容在 7.9 以上）。普通代码段只有 6.6~6.9。
    所以熵掉了只能说明一件事：那一段不是密文，是明文。
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


# 密文段熵的下限。RC4 伪随机流的熵通常在 7.9 以上，普通代码段只有 6.6~6.9，
# 两者之间有明显空隙，7.0 是安全阈值。
#
# ⚠️ 但熵值统计需要足够样本才有效：N 字节的段最多只有 N 种不同取值，
# 熵的理论上限是 min(8, log2(N))。24 字节的上限仅 log2(24)≈4.59 ——
# 2026-10-18 实测踩过：拿 24 字节的 .ncguard 跑安检，熵 4.502 被判失败，
# 但那其实是接近满值的随机数据（假阳性）。
# 因此段长低于 ENTROPY_MIN_BYTES 时直接跳过安检，不做判断。
ENTROPY_MIN = 7.0
ENTROPY_MIN_BYTES = 256


def check_entropy_or_fail(elf: 'Elf', sec_name: str) -> float:
    """校验某段加密后的熵值，异常则抛 ElfError（调用方按 fail-fast 处理）。

    为什么需要这道安检：so 加密是【自动捆绑】的层（用户没有勾选框可取消），
    一旦锁箱静默失效——比如段缺失时返回成功码、或某次改动把明文写回——
    流水线全绿、app 正常，用户完全感知不到。这类"静默失效"比漏洞本身更危险。
    熵值检查把它变成构建期炸响。

    ⚠️ 样本量门槛：N 字节的段最多只有 N 种不同取值，熵的理论上限是
    min(8, log2(N))。段长低于 ENTROPY_MIN_BYTES（256）时统计不具区分度
    （24 字节的上限仅 log2(24)≈4.59，再随机也过不了 7.0），直接跳过。
    """
    sec = elf.find(sec_name)
    if sec is None:
        raise ElfError('熵值安检失败：段 %s 不存在（加密未生效）' % sec_name)
    if sec['size'] < ENTROPY_MIN_BYTES:
        # 段太短，熵值统计不具区分度——跳过而非误判
        return 0.0
    seg = bytes(elf.data[sec['offset']: sec['offset'] + sec['size']])
    ent = shannon_entropy(seg)
    if ent < ENTROPY_MIN:
        raise ElfError(
            '熵值安检失败：段 %s 熵仅 %.3f（下限 %.1f）——'
            '这一段不是密文而是明文，加密未生效。'
            '排查方向：① 锁箱是否真的跑了 ② 段内容是否被后续步骤覆盖回明文'
            % (sec_name, ent, ENTROPY_MIN))
    return ent


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
    # 派生 so 域密钥（2026-12 证书绑定，照抄 XopProtector key ladder）：
    #   k_so = HKDF-SHA256(ikm=master, salt=SHA256(certDER), info="nc-so-v1"+pkg, 16)
    # master 仍由打包侧注入（此处占位；占位值公开无所谓——盐是证书指纹，
    # 换 key 重打包 → cert 变 → k_so 变 → 密文解不开）。
    # ⚠️ C 侧 nc_guard_key.c 的 ncg_derive_k_so() 必须与本函数逐字节同规则，
    #    改一侧必须同步另一侧（本轮已用 3 场景对拍验证 HKDF/HMAC/SHA256）。
    if cert == b'\x00' * 32:
        # cert 全零 = 调用方没传真证书 → 拒绝锁箱。
        # 静默用全零 salt 等于把密钥暴露给"能跑本脚本的人"（仓库是公开的），
        # 那 4012 字节密文秒变明文。fail-fast，逼调用方提供真证书。
        raise ElfError('cert 全零：必须提供 --cert-hex（证书绑定；全零 salt 会使'
                       '密文可被公开脚本解开）')
    keys = derive_app_keys(b'\x11' * 32, cert, package or '')
    k_so = keys['so']
    k_mac = keys['mac']          # 2026-12 完整性校验专用，与 so 域硬分隔

    plain = bytes(elf.data[sec['offset']: sec['offset'] + sec['size']])
    cipher = rc4(k_so, plain)

    # 期望 MAC 对【密文】算，不对明文算：密文在解密前就可读，于是可以
    # "先验后解" —— 一旦被改过，根本不会把明文装进 .ncguard（fail-closed）。
    # 若对明文算，就必须先解密再验，篡改的明文已经落盘生效，晚一步。
    # 另一个理由是 RC4 是流密码：改密文 1 位恰好只翻明文 1 位，未必崩溃，
    # 攻击者可以"改一位→跑→看行为"做廉价 oracle；MAC 让这种试探第一次就暴露。
    expect_mac = hmac_sha256(k_mac, cipher)

    if dry:
        print('[dry-run] 段 %s: %d 字节 → %d 字节（size-preserving=%s）'
              % (section, len(plain), len(cipher), len(plain) == len(cipher)))
        print('[dry-run] 密钥（hex）: %s' % k_so.hex())
        print('[dry-run] mac 域（hex）: %s' % k_mac.hex())
        print('[dry-run] 期望 MAC（hex，对密文算）: %s' % expect_mac.hex())
        print('[dry-run] 未写文件')
        return 0

    # 写回密文（原地，长度不变）
    elf.data[sec['offset']: sec['offset'] + sec['size']] = cipher

    # 密钥槽：magic(16) + wrapped_k_so(16) + wrapped_k_mac(16) + expect_mac(32)
    #          = 80 字节，.nckey 段必须同步扩到 80（否则 assert 炸）
    # ⚠️ 切片窗口必须与 blob 等长：elf.data[a:b] = blob 若 len(blob) > b-a，
    # Python 会【插入】而非覆盖，把后续字节（段表/相邻段）顶坏。本人踩过。
    # 布局保持 magic+wrapped_k_so 在前 32 字节【不变】——2026-12 之前的 C 侧
    # ncg_recover_key() 正是从 offset 16 读 k_so 的，向前兼容。
    wrapped = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(k_so))
    wrapped_mac = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(k_mac))
    blob = SLOT_MAGIC + wrapped + wrapped_mac + expect_mac
    assert len(blob) == 80, 'blob %d != 80' % len(blob)
    assert len(blob) == slot['size'], \
        'blob %d != slot size %d（.nckey 段需扩到 80；改了一侧必须同步另一侧）' \
        % (len(blob), slot['size'])
    elf.data[slot['offset']: slot['offset'] + len(blob)] = blob

    # 熵值安检（2026-10-18）：必须在【写盘之前】。
    # 若放到写盘之后，fail-fast 时坏包已经落盘，protect.sh 虽然 exit 1 但
    # 文件已在——而它会被后续步骤当成有效产物。所以先验后写。
    if not dry:
        ent = check_entropy_or_fail(elf, section)
        if ent > 0:
            print('   熵值安检: %.3f（下限 %.1f）✅' % (ent, ENTROPY_MIN))
        else:
            _sec = elf.find(section)
            print('   熵值安检: 段仅 %d 字节（< %d），样本不足跳过'
                  % (_sec['size'] if _sec else 0, ENTROPY_MIN_BYTES))

    with open(out_path, 'wb') as f:
        f.write(bytes(elf.data))

    print('✅ 已锁: %s → %s' % (so_path, out_path))
    print('   段 %s: %d 字节已加密（size-preserving）' % (section, len(plain)))
    print('   密钥槽 %s: %d 字节' % (SLOT_NAME, len(blob)))
    print('   ⚠️ 运行期需配套"开箱"代码解密；没有它，这段代码不可执行')
    return 0


# ── 二级锁箱：把 unlock 本体也锁进密文（自解谜）───────────────────
def lock_head(so_path: str, out_path: str, force: bool = False) -> int:
    """锁 .ncguard_head 段，并给明文 stub 写它的密钥槽。

    这是"把开锁器锁进它开的那只箱子"的构建期半边：
      .ncguard_head（unlock 本体）← 用 k_stub 锁
      .nckey_stub（stub 的槽）    ← 写 magic + wrapped_k_stub + stub/head 段
                                     链接期地址 + head_size，让明文 stub 能解它

    k_stub 与 k_so 必须是两把钥匙：stub 只负责解 head，head 才负责解
    业务段。复用一把 = 解开 head 就等于拿到业务段的钥匙，分级失去意义。

    段地址取自 section header table（strip 只删 .symtab/.strtab，段表始终
    完整）。明文 stub 靠 `&ncg_stub_slot(PC 相对) - stub_sh_addr` 算出镜像
    基址，再加 head_sh_addr 定位 head 段 —— 全程不读盘、不碰符号表。
    """
    with open(so_path, 'rb') as f:
        raw = f.read()
    elf = Elf(raw)

    head = elf.find(HEAD_NAME)
    if head is None:
        # ⚠️ 2026-10-18 从 return 0 改为 return 1（fail-fast）。
        # 此前这里"跳过二级锁箱"并返回 0（exit code 0 = 成功），而
        # protect.sh 的判据是 exit != 0 才失败 → 段缺失时静默放行：
        # unlock 本体保持明文、自解谜没发生，但流水线显示成功。
        # 这正是"以为防了其实没防"的静默降级，最该避免。
        #
        # 为什么可以安全地 fail-fast：走到这里说明 protect.sh 已经进了
        # `if [[ -d "$WORK/project/libs" ]]` 分支，即本就要编译 libnc.so；
        # 而只要编译了，nc_guard_boot.c 就在工程里、.ncguard_head 段就该在。
        # 段不在 = 拷贝漏了 / boot.c 没编入 / 段被 gc-sections 回收，
        # 三种都是真实配置错误，没有一种应该放行。
        # （纯 dex 组合如只勾 stringenc 时根本不调 lock_head，不受影响。）
        print('❌ 段 %s 不存在 —— 二级锁箱无法进行。'
              % HEAD_NAME, file=sys.stderr)
        print('   排查方向：① nc_guard_boot.c 是否拷进 NDK 工程'
              '（protect.sh 的拷贝清单）② 段是否被 --gc-sections 回收'
              '（检查 ncg_key_slot/ncg_stub_slot 的 retain）'
              '③ nc_guard_key.h 是否一并拷入', file=sys.stderr)
        return 1

    slot = elf.find(STUB_SLOT)
    if slot is None:
        print('❌ 密钥槽段 %s 不存在（nc_guard_boot.c 的 ncg_stub_slot 未编入）'
              % STUB_SLOT, file=sys.stderr)
        return 1

    if head['size'] == 0:
        print('❌ 段 %s 长度为 0，没有 unlock 本体可锁' % HEAD_NAME, file=sys.stderr)
        return 1

    # 幂等：已锁（slot magic 在）默认拒绝，防二次加密毁数据
    existing = bytes(elf.data[slot['offset']: slot['offset'] + 8])
    if existing == STUB_MAGIC and not force:
        print('❌ %s 已被锁（stub 槽 magic 已写）。二次锁会毁数据。'
              % so_path, file=sys.stderr)
        return 1

    # ⚠️ 2026-10-18 不再从 .symtab 读入口符号 —— NDK ndk-build 默认 strip
    # 符号表，CI 39074690534 实测因此 fail-fast（"符号 ncg_head_unlock 不在
    # .symtab"）。也不能靠"让 CI 不 strip"绕过：那会把 frida_port_probe /
    # xposed_maps_probe 等探针名暴露进符号表，等于泄露检测意图。
    # 改用【section header table】——strip 只删 .symtab/.strtab，段表始终完整。
    # stub 侧靠 slot 里的 stub_sh_addr + 自身 PC 相对地址算出镜像基址，
    # 再加 head_sh_addr 定位 head 段，全程不碰符号表。

    # k_stub：与 k_so 独立的第二把钥匙（hardcode 的理由同 master ——
    # 真正的盐是证书指纹，占位值公开不影响"换 key 重打包即失效"）
    k_stub = bytes([0x3B, 0x7C, 0x19, 0x5E, 0xA2, 0xDF, 0x48, 0x31,
                    0x6C, 0x85, 0xEA, 0x27, 0x54, 0x9B, 0x0F, 0xD6])
    # k_mac_head：第三把钥匙，只用于 head 段的完整性校验（P0-b）。
    # 与 k_stub / k_so 都必须不同——复用任何一把都意味着"解开 head 就等于
    # 拿到业务段的钥匙"或"知道解密钥匙即可伪造 MAC"，分级失去意义。
    k_mac_head = bytes([0x91, 0x4A, 0xD2, 0x08, 0x7B, 0xE3, 0x5F, 0xC6,
                        0x2D, 0xB8, 0x64, 0x17, 0xAF, 0x39, 0x8E, 0x51])

    plain = bytes(elf.data[head['offset']: head['offset'] + head['size']])
    # ⚠️ 必须是【简单循环 XOR】，不能用 rc4()！
    # 2026-10-18 实测踩过：这里抄了 rc4()，而 stub 侧是
    #   `for(i<head_size) start[i] ^= k[i & 15];`
    # 两边算法不同 → 解出来是乱 C → dlopen 即 SIGILL（exit 132）。
    # 刻意不用 RC4 的理由：明文 stub 里不能出现 256 字节 S 盒初始化循环
    # —— 那本身就是"这是 RC4"的活招牌，且会显著撑大 stub。简单 XOR 的
    # 代价由 HMAC 兜底（head 段的 MAC 见下方 P0-b，2026-10-18 补上）。
    cipher = bytes(b ^ k_stub[i % len(k_stub)] for i, b in enumerate(plain))

    elf.data[head['offset']: head['offset'] + head['size']] = cipher

    # P0-b：对【密文】算 HMAC-SHA256(k_mac_head, head 密文)。
    # 与 .ncguard 的 expect_mac 完全同构——解密前就能验，验不过就不装明文。
    # 在此之前 head 段只有 XOR，攻击者可改 head 密文中对应"unlock 本体的
    # MAC 校验函数"那几位，把 .ncguard 的 HMAC 保护改成恒真从而绕过。
    expect_mac_head = hmac_sha256(k_mac_head, cipher)

    # stub 槽（88 字节，P0-b 起）：magic(8) + wrapped_k_stub(16)
    #   + stub_sh_addr(4) + head_sh_addr(4) + head_size(4) + reserved(4)
    #   + wrapped_k_mac_head(16) + expect_mac_head(32)
    # ⚠️ 全程用 section header table 的 sh_addr/size，不碰 .symtab（见上方注释）
    import struct as _s
    wrapped = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(k_stub))
    wrapped_mac = bytes(b ^ XOR_KEY[i % len(XOR_KEY)]
                        for i, b in enumerate(k_mac_head))
    blob = (STUB_MAGIC + wrapped
            + _s.pack('<I', slot['addr'])
            + _s.pack('<I', head['addr'])
            + _s.pack('<I', head['size'])
            + _s.pack('<I', 0)
            + wrapped_mac
            + expect_mac_head)
    assert len(blob) == 88, 'stub blob %d != 88' % len(blob)
    assert len(blob) == slot['size'], \
        'blob %d != slot size %d（.nckey_stub 段需扩到 88 字节；' \
        '改 nc_guard_boot.c 的 NCG_STUB_SIZE 必须同步这里）' \
        % (len(blob), slot['size'])
    elf.data[slot['offset']: slot['offset'] + len(blob)] = blob

    # 熵值安检（2026-10-18）：必须在【写盘之前】，理由同 lock()——
    # fail-fast 时坏包不能已经落盘，否则会被后续步骤当成有效产物。
    # head 段通常 1-2KB（CI 实测 arm64 1588B / v7a 1112B），RC4 输出熵在
    # 7.4 左右，远高于普通代码段的 6.6~6.9。低于 256 字节时自动跳过
    # （采样不足，见 check_entropy_or_fail 的说明）。
    ent = check_entropy_or_fail(elf, HEAD_NAME)
    print('   熵值安检: %.3f（下限 %.1f）✅' % (ent, ENTROPY_MIN))

    with open(out_path, 'wb') as f:
        f.write(bytes(elf.data))

    print('✅ 二级锁箱: %s → %s' % (so_path, out_path))
    print('   段 %s: %d 字节已加密（unlock 本体）' % (HEAD_NAME, head['size']))
    print('   密钥槽 %s: %d 字节（magic + wrapped_k_stub + stub/head addr + size）'
          % (STUB_SLOT, len(blob)))
    print('   段地址: stub=0x%x head=0x%x size=0x%x（取自 section header table）'
          % (slot['addr'], head['addr'], head['size']))
    print('   ⚠️ 静态视角：unlock 本体已不可读，只剩明文 stub')
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description='把 so 的代码段加密锁死（构建期锁箱）')
    ap.add_argument('input', help='输入 .so')
    ap.add_argument('output', help='输出 .so')
    ap.add_argument('--section', default=SECTION_NAME,
                    help='要锁的段名（默认 %s）' % SECTION_NAME)
    ap.add_argument('--cert-hex', default='',
                    help='证书 SHA-256（hex，32 字节）。与 --from-apk 二选一')
    ap.add_argument('--from-apk', default='',
                    help='从 APK 自动提取第一签名者证书 SHA-256（与 --cert-hex 等价，'
                         '但免去手工提证书；v3 优先回退 v2）')
    ap.add_argument('--cert-only', action='store_true',
                    help='只打印 APK 证书 SHA-256 后退出（供流水线校验/搬运）')
    ap.add_argument('--package', default='', help='包名（HKDF info 的一部分）')
    ap.add_argument('--force', action='store_true', help='允许对已锁文件二次加密（调试用）')
    ap.add_argument('--dry-run', action='store_true', help='只演示不写文件')
    ap.add_argument('--lock-head', action='store_true',
                    help='二级锁箱：把 unlock 本体也锁进 %s（自解谜，需先跑过一级锁箱）'
                         % HEAD_NAME)
    args = ap.parse_args(argv)

    # 证书与包名来源：
    #   --from-apk  自动提 cert（定点读 Signing Block）+ package（AXML 解析）
    #   --cert-hex  手工给 cert；package 仍可缺省（HKDF info 只有 label 前缀，
    #               换 key 重打包依然解不开——cert 才是关键 salt）
    #   都无 → cert 全零 → lock() fail-fast（全零 salt = 公开脚本可解，等于没锁）
    package = args.package
    if args.from_apk:
        cert = apk_first_signer_cert_sha256(args.from_apk)
        if args.cert_only:
            print(cert.hex())
            return 0
        if not package:
            # 自动补包名（原来指望 apktool.yml 的 package 字段——那字段不存在，
            # 2026-10-17 CI 因此 fail-fast；改为从 AXML 直接解析）
            package = manifest_package(args.from_apk)
    elif args.cert_hex:
        cert = bytes.fromhex(args.cert_hex)
    else:
        cert = b'\x00' * 32

    try:
        if args.lock_head:
            return lock_head(args.input, args.output, args.force)
        return lock(args.input, args.output, args.section, cert,
                    package, args.force, args.dry_run)
    except ElfError as e:
        print('❌ ELF 错误: %s' % e, file=sys.stderr)
        return 1
    except OSError as e:
        print('❌ 文件错误: %s' % e, file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
