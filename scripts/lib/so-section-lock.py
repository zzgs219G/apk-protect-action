#!/usr/bin/env python3
"""so-section-lock.py — 把 so 的代码段加密锁死（构建期"锁箱"）

威胁模型：攻击者拿 libnc.so，用 IDA/Ghidra + LLM 静态分析。
作用：把标记过的代码段用 RC4 加密后写回 so 文件，磁盘上的段是密文。
      运行时由 libnc.so 自己解密（配套运行期"开箱"代码）。
      这不是防住，是推高 AI 静态分析的 token 消耗。

威胁由来（2026-12）：so 原本只有 -fvisibility=hidden/-Oz/strip 这类
编译瘦身，没有任何一层作用在【函数体可读性】上。XopProtector 的
.bitcode 自解密段是业界成熟做法，本脚本是其"锁箱"半边的等价实现。

2026-12 第二版追加 HMAC 完整性校验（加密段从"改坏"升级为"检测到"）：
  对【密文】算 HMAC-SHA256，密钥用独立的 mac 域（label "nc-so-mac-v1"，
  绝不复用 so 域——复用等于"知道 RC4 密钥就能伪造 MAC"，校验形同虚设）。

  ⚠️⚠️ 2026-10-20：本文件此前通篇使用 2026-10-19 改名前的旧段名
  （.ncguard / .ncguard_ro / .ncguard_head / .ncguard_head_ro /
   .nckey / .nckey_stub），与实际操作的常量（SECTION_NAME / SLOT_NAME /
  HEAD_NAME / HEAD_RO_NAME / STUB_SLOT）名实不符 —— 读者按注释里的旧名
  去搜代码会搜不到。现已全部改为现行名。

  段名对照表（旧名 → 现行名，改段名前先查此表）：
    .ncguard          → .ncx     加密代码段（AXR）
    .ncguard_ro       → .ncxr    加密常量表（AWR）
    .ncguard_head     → .ncxh    unlock 本体（二级锁箱对象）
    .ncguard_head_ro  → .ncxhr   master 数据段（32B）
    .nckey            → .nck     一级密钥槽
    .nckey_stub       → .ncks    二级 stub 密钥槽

  ⚠️ scripts/sigcheck/archive/nc_guard_unlock.c 是历史存档（2026-10-20
  已移出 src/），【刻意保留旧名】—— 读到 .ncguard 说明那是旧版实现，
  不要照着改。它不参与任何构建。

  .nck slot 布局（96 字节，2026-10-19 P1-a 起；原 80 字节版见历史记录）：
    [0:16]  magic        seed + 8 个 0（seed 见 SLOT_MAGIC_SEED）
    [16:32] decoy        诱饵（P1-a 起非真密钥，真 k_so 由运行期证书派生）
    [32:48] decoy_mac    诱饵（同上）
    [48:80] expect_mac    HMAC-SHA256(k_mac, 密文)
    [80:88] pkg_sha8      SHA256(包名) 前 8 字节
    [88:96] reserved
  两侧契约：本文件 blob 组装 + assert len(blob)==96，C 侧 nc_guard_probe.c
  的 ncg_key_slot[96] 与 nc_guard_boot.c 的 NCG_SLOT_SIZE / NCG_OFF_*。

与 XopProtector 的对应关系（照抄逻辑、改名以清晰）：
  Xop: PROTECTOR_ENCRYPT 宏 → SECTION(".bitcode")        本: __attribute__((section(SECTION_NAME)))
  Xop: packer/SoSectionEncryptor.java (Java + Gradle)    本: 本脚本 (Python，protect.sh 可直接调)
  Xop: packer/KeyLadder.java HKDF 派生                   本: hkdf_labels() 同 label 规则
  Xop: section_decrypt.cpp decrypt_section()             本: 由运行期 C 代码负责（另行抄）

用法：
  so-section-lock.py <输入.so> <输出.so> [--section .ncx] [--dry-run]

设计约束：
  - size-preserving：加密后段长度不变（ELF 段大小固定，运行期原地解密）
  - 只加密自定义段（默认 .ncx），不动 .text/.rodata 等标准段
  - 幂等：重复锁同一文件 = 二次加密（会毁数据），故默认拒绝已锁文件，
    用 --force 才强制（仅调试用）
"""
import argparse
import hashlib
import math
import os
import re
import struct
import sys
import zlib


# ── 从 nc_guard_layout.h 抽取契约常量（2026-10-20）──────────────────
# 为什么让 Python 从 C 头文件抽，而不是反过来（C 从 Python 抽）：
#   · C 头文件是编译期强制生效的（_Static_assert 已在里头把关偏移重叠），
#     让 Python 当消费者，它不可能漂移；
#   · 反过来 Python 要写一个 C 头解析器，那本身就是新的 bug 源。
#
# 失败即抛错，绝不静默兜底："以为同步了其实没同步"比编译失败危险得多。
def _load_layout_contract():
    """从 nc_guard_layout.h 抽取段名/尺寸/偏移/种子，返回 dict。

    头文件定位：本脚本在 scripts/lib/，头文件在 scripts/sigcheck/src/。
    找不到头文件 → 抛 FileNotFoundError（调用方应视为构建配置错误）。
    """
    here = os.path.dirname(os.path.abspath(__file__))
    for cand in (os.path.join(here, '..', 'sigcheck', 'src', 'nc_guard_layout.h'),
                 os.path.join(here, 'nc_guard_layout.h')):
        cand = os.path.normpath(cand)
        if os.path.isfile(cand):
            path = cand
            break
    else:
        raise FileNotFoundError(
            '找不到 nc_guard_layout.h（契约真相源）。'
            '它应在 scripts/sigcheck/src/ 下；缺失意味着锁箱契约无从对拍，'
            '拒绝继续——否则会用过期常量锁出一个运行期 SIGILL 的包。')

    with open(path, encoding='utf-8') as f:
        text = f.read()

    out = {}
    # ① 段名：#define NC_SEC_XXX  ".yyy"
    for m in re.finditer(r'#define\s+(NC_SEC_[A-Z_]+)\s+"([^"]+)"', text):
        out[m.group(1)] = m.group(2)
    # ② 尺寸/偏移：#define NC_XXX_YYY  104
    for m in re.finditer(r'#define\s+(NC_(?:SLOT|STUB|OFF)_[A-Z0-9_]+)\s+(\d+)', text):
        out[m.group(1)] = int(m.group(2))
    # ③ magic 种子初始化列表：#define NC_SEED_XXX_INIT { 0x.., ... }
    # ⚠️ 必须支持【续行】形态（`#define X \` + 换行 + `{ ... }`）——
    #    layout.h 为可读性把初始化列表放在下一行，\s* 匹配不到换行。
    #    2026-10-20 实测踩过：漏掉续行支持 → 两个 seed 抽不到 →
    #    "缺少必需常量" 直接构建失败。
    for m in re.finditer(
            r'#define\s+(NC_SEED_[A-Z_]+_INIT)\s*\\?\s*\{([^}]*)\}', text):
        vals = [int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]+)', m.group(2))]
        out[m.group(1)] = bytes(vals)

    required = ['NC_SEC_CODE', 'NC_SEC_CONST', 'NC_SEC_HEAD', 'NC_SEC_HEADRO',
                'NC_SEC_SLOT', 'NC_SEC_STUBSLOT',
                'NC_SLOT_SIZE', 'NC_STUB_SIZE',
                'NC_SEED_SLOT_INIT', 'NC_SEED_STUB_INIT']
    missing = [k for k in required if k not in out]
    if missing:
        raise ValueError(
            'nc_guard_layout.h 缺少必需常量: %s —— 头文件被改坏了？' % ', '.join(missing))
    return out


_LAYOUT = _load_layout_contract()

# ── 常量契约（与运行期 C 代码共享，改这里必须同步改 C 侧）────────────
# ⚠️⚠️ 2026-10-20 起，本区常量不再手写，而是从 nc_guard_layout.h 抽取。
#   那是契约的【唯一真相源】。此前这些值在 C 侧与 Python 侧各写一份，
#   改一处漏一处的症状是运行期 SIGILL（不是编译错误），极难定位；
#   仓库历史报错三/九/十一/十二全是同类根因。
#   抽取失败（头文件缺失/正则不匹配）直接抛错，绝不静默用旧值兜底 ——
#   "以为同步了其实没同步"比编译失败危险得多。
#
# 抽取规则：只认 `#define NAME value` 形态，值必须是 8/16 位十六进制串
# （段名是带引号的字符串，另行处理）。见 _load_layout_contract()。

SECTION_NAME = _LAYOUT['NC_SEC_CODE']   # 加密代码段（Xop 用 .bitcode，改名避开指纹）
SLOT_NAME = _LAYOUT['NC_SEC_SLOT']      # 密钥槽段（Xop 用 .protwrap）
# ⚠️ 2026-10-19：magic 不再以明文字面量落进 .nck/.ncks。
# 原实现直接写 b'NCKEYLOCK' / b'NCSTUBLK'，攻击者 `strings -n 6` 就能扫出
# 两条明确路标（实测旧产物可见 3 条）。现在改成 seed ^ XOR_KEY 的形式，
# 二进制里不再有该字面量；运行期 C 侧由 ncg_magic_ok() 用同样的
# seed ^ 碎片密钥 生成后比对，语义（匹配=已锁，不匹配=未锁放行）不变。
# 改这四个常量必须同步 nc_guard_boot.c 的 NCG_MAGIC_SEED_SLOT/STUB。
SLOT_MAGIC_SEED = _LAYOUT['NC_SEED_SLOT_INIT']   # ← 来自 nc_guard_layout.h
STUB_MAGIC_SEED = _LAYOUT['NC_SEED_STUB_INIT']   # ← 来自 nc_guard_layout.h
XOR_KEY = bytes([0x7E, 0x31, 0xA5, 0x0D, 0xC8, 0x92, 0x4B, 0xF6])
# 注意：'NCKEYLOCK' 是 9 字节，seed 只覆盖前 8 字节（第 9 字节 'K' 由
# 运行期 C 侧的 8 字节比较不涉及——C 侧比的是前 8 字节 'NCKEYLOC'）。
assert bytes(a ^ b for a, b in zip(SLOT_MAGIC_SEED, XOR_KEY)) == b'NCKEYLOC'
assert bytes(a ^ b for a, b in zip(STUB_MAGIC_SEED, XOR_KEY)) == b'NCSTUBLK'
# ⚠️ 落盘的是【seed 本身】，不是 seed^key。这是本机制的关键：
#   - 落盘 seed（看起来是随机字节）→ strings 搜不到任何路标
#   - 运行期 C 侧算 seed ^ 碎片密钥 = "NCKEYLOC" 再与... 不需要再比了：
#     C 侧直接把落盘的 8 字节当作 seed，与自己算出的期望值比对即可。
#   语义："slot 前 8 字节 == SLOT_MAGIC_SEED" ⇒ 已锁。
# 旧的 SLOT_MAGIC/SLOT_MAGIC_SEED 双轨容易搞混，这里只保留 seed 一个真相源。
SLOT_MAGIC = SLOT_MAGIC_SEED + b'\x00' * 8   # 16 字节，后 8 保留
# ⚠️ 2026-10-18 与 LSGS 彻底分离（原注释写"与 LSGS 同源"，是错的）：
# 同一把 8 字节密钥此前同时护三处 —— .ncx 的 wrapped_k_so /
# wrapped_k_mac、.ncxh 的 wrapped_k_stub、以及 make-sig-log.py 的
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
#   [24:28) stub_sh_addr —— .ncks 段自身的链接期虚拟地址
#   [28:32) head_sh_addr —— .ncxh 段的链接期虚拟地址
#   [32:36) head_size    —— .ncxh 段字节数
#   [36:40) 预留（对齐与将来扩展）
#
# ⚠️ 2026-10-18 不存 entry_delta（入口符号 − 段起始偏移）：那需要从 .symtab
# 读符号地址，而 NDK ndk-build 默认 strip 符号表（CI 39074690534 实测因此
# fail-fast）。也不能靠"让 CI 不 strip"绕过——那会把 frida_port_probe /
# xposed_maps_probe 等探针名暴露进符号表，等于泄露检测意图。
# 改用 section header table：strip 只删 .symtab/.strtab，段表始终完整。
HEAD_NAME = _LAYOUT['NC_SEC_HEAD']      # 装 unlock 本体的段
HEAD_RO_NAME = _LAYOUT['NC_SEC_HEADRO']  # 存 master（2026-10-19 随机化）
STUB_SLOT = _LAYOUT['NC_SEC_STUBSLOT']  # stub 的密钥槽
STUB_MAGIC = STUB_MAGIC_SEED


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
    """v2/v3 scheme 块里第一个 signer 的第一张证书 DER。

    ⚠️ 2026-10-19 重写。旧实现（"从 signedData 尾部反推证书数"）是错的：
    APK Sig Scheme v2/v3 的 certificates 段是【长度前缀序列】，没有"证书数"。
    旧代码在真 APK 上碰巧从一个错误偏移取到 294 字节、头 `30820122` 的块并
    当作证书返回——那是 **public key**，不是证书。真证书是 712 字节、头
    `308202c4`。后果：k_so 实际绑定的是"公钥"而非"证书"，换了签名密钥但
    证书链相同时绑定形同未变。

    规范布局（source.android.com/docs/security/features/apksigning/v2）：
      signers     = signers_len(4) + [signer_len(4) + signer]...
      signer      = signed_data_len(4) + signed_data
                    + signatures_len(4) + signatures
                    + public_key_len(4) + public_key
      signed_data = digests_len(4) + digests
                    + certificates_len(4) + [cert_len(4) + cert_der]...
                    + additional_attrs_len(4) + ...
    """
    if not scheme or len(scheme) < 12:
        return None

    def _from_signer(signer, n):
        if n < 12:
            return None
        sd_len = int.from_bytes(signer[0:4], 'little')
        if sd_len < 8 or sd_len + 4 > n:
            return None
        sd = signer[4:4 + sd_len]
        q = 0
        dg = int.from_bytes(sd[q:q + 4], 'little')  # digests_len
        if dg < 4 or dg + 8 > sd_len:
            return None
        q += 4 + dg
        certs_len = int.from_bytes(sd[q:q + 4], 'little')
        q += 4
        if certs_len < 4 or q + certs_len > sd_len:
            return None
        cl = int.from_bytes(sd[q:q + 4], 'little')
        q += 4
        if cl == 0 or cl > certs_len - 4 or q + cl > sd_len:
            return None
        return sd[q:q + cl]

    # 规范路径：跳 signers_len，再跳 signer_len
    off = 4
    if off + 4 <= len(scheme):
        sl = int.from_bytes(scheme[off:off + 4], 'little')
        if sl >= 12 and off + 4 + sl <= len(scheme):
            r = _from_signer(scheme[off + 4:off + 4 + sl], sl)
            if r:
                return r
    # 回退路径：signers_len 被写成"个数"（=1）
    cnt = int.from_bytes(scheme[0:4], 'little')
    if 1 <= cnt <= 8 and off + 4 <= len(scheme):
        sl = int.from_bytes(scheme[off:off + 4], 'little')
        if sl >= 12 and off + 4 + sl <= len(scheme):
            return _from_signer(scheme[off + 4:off + 4 + sl], sl)
    return None


def shannon_entropy(data: bytes) -> float:
    """香农熵（bits/byte）。用于验证"加密真的生效了"。

    RC4 输出是伪随机流，熵必然接近 8.0（实测 .ncxh 约 7.4、
    .ncx 视内容在 7.9 以上）。普通代码段只有 6.6~6.9。
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
# 2026-10-18 实测踩过：拿 24 字节的 .ncx 跑安检，熵 4.502 被判失败，
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
    """锁一个或多个段。

    section 支持逗号分隔的多段名（2026-10-19 新增），例如
    ".ncx,.ncxr"。多段共用同一把 k_so、同一个 MAC ——这是刻意的：
    它们逻辑上是同一份受保护资产（代码 + 它要用的常量表），拆成两把钥匙
    只会让运行期需要多解一次、多存一份 key，收益为零。
    为什么必须分两个 ELF 段：clang 不允许 const 数据进 AXR 段
    （'causes a section type conflict'），所以表只能另开一个 AWR 段。
    """
    with open(so_path, 'rb') as f:
        raw = f.read()
    elf = Elf(raw)

    sec_names = [s.strip() for s in section.split(',') if s.strip()]
    if not sec_names:
        print('❌ --section 为空', file=sys.stderr)
        return 1
    sec = elf.find(sec_names[0])
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
    # ── master 随机化（2026-10-19）────────────────────────────────
    # 修实测报告静态 P1-1：master 原是全 0x11 占位符躺在 .rodata，
    # `od` 一条命令读出 → 配合 APK 证书离线算 k_so → 8 分钟解开 .ncx。
    #
    # 这里生成随机 master，并用它派生 k_so / k_mac。
    # master 本身【以明文写进 .ncxhr 段】——注意：这一步写的是
    # 明文，真正的保护来自随后的 --lock-head（用 k_stub 把它 XOR 成密文）。
    # 所以必须严格按「先一级锁箱、再二级锁箱」的顺序跑，中间产物不含明文
    # master 的窗口仅存在于构建机临时目录里。
    head_ro = elf.find(HEAD_RO_NAME)
    if head_ro is None:
        raise ElfError('段 %s 不存在 —— master 无处存放（nc_guard_boot.c 的 '
                       'ncg_master 需标段，且编译时要有 NC_GUARD_SECTIONED）'
                       % HEAD_RO_NAME)
    if head_ro['size'] < 32:
        raise ElfError('%s 仅 %d 字节，容不下 32 字节 master'
                       % (HEAD_RO_NAME, head_ro['size']))
    master = os.urandom(32)
    assert any(master), 'master 不能全零（全零会被运行期判为"未锁"）'
    elf.data[head_ro['offset']: head_ro['offset'] + 32] = master
    print('   master: 32 字节随机生成（将随二级锁箱藏入 %s）' % HEAD_RO_NAME)

    keys = derive_app_keys(master, cert, package or '')
    k_so = keys['so']
    k_mac = keys['mac']          # 2026-12 完整性校验专用，与 so 域硬分隔

    # ── 多段加密（2026-10-19：.ncx 代码 + .ncxr 常量表）──────
    # 两段共用 k_so：逻辑上是同一份资产。MAC 覆盖【所有密文的拼接】，
    # 于是任何一段被改都会让整体验签失败（与单段语义完全一致）。
    segs = []                      # [(name, sec, plain, cipher)]
    for nm in sec_names:
        sc = elf.find(nm)
        if sc is None:
            print('❌ 段 %s 不存在。先确认 C 代码用 __attribute__((section("%s"))) 标记了它。'
                  % (nm, nm), file=sys.stderr)
            print('   现有段: %s' % ', '.join(x['name'] for x in elf.sections),
                  file=sys.stderr)
            return 1
        elf.require_shf_alloc(sc)
        if sc['size'] == 0:
            print('❌ 段 %s 长度为 0，没有内容可锁' % nm, file=sys.stderr)
            return 1
        pl = bytes(elf.data[sc['offset']: sc['offset'] + sc['size']])
        segs.append((nm, sc, pl, rc4(k_so, pl)))

    plain = segs[0][2]             # 兼容下方 dry-run 打印与旧日志
    cipher = segs[0][3]

    # 期望 MAC 对【密文】算，不对明文算：密文在解密前就可读，于是可以
    # "先验后解" —— 一旦被改过，根本不会把明文装进 .ncx（fail-closed）。
    # 若对明文算，就必须先解密再验，篡改的明文已经落盘生效，晚一步。
    # 另一个理由是 RC4 是流密码：改密文 1 位恰好只翻明文 1 位，未必崩溃，
    # 攻击者可以"改一位→跑→看行为"做廉价 oracle；MAC 让这种试探第一次就暴露。
    _mac_input = b''.join(sg[3] for sg in segs)   # 所有段密文按顺序拼接
    expect_mac = hmac_sha256(k_mac, _mac_input)

    if dry:
        print('[dry-run] 段 %s: %d 字节 → %d 字节（size-preserving=%s）'
              % (section, len(plain), len(cipher), len(plain) == len(cipher)))
        print('[dry-run] 密钥（hex）: %s' % k_so.hex())
        print('[dry-run] mac 域（hex）: %s' % k_mac.hex())
        print('[dry-run] 期望 MAC（hex，对密文算）: %s' % expect_mac.hex())
        print('[dry-run] 未写文件')
        return 0

    # 写回密文（各段原地，长度不变）
    for nm, sc, pl, ci in segs:
        elf.data[sc['offset']: sc['offset'] + sc['size']] = ci

    # 密钥槽：magic(16) + wrapped_k_so(16) + wrapped_k_mac(16) + expect_mac(32)
    #          + pkg_sha8(8) + reserved(8) = 96 字节
    #          .nck 段必须同步扩到 96（否则 assert 炸）
    # ⚠️ 切片窗口必须与 blob 等长：elf.data[a:b] = blob 若 len(blob) > b-a，
    # Python 会【插入】而非覆盖，把后续字节（段表/相邻段）顶坏。本人踩过。
    # 布局保持 magic+wrapped_k_so 在前 32 字节【不变】——旧 C 侧开箱代码
    # 从 offset 16 读 k_so，向前兼容。
    #
    # 2026-10-19 P1-a 扩容 80→96：
    #   [80:88] pkg_sha8 —— SHA256(包名) 前 8 字节。运行期用 /proc/self/cmdline
    #           取到的进程名算同样指纹做一致性校验，不一致即 fail-closed(-12)。
    #           存指纹而非明文包名：明文会暴露"密钥与包名有关"这条线索。
    #   [88:96] reserved —— 对齐预留，将来加字段不必再动长度契约。
    # ⚠️⚠️ 2026-10-19 P1-a 关键：slot[16:32] 不再存真实 k_so 的 wrapped 版本！
    #
    # 原实现 `wrapped = k_so ^ XOR_KEY` 会让 P1-a 完全失去意义：
    # 证书派生的目的就是"密钥不在文件里"，可 slot 里又躺了一份 packaged
    # 真密钥 → 攻击者 `slot[16:32] ^ XOR_KEY` 照样拿到 k_so，
    # 20 行 Python 解完，运行期派生再多也是白做。
    #
    # 现在这里写【诱饵】：确定性随机值，与真 k_so 无关。
    # 运行期 ncg_head_unlock() 从证书重新派生 k_so，根本不读这段。
    # 保留 16 字节是为了维持 slot 布局与"存在一个 k_so 字段"的假象，
    # 让攻击者以为自己找到了密钥（然后解出乱码）。
    #
    # 同理 k_mac 也不该落盘 —— 它是 HMAC 密钥，落盘等于把完整性校验
    # 交给攻击者。运行期同样从证书重新派生。
    # ⚠️ 2026-10-19 诱饵改真随机（原来是确定性 sha256，被复测报告识破）：
    #   报告 §7.1 实测第一版与第二版的 wrapped_k_so 完全相同
    #   （d6054d96f1e71285...），据此判定「它是诱饵死字段，不参与真实派生」。
    #   确定性诱饵的问题：同一个包名永远生成同一串字节，
    #   **两版产物一比对立功**——攻击者不需要懂任何密码学，只要 diff 两个 so。
    #   改 os.urandom 后每次构建都不同，diff 手法失效。
    _decoy_seed = os.urandom(16)
    wrapped = bytes(b ^ XOR_KEY[i % len(XOR_KEY)]
                    for i, b in enumerate(_decoy_seed))
    _decoy_mac = os.urandom(16)
    wrapped_mac = bytes(b ^ XOR_KEY[i % len(XOR_KEY)]
                        for i, b in enumerate(_decoy_mac))
    pkg_sha8 = hashlib.sha256((package or '').encode('utf-8')).digest()[:8]
    blob = (SLOT_MAGIC + wrapped + wrapped_mac + expect_mac
            + pkg_sha8 + b'\x00' * 8)
    assert len(blob) == _LAYOUT['NC_SLOT_SIZE'], \
        ('blob %d != NC_SLOT_SIZE %d（nc_guard_layout.h 与 C 侧 ncg_key_slot[] '
         '长度不一致；改一侧必须同步另一侧）'
         % (len(blob), _LAYOUT['NC_SLOT_SIZE']))
    assert len(blob) == slot['size'], \
        'blob %d != slot size %d（.nck 段需扩到 %d；改了一侧必须同步另一侧）' \
        % (len(blob), slot['size'], _LAYOUT['NC_SLOT_SIZE'])
    elf.data[slot['offset']: slot['offset'] + len(blob)] = blob

    # 熵值安检（2026-10-18）：必须在【写盘之前】。
    # 若放到写盘之后，fail-fast 时坏包已经落盘，protect.sh 虽然 exit 1 但
    # 文件已在——而它会被后续步骤当成有效产物。所以先验后写。
    if not dry:
        for nm, sc, pl, ci in segs:
            ent = check_entropy_or_fail(elf, nm)
            if ent > 0:
                print('   熵值安检[%s]: %.3f（下限 %.1f）✅' % (nm, ent, ENTROPY_MIN))
            else:
                _sec = elf.find(nm)
                print('   熵值安检[%s]: 段仅 %d 字节（< %d），样本不足跳过'
                      % (nm, _sec['size'] if _sec else 0, ENTROPY_MIN_BYTES))

    with open(out_path, 'wb') as f:
        f.write(bytes(elf.data))

    print('✅ 已锁: %s → %s' % (so_path, out_path))
    for nm, sc, pl, ci in segs:
        print('   段 %s: %d 字节已加密（size-preserving，共用 k_so）' % (nm, len(pl)))
    print('   密钥槽 %s: %d 字节' % (SLOT_NAME, len(blob)))
    print('   ⚠️ 运行期需配套"开箱"代码解密；没有它，这段代码不可执行')
    return 0


# ── 二级锁箱：把 unlock 本体也锁进密文（自解谜）───────────────────
def lock_head(so_path: str, out_path: str, force: bool = False) -> int:
    """锁 .ncxh 段，并给明文 stub 写它的密钥槽。

    这是"把开锁器锁进它开的那只箱子"的构建期半边：
      .ncxh（unlock 本体）← 用 k_stub 锁
      .ncks（stub 的槽）    ← 写 magic + wrapped_k_stub + stub/head 段
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
        # 而只要编译了，nc_guard_boot.c 就在工程里、.ncxh 段就该在。
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

    # ── 阶段3 代码自绑定（2026-10-19）────────────────────────────────
    # 修强度报告 §6「抗静态 patch = 弱」：此前 k_stub 与代码零关联，
    # 攻击者 patch 明文 stub（如把 HMAC 校验改恒真）无需代价。
    #
    # 现在把 .text 段的 CRC32 混进实际用于加密的密钥：
    #   cipher_key = k_stub ^ fold(crc32(.text))
    # 运行期 stub 先对 .text 算同样的 CRC，异或回去，才能得到正确密钥。
    # 改任何一处明文代码 → CRC 变 → 密钥错 → head 解出乱码 → SIGILL。
    #
    # 为什么能自洽：.text 段 addr==offset 且整体无重定位
    # （实测 readelf -r 的重定位全部落在 0x71d0 之后，.text 结束于 0x2714），
    # 所以锁箱期按文件算的 CRC == 运行期按内存算的 CRC。
    # 注意：CRC 覆盖 .text【锁箱前】的字节；二级锁箱只改 .ncxh，
    # 不动 .text，所以运行期看到的 .text 与锁箱期完全一致。
    text_sec = elf.find('.text')
    if text_sec is None:
        raise ElfError('.text 段不存在，无法做代码自绑定（阶段3）')
    _text_bytes = bytes(elf.data[text_sec['offset']:
                                 text_sec['offset'] + text_sec['size']])
    code_crc = zlib.crc32(_text_bytes) & 0xFFFFFFFF
    # 折叠进 16 字节密钥：与 C 侧 `k[i] ^= (crc >> ((i&3)*8)) & 0xFF` 同规则
    k_stub_eff = bytes(
        k_stub[i] ^ ((code_crc >> ((i & 3) * 8)) & 0xFF) for i in range(16)
    )
    print('   代码自绑定: CRC32(.text)=0x%08x → 已混入 k_stub' % code_crc)
    # k_mac_head：第三把钥匙，只用于 head 段的完整性校验（P0-b）。
    # 与 k_stub / k_so 都必须不同——复用任何一把都意味着"解开 head 就等于
    # 拿到业务段的钥匙"或"知道解密钥匙即可伪造 MAC"，分级失去意义。
    k_mac_head = bytes([0x91, 0x4A, 0xD2, 0x08, 0x7B, 0xE3, 0x5F, 0xC6,
                        0x2D, 0xB8, 0x64, 0x17, 0xAF, 0x39, 0x8E, 0x51])

    # ── master 随机化 + 藏进 .ncxhr（2026-10-19）──────────
    #
    # 修实测报告静态 P1-1：master[32] 原是 static const 全 0x11 的占位符，
    # 躺在 .rodata，`od` 一条命令读出 → 配合 APK 证书离线算 k_so →
    # 8 分钟解开 .ncx。全程不需要运行、不需要真机、不需要私钥。
    #
    # 只换成随机数不够：随机值若仍是 .rodata 裸常量，`od` 一样读，成本不变。
    # 必须【同时】做到：值随机 + 藏在读不到的地方。
    #
    # 现在：master 写进 .ncxhr 段，用【k_stub】加密（不是 k_so！）。
    #   · 用 k_stub：链路单向 —— 碎片 → XOR_KEY → k_stub → {解 head,
    #     解 head_ro → master} → k_so。没有循环依赖。
    #   · 用 k_so 会死循环：k_so 的派生正需要 master。
    #
    # 攻击链从 2 步变 5 步，且中间产物全不是明文常量。
    head_ro = elf.find(HEAD_RO_NAME)
    if head_ro is None:
        raise ElfError('段 %s 不存在 —— master 无处存放（nc_guard_boot.c 的 '
                       'ncg_master 是否被标段？需 NC_GUARD_SECTIONED）'
                       % HEAD_RO_NAME)
    if head_ro['size'] < 32:
        raise ElfError('%s 只有 %d 字节，容不下 32 字节 master'
                       % (HEAD_RO_NAME, head_ro['size']))
    # master 已由一级锁箱（lock()）写入明文，这里只负责加密它。
    # ⚠️ 顺序不可颠倒：lock() 要用 master 派 k_so，所以它必须先存在；
    #    lock_head() 用 k_stub 把它锁起来。反过来做就没有 master 可用。
    ro_plain = bytes(elf.data[head_ro['offset']:
                             head_ro['offset'] + 32])
    if not any(ro_plain):
        raise ElfError('%s 里的 master 全零 —— 一级锁箱没跑过？'
                       '必须严格按「先 --section 再 --lock-head」的顺序'
                       % HEAD_RO_NAME)
    master = ro_plain
    ro_cipher = bytes(master[i] ^ k_stub_eff[i % 16] for i in range(32))
    # ⚠️ 等长覆盖：切片赋值长度不等会"插入"而非"覆盖"，顶坏后续字节
    assert len(ro_cipher) == 32
    elf.data[head_ro['offset']: head_ro['offset'] + 32] = ro_cipher
    print('   master: 已锁入 %s（用 k_stub，非 k_so；攻击链 +3 步）'
          % HEAD_RO_NAME)

    plain = bytes(elf.data[head['offset']: head['offset'] + head['size']])
    # ⚠️ 必须是【简单循环 XOR】，不能用 rc4()！
    # 2026-10-18 实测踩过：这里抄了 rc4()，而 stub 侧是
    #   `for(i<head_size) start[i] ^= k[i & 15];`
    # 两边算法不同 → 解出来是乱 C → dlopen 即 SIGILL（exit 132）。
    # 刻意不用 RC4 的理由：明文 stub 里不能出现 256 字节 S 盒初始化循环
    # —— 那本身就是"这是 RC4"的活招牌，且会显著撑大 stub。简单 XOR 的
    # 代价由 HMAC 兜底（head 段的 MAC 见下方 P0-b，2026-10-18 补上）。
    cipher = bytes(b ^ k_stub_eff[i % len(k_stub_eff)] for i, b in enumerate(plain))

    elf.data[head['offset']: head['offset'] + head['size']] = cipher

    # P0-b：对【密文】算 HMAC-SHA256(k_mac_head, head 密文)。
    # 与 .ncx 的 expect_mac 完全同构——解密前就能验，验不过就不装明文。
    # 在此之前 head 段只有 XOR，攻击者可改 head 密文中对应"unlock 本体的
    # MAC 校验函数"那几位，把 .ncx 的 HMAC 保护改成恒真从而绕过。
    expect_mac_head = hmac_sha256(k_mac_head, cipher)

    # stub 槽（96 字节，2026-10-19 阶段3）：magic(8) + wrapped_k_stub(16)
    #   + stub_sh_addr(4) + head_sh_addr(4) + head_size(4)
    #   + code_addr(4) + code_len(4) + reserved(4)          ← 阶段3 新增 8+4
    #   + wrapped_k_mac_head(16) + expect_mac_head(32)
    # ⚠️ 全程用 section header table 的 sh_addr/size，不碰 .symtab（见上方注释）
    #
    # 阶段3 代码自绑定（修强度报告「抗静态 patch = 弱」）：
    #   code_addr/code_len 指向 .text 段。运行期 stub 对这段算 CRC32 并
    #   异或进 k_stub —— 改任何一处明文代码 → CRC 变 → k_stub 变 →
    #   head 解出乱码。没有"校验分支"可以单独 patch 掉，形成链式依赖。
    #   为什么能自洽：.text 段 addr==offset 且【整体无重定位】
    #   （readelf -r 的重定位全部落在 0x71d0 之后，而 .text 结束于 0x2714），
    #   所以锁箱期按文件算的 CRC 与运行期按内存算的完全相同。
    import struct as _s
    text = elf.find('.text')
    if text is None:
        raise ElfError('.text 段不存在，无法做代码自绑定（阶段3）')
    wrapped = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(k_stub))
    wrapped_mac = bytes(b ^ XOR_KEY[i % len(XOR_KEY)]
                        for i, b in enumerate(k_mac_head))
    blob = (STUB_MAGIC + wrapped
            + _s.pack('<I', slot['addr'])
            + _s.pack('<I', head['addr'])
            + _s.pack('<I', head['size'])
            + _s.pack('<I', text['addr'])
            + _s.pack('<I', text['size'])
            + _s.pack('<I', 0)
            + wrapped_mac
            + expect_mac_head
            + _s.pack('<I', head_ro['addr'])
            + _s.pack('<I', 32))
    assert len(blob) == _LAYOUT['NC_STUB_SIZE'], \
        ('stub blob %d != NC_STUB_SIZE %d（nc_guard_layout.h 与 C 侧 '
         'ncg_stub_slot[] 长度不一致；改一侧必须同步另一侧）'
         % (len(blob), _LAYOUT['NC_STUB_SIZE']))
    assert len(blob) == slot['size'], \
        'blob %d != slot size %d（.ncks 段需扩到 %d 字节；' \
        '改 nc_guard_layout.h 的 NC_STUB_SIZE 必须同步 C 侧）' \
        % (len(blob), slot['size'], _LAYOUT['NC_STUB_SIZE'])
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
