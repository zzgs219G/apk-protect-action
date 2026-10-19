#!/usr/bin/env python3
"""so-harden.py — so 静态分析加固（AI 定向）

威胁模型：攻击者拿 libnc.so，用 IDA/Ghidra/BinaryNinja + LLM 反编译阅读。
不是防住，是推高 AI 的静态分析 token 消耗。三招，全部构建期完成，
零运行时性能损耗，git 工作区零改动（只变换 WORK 里的副本）。

  1. 标识符匿名化  static 函数/变量名 → 无意义短名
                     （JNIEXPORT 导出的 2 个函数保留，dalvm 按名调用）
  2. 字符串密文化  所有字符串字面量 → 构建期 XOR + 运行时一次性解密
  3. 注释剥离       AI 最省 token 的输入就是注释，源码进 so 虽不留注释，
                     但保留给"人读版"的源码常被直接贴给 AI

用法：
  so-harden.py <输入.c/.cpp> <输出.c/.cpp>

设计约束：
  - 只处理 static 作用域标识符（文件内可见），不动 extern/导出符号
  - 字符串只加密"长度>=4 且不含 % 格式符"的（% 要留给 __android_log_print）
  - 生成 C89/C++11 兼容代码（NDK clang 接受）
"""
import re
import sys

# ─── 1. 标识符匿名化 ────────────────────────────────────────────────
# 匹配 static 函数定义/声明的名字（不碰 extern、不碰 JNIEXPORT 那行）
RE_STATIC_FUNC = re.compile(r'\bstatic\s+[A-Za-z_][A-Za-z0-9_ \*]*?\b([a-z_][a-z0-9_]*)\s*\(')
RE_STATIC_VAR = re.compile(r'\bstatic\s+[A-Za-z_][A-Za-z0-9_ \*]*?\b([a-z_][a-z0-9_]*)\s*([=;\[,])')

def anon_identifiers(src: str) -> str:
    """static 标识符 → f_<n> 短名。确定性映射（同源多次生成同结果）。"""
    names = []
    for m in RE_STATIC_FUNC.finditer(src):
        names.append(m.group(1))
    for m in RE_STATIC_VAR.finditer(src):
        names.append(m.group(1))
    # 去重保序；短名不带语义
    uniq = sorted(set(n for n in names if not n.startswith('_')))
    mapping = {n: f'zz{i:03d}' for i, n in enumerate(uniq)}
    if not mapping:
        return src
    # 用词边界替换全文件（static 标识符的作用域就是本文件，安全）
    out = src
    for old, new in mapping.items():
        out = re.sub(r'\b%s\b' % re.escape(old), new, out)
    return out


# ─── 2. 字符串密文化 ────────────────────────────────────────────────
# XOR key 与 LSGS 同源（sig_log_data.h 的 8 字节 key），统一契约
XOR_KEY = bytes([0x5A, 0xC3, 0x11, 0x9E, 0xF0, 0x37, 0xB2, 0x6D])

def _is_encryptable(s: str) -> bool:
    """加密门槛：长度>=4、不含格式符（% 要留给 log）、不含路径分隔符外的敏感结构。"""
    if len(s) < 4:
        return False
    if '%' in s or '\n' in s or '\\' in s:
        return False
    return True

def encrypt_strings(src: str) -> str:
    """字符串字面量 → _sh(id) 调用；密文表附在文件尾部。"""
    # 保护 #include 整行：只替换 token 不够——`#include "nc.h"` 变成
    # `\x00INC\x00 "nc.h"` 后引号内容仍被下面的正則扫到（本例踩过）。
    # 改为整行藏起。
    lines = src.split('\n')
    held = []
    for idx, ln in enumerate(lines):
        if ln.lstrip().startswith('#include'):
            held.append(ln)
            lines[idx] = '\x00INC%d\x00' % (len(held) - 1)
    src = '\n'.join(lines)
    lits = []
    # 只匹配双引号字符串字面量（不含 include 路径与已生成的宏）
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', src):
        s = m.group(1)
        if _is_encryptable(s):
            lits.append(s)
    uniq = sorted(set(lits))
    if not uniq:
        return src

    # 密文表 + 解密函数（文件尾部注入）
    blob = ['']
    blob.append('/* so-harden: 字符串密文表（构建期生成，勿手改） */')
    blob.append('static const unsigned char _sh_blob[] = {')
    flat = bytearray()
    for s in uniq:
        enc = bytes(b ^ XOR_KEY[i % len(XOR_KEY)] for i, b in enumerate(s.encode('utf-8')))
        flat += enc
        flat.append(0)          # NUL 终结
        flat.append(len(s))     # 长度记录（解密时截断）
    for i in range(0, len(flat), 16):
        blob.append('    ' + ','.join('0x%02x' % b for b in flat[i:i+16]) + ',')
    blob.append('};')
    # id → (offset, len)，编译期常量
    off = 0
    entries = []
    for s in uniq:
        enc_len = len(s.encode('utf-8'))
        entries.append((off, len(s)))
        off += enc_len + 2
    blob.append('static const struct { unsigned o; unsigned l; } _sh_idx[] = {')
    for o, l in entries:
        blob.append('    {%d, %d},' % (o, l))
    blob.append('};')
    # 解密函数：返回 thread-unsafe 静态缓冲（调用点均为短生命周期使用）
    blob.append('static char _sh_buf[512];')
    # ⚠️ key 必须在 _sh() 之前定义（C 无前向声明时报"undeclared identifier"）
    blob.append('static const unsigned char _sh_key[8] = {0x5A,0xC3,0x11,0x9E,0xF0,0x37,0xB2,0x6D};')
    blob.append('static const char *_sh(unsigned id) {')
    blob.append('    unsigned o = _sh_idx[id].o, l = _sh_idx[id].l, i;')
    blob.append('    if (l >= sizeof(_sh_buf)) l = sizeof(_sh_buf) - 1;')
    blob.append('    for (i = 0; i < l; i++) _sh_buf[i] = (char)_sh_blob[o + i] ^ _sh_key[i & 7];')
    blob.append('    _sh_buf[l] = 0;')
    blob.append('    return _sh_buf;')
    blob.append('}')

    # 替换：按出现顺序编号
    counter = [0]
    idx_of = {s: i for i, s in enumerate(uniq)}
    def repl(m):
        s = m.group(1)
        if s in idx_of:
            return '"_sh(%d)"' % idx_of[s]
        return m.group(0)
    out = re.sub(r'"((?:[^"\\]|\\.)*)"', repl, src)
    # 还原 include 整行（编号占位 → 原文）
    for i, ln in enumerate(held):
        out = out.replace('\x00INC%d\x00' % i, ln)
    return out + '\n'.join(blob) + '\n'


# ─── 3. 注释剥离 ────────────────────────────────────────────────────
def strip_comments(src: str) -> str:
    """去掉 /*...*/ 与 // 注释。⚠️ 会误伤字符串内的 // 与 /*——用占位保护。"""
    # 保护字符串：先把字符串字面量替换成占位
    lits = []
    def keep(m):
        lits.append(m.group(0))
        return '\x00%d\x00' % (len(lits) - 1)
    protected = re.sub(r'"(?:[^"\\]|\\.)*"', keep, src)
    protected = re.sub(r'/\*.*?\*/', '', protected, flags=re.S)
    protected = re.sub(r'//[^\n]*', '', protected)
    # 还原
    def restore(m):
        return lits[int(m.group(1))]
    return re.sub(r'\x00(\d+)\x00', restore, protected)


def harden(src: str, *, do_ident=True, do_str=True, do_comment=False) -> str:
    if do_comment:
        src = strip_comments(src)
    if do_str:
        src = encrypt_strings(src)
    if do_ident:
        src = anon_identifiers(src)
    return src


def main(argv):
    if len(argv) != 3:
        print('用法: so-harden.py <输入> <输出>', file=sys.stderr)
        return 2
    with open(argv[1], encoding='utf-8') as f:
        src = f.read()
    flags = set(a[2:] for a in argv[3:] if a.startswith('--'))
    out = harden(src,
                 do_ident='no-ident' not in flags,
                 do_str='no-str' not in flags,
                 do_comment='comment' in flags)
    with open(argv[2], 'w', encoding='utf-8') as f:
        f.write(out)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
