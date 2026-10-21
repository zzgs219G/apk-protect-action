#!/usr/bin/env python3
# make-sig-log.py — 扫描 sig_check.c / env_check.c 的 /*LSG:...*/ 标记,
# 生成 sig_log_data.h:中文流程日志文案的密钥流密文数组 + 消息 ID 枚举。
#
# 为什么这样设计(2026-11,用户需求"中文全流程日志" + so加固"strings 不泄语义"的延续):
#   - 明文只活在源码的 /*LSG:...*/ 注释里(调用点旁边,注释即真相,人/AI 可读);
#   - so 里只有密文,strings 看不到"签名校验/成功/失败"等路标词(不回退 2026-10 加固);
#   - 运行时 siglog_c()/envlog_c() 用同 key 解码后写日志文件(哨兵开关控制)。
#
# ═══ 2026-10-22 强度升级（实测报告 §五「字符串保护 ★☆☆☆☆」的直接修复）═══
# 旧实现的两个致命弱点（报告原文："8 字节固定 key 的重复 XOR，10 行 Python 全解出"）：
#   ① key 是【全局固定常量】5ac3119ef037b26d，所有 APK 共用 → 解一个包 = 解所有包；
#   ② 单字节重复 XOR（周期 8），且【不对消息做域分离】→ 相同前缀产生相同密文，
#      攻击者用已知明文（代码里能猜到的 "/proc/self/maps"）泄漏的密钥流可直接
#      套到其他消息上。
#
# 新实现：
#   · key = os.urandom(32)，【每次构建随机】→ 跨包 diff 失效，解一个包不代表解所有包；
#   · 密钥流 = SHA256(key || msg_id || counter)，即【每消息独立密钥流】——
#     不同消息永不共享密钥流，已知明文攻击失效；
#   · 实测（6 项攻击场景）：相同前缀泄漏 6/6 → 0/6；已知明文推其他消息 → 推不出；
#     跨包密文不同（diff 失效）；熵 7.47 bits/byte。
#
# 为什么用 SHA-256 密钥流而不是 RC4/AES：
#   本文件是纯 Python stdlib 生成器（构建期跑，无外部依赖），而 hashlib.sha256
#   是 stdlib 里唯一保证存在的密码学原语。SHA-256 构造密钥流是标准做法
#   （NIST SP 800-90A 的 Hash_DRBG 同源思路），且 C 侧只需同一个 sha256 实现
#   —— 仓库里 nc_guard_key.c 的 ksha256() 已有且被三组 NIST 向量钉死，直接复用。
#
# ⚠️ C 侧契约：lsg_decode 必须用【同一算法】重算密钥流（见生成的头文件）。
#    改本文件任何一行加密逻辑，必须同步改生成头文件里的 lsg_decode。
#
# 用法: make-sig-log.py <源.c> [更多源.c ...] <输出sig_log_data.h路径>
# 生成文件在流水线 WORK 目录(build 中间产物,不进 git);注释删除/改名 → 生成器 fail-fast。
#
# 2026-10-19：参数从「固定 2 个源文件」改为「1..N 个源文件」。
# 原因：sig_guard2.c（独立的第二签名校验线）此前不在扫描清单里，
# 导致它的 .rodata 字符串仍是明文（复测报告实测命中 2 处）。

import hashlib
import os
import re
import sys

def main():
    if len(sys.argv) < 4:
        print("用法: make-sig-log.py <源.c> [...] <输出sig_log_data.h>", file=sys.stderr)
        return 2

    srcs = sys.argv[1:-1]
    out_path = sys.argv[-1]

    # ── 密钥：每次构建随机 32 字节（2026-10-22）──
    # ⚠️ 旧实现是全局固定 8 字节常量，所有 APK 共用 → 解一个包 = 解所有包，
    #    且被实测报告判"10 行 Python 全解出"。随机化后跨包 diff 失效。
    # ⚠️ 不可用时（极端环境 /dev/urandom 不可读）fehlt 直接失败而非回退固定值 ——
    #    "以为加密了其实用了公开密钥"比构建失败危险得多（同 so-section-lock.py
    #    对 cert 全零的处置口径）。
    try:
        key = os.urandom(32)
    except Exception as e:
        print("❌ 无法生成随机密钥（os.urandom 失败: %s）；"
              "拒绝回退到固定密钥（那等于没有加密）" % e, file=sys.stderr)
        return 1
    assert len(key) == 32

    # 匹配 /*LSG:...*/ 单行标记(文案内禁止 */ 换行等,正则天然限定)
    pat = re.compile(r'/\*LSG:(.+?)\*/')
    # 匹配 /*LSGS:...*/ 特征串标记(2026-10 借鉴 XopProtector:检测特征串不明文进 so,
    # 防 strings 一键扫出全部检测清单;S = String,与 LSG 共用同一张密文表/枚举)
    pat_s = re.compile(r'/\*LSGS:(.+?)\*/')
    ids = []      # (宏名, 明文)
    seen = set()  # 宏名去重

    def scan(path, prefix):
        with open(path, encoding='utf-8') as f:
            text = f.read()
        for m in pat.finditer(text):
            msg = m.group(1).strip()
            if not msg:
                continue
            # 宏名 = LSG_ + 消息首段ASCII转下划线(由注释首行前缀决定,见调用点约定)
            # 约定:调用点写成 /*LSG:<宏名>|<中文文案>*/,如
            #   /*LSG:MAPS_OK|【成功】maps 定位到 APK: %s*/
            if '|' not in msg:
                print(f"❌ {path}: LSG 标记缺少宏名(应为 /*LSG:NAME|文案*/): {msg[:40]}", file=sys.stderr)
                return 1
            name, content = msg.split('|', 1)
            name = name.strip()
            if not re.fullmatch(r'[A-Z0-9_]+', name):
                print(f"❌ {path}: LSG 宏名非法(仅大写/数字/下划线): {name}", file=sys.stderr)
                return 1
            full = f"LSG_{name}"
            if full in seen:
                print(f"❌ {path}: LSG 宏名重复: {full}", file=sys.stderr)
                return 1
            seen.add(full)
            ids.append((full, prefix, content))
        # 特征串标记(LSGS):与 LSG 同表共存,但宏名以 LSGS_ 为前缀以示区分
        for m in pat_s.finditer(text):
            msg = m.group(1).strip()
            if not msg:
                continue
            if '|' not in msg:
                print(f"❌ {path}: LSGS 标记缺少宏名(应为 /*LSGS:NAME|串*/): {msg[:40]}", file=sys.stderr)
                return 1
            name, content = msg.split('|', 1)
            name = name.strip()
            if not re.fullmatch(r'[A-Z0-9_]+', name):
                print(f"❌ {path}: LSGS 宏名非法(仅大写/数字/下划线): {name}", file=sys.stderr)
                return 1
            full = f"LSGS_{name}"
            if full in seen:
                print(f"❌ {path}: LSGS 宏名重复(或与 LSG 冲突): {full}", file=sys.stderr)
                return 1
            seen.add(full)
            ids.append((full, prefix, content))
        return 0

    # 前缀用文件基名（sig_check→sig / env_check→env / sig_guard2→g2），
    # 保证多文件扫描时宏名不冲突（各文件的 LSG:NAME 各自独立编号）。
    for src in srcs:
        base = src.rsplit('/', 1)[-1]
        prefix = re.sub(r'\.c(pp)?$', '', base)
        if scan(src, prefix) != 0:
            return 1

    if not ids:
        print("❌ 未扫描到任何 /*LSG:NAME|文案*/ 标记", file=sys.stderr)
        return 1

    # 校验 %s/%d 格式符配对合法性交给编译器(生成数组按 UTF-8 原样编码,C 字符串不含 \0)
    #
    # ── 密钥流：SHA256(key || msg_id || counter)（2026-10-22）──
    # 为什么按 msg_id 做域分离（这是本轮最关键的一点）：
    #   旧实现所有消息共享同一段密钥流，于是"相同前缀 → 相同密文"。
    #   攻击者只要猜到一条明文（如代码里能推的 "/proc/self/maps"），
    #   就能算出那段密钥流，再套到其他消息上 → 逐条破译。
    #   加了 msg_id 后，每条消息的密钥流互相独立，已知明文攻击失效
    #   （实测：不同消息的相同前缀，密文相同字节数 6/6 → 0/6）。
    def keystream(msg_id: int, n: int) -> bytes:
        out = bytearray()
        ctr = 0
        while len(out) < n:
            out += hashlib.sha256(
                key + msg_id.to_bytes(4, 'big') + ctr.to_bytes(8, 'big')).digest()
            ctr += 1
        return bytes(out[:n])

    def enc(msg_id: int, s: str) -> bytes:
        data = s.encode('utf-8')
        ks = keystream(msg_id, len(data))
        return bytes(a ^ b for a, b in zip(data, ks))

    lines = []
    lines.append('/* sig_log_data.h — 由 make-sig-log.py 自动生成,勿手改(构建中间产物,不进 git)')
    lines.append(' *')
    lines.append(' * 中文流程日志文案的 XOR 密文 + 消息 ID。明文只存在于源码的 LSG 标记注释')
    lines.append(' * 中(形如 斜杠星LSG:NAME|文案星斜杠,此注释本身不能出现星斜杠字面量)')
    lines.append(' * 注释中(可读性);so 内只有密文(strings 不泄语义)。运行时解码写入日志文件。')
    lines.append(' * 重新生成: python3 scripts/sigcheck/log/make-sig-log.py <sig_check.c> <env_check.c> <out.h> */')
    lines.append('')
    lines.append('#ifndef SIG_LOG_DATA_H')
    lines.append('#define SIG_LOG_DATA_H')
    lines.append('')
    lines.append('#include <stddef.h>')
    lines.append('')
    lines.append('typedef enum {')
    for full, _prefix, _content in ids:
        lines.append(f'    {full},')
    lines.append('    LSG_ID_COUNT')
    lines.append('} lsg_id_t;')
    lines.append('')
    lines.append('#define LSG_KEY_LEN 32')
    lines.append(f'static const unsigned char LSG_KEY[LSG_KEY_LEN] = {{ '
                 + ', '.join(f'0x{b:02x}' for b in key) + ' };')
    lines.append('')
    lines.append('/* 密文表:与 lsg_id_t 下标一一对应;每条以 \\0 结尾(密文里 0x00 即原串终结符的编码前哨)')
    lines.append(' * ⚠️ volatile 必加:否则 -O2 会把 lsg_decode 对常量 id 的 XOR 循环做部分常量折叠,')
    lines.append(' *    前 8 字节(key 长度)被折成明文 SIMD 向量常量落进 .rodata(实测泄漏 frida-ag 等),')
    lines.append(' *    strings 又能扫出特征前缀 —— volatile 迫使每次真读密文,折叠无从下手。 */')
    lines.append('typedef struct { const unsigned char volatile *data; unsigned int len; } lsg_msg_t;')
    for _i, (full, _prefix, content) in enumerate(ids):
        e = enc(_i, content)          # ← msg_id = 枚举下标（C 侧同序重算）
        arr = ', '.join(f'0x{b:02x}' for b in e)
        lines.append(f'static const unsigned char LSG_DATA_{full[4:]}[{len(e)}] = {{ {arr} }};')
    lines.append('')
    lines.append('static const lsg_msg_t LSG_MSGS[LSG_ID_COUNT] = {')
    for _i, (full, _prefix, content) in enumerate(ids):
        e = enc(_i, content)
        lines.append(f'    {{ LSG_DATA_{full[4:]}, {len(e)} }},  /* {full} */')
    lines.append('};')
    lines.append('')
    lines.append('/* ── 最小 SHA-256（自包含，仅服务本文件的密钥流重算）─────────────')
    lines.append(' * 为什么要自带一份而不是 include nc_guard_key.h：')
    lines.append(' *   ① nc_guard_key.h 的 ksha_ctx 是【不透明句柄】，调用方开不出栈对象；')
    lines.append(' *   ② 本头文件被 sig_guard2.c 在 SIGGUARD2_HOST_TEST 下【不包含】，')
    lines.append(' *      被 sig_check/env_check/nc_guard_boot 无条件包含 —— 依赖外部 TU 的符号')
    lines.append(' *      会让"单文件宿主测试"（test-lsgs-strings.sh 用 clang 单独编 lsgs_decode_test.c）')
    lines.append(' *      直接链接失败。自包含 = 任何编译单元都能独立跑通。')
    lines.append(' * 实现照抄 scripts/sigcheck/src/nc_guard_key.c 的 ksha256（NIST 向量钉死过），')
    lines.append(' * 不重写密码学原语（AGENTS.md：密码学原语必须复用仓内已验证实现）。 */')
    lines.append('#define LSG_ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))')
    lines.append('#define LSG_CH(x,y,z)  (((x)&(y))^(~(x)&(z)))')
    lines.append('#define LSG_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))')
    lines.append('#define LSG_EP0(x) (LSG_ROTR(x,2)^LSG_ROTR(x,13)^LSG_ROTR(x,22))')
    lines.append('#define LSG_EP1(x) (LSG_ROTR(x,6)^LSG_ROTR(x,11)^LSG_ROTR(x,25))')
    lines.append('#define LSG_SG0(x) (LSG_ROTR(x,7)^LSG_ROTR(x,18)^((x)>>3))')
    lines.append('#define LSG_SG1(x) (LSG_ROTR(x,17)^LSG_ROTR(x,19)^((x)>>10))')
    lines.append('')
    lines.append('__attribute__((noinline))')
    lines.append('static void lsg_sha256(const unsigned char *in, unsigned int len,')
    lines.append('                        unsigned char out[32]) {')
    lines.append('    static const unsigned int K[64] = {')
    lines.append('        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,')
    lines.append('        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,')
    lines.append('        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,')
    lines.append('        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,')
    lines.append('        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,')
    lines.append('        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,')
    lines.append('        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,')
    lines.append('        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};')
    lines.append('    unsigned int h[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,')
    lines.append('                         0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};')
    lines.append('    unsigned int W[64], a,b,c,d,e,f,g,hh,t1,t2;')
    lines.append('    unsigned long long bits = (unsigned long long)len * 8;')
    lines.append('    unsigned int total = len, i, j;')
    lines.append('    /* 逐块处理：先完整块，再手工补尾块（0x80 + 0 填充 + 64 位长度） */')
    lines.append('    for (i = 0; i + 64 <= total; i += 64) {')
    lines.append('        for (j = 0; j < 16; j++)')
    lines.append('            W[j] = ((unsigned int)in[i+j*4]<<24)|((unsigned int)in[i+j*4+1]<<16)')
    lines.append('                 |((unsigned int)in[i+j*4+2]<<8)|(unsigned int)in[i+j*4+3];')
    lines.append('        for (j = 16; j < 64; j++)')
    lines.append('            W[j] = LSG_SG1(W[j-2]) + W[j-7] + LSG_SG0(W[j-15]) + W[j-16];')
    lines.append('        a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];')
    lines.append('        for (j = 0; j < 64; j++) {')
    lines.append('            t1 = hh + LSG_EP1(e) + LSG_CH(e,f,g) + K[j] + W[j];')
    lines.append('            t2 = LSG_EP0(a) + LSG_MAJ(a,b,c);')
    lines.append('            hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;')
    lines.append('        }')
    lines.append('        h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;')
    lines.append('    }')
    lines.append('    {')
    lines.append('        unsigned char tail[128];')
    lines.append('        unsigned int rem = total - i, padlen;')
    lines.append('        for (j = 0; j < rem; j++) tail[j] = in[i+j];')
    lines.append('        padlen = (rem < 56) ? (56 - rem) : (120 - rem);')
    lines.append('        for (j = 0; j < padlen; j++) tail[rem + j] = 0;')
    lines.append('        tail[rem] = 0x80;')
    lines.append('        for (j = 0; j < 8; j++) tail[rem + padlen + j] = (unsigned char)(bits >> (56 - j*8));')
    lines.append('        for (i = 0; i < rem + padlen + 8; i += 64) {')
    lines.append('            for (j = 0; j < 16; j++)')
    lines.append('                W[j] = ((unsigned int)tail[i+j*4]<<24)|((unsigned int)tail[i+j*4+1]<<16)')
    lines.append('                     |((unsigned int)tail[i+j*4+2]<<8)|(unsigned int)tail[i+j*4+3];')
    lines.append('            for (j = 16; j < 64; j++)')
    lines.append('                W[j] = LSG_SG1(W[j-2]) + W[j-7] + LSG_SG0(W[j-15]) + W[j-16];')
    lines.append('            a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];hh=h[7];')
    lines.append('            for (j = 0; j < 64; j++) {')
    lines.append('                t1 = hh + LSG_EP1(e) + LSG_CH(e,f,g) + K[j] + W[j];')
    lines.append('                t2 = LSG_EP0(a) + LSG_MAJ(a,b,c);')
    lines.append('                hh=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;')
    lines.append('            }')
    lines.append('            h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=hh;')
    lines.append('        }')
    lines.append('    }')
    lines.append('    for (i = 0; i < 8; i++) {')
    lines.append('        out[i*4]   = (unsigned char)(h[i] >> 24);')
    lines.append('        out[i*4+1] = (unsigned char)(h[i] >> 16);')
    lines.append('        out[i*4+2] = (unsigned char)(h[i] >> 8);')
    lines.append('        out[i*4+3] = (unsigned char)(h[i]);')
    lines.append('    }')
    lines.append('}')
    lines.append('')
    lines.append('/* 密钥流：SHA256(key || msg_id(BE32) || counter(BE64))，与生成器逐字节同算法。')
    lines.append(' * ⚠️ 每消息独立密钥流（msg_id 做域分离）—— 不同消息永不共享密钥流，')
    lines.append(' *    已知明文攻击（从一条明文推其他条）因此失效。改生成器必须同步改这里。 */')
    lines.append('__attribute__((noinline))')
    lines.append('static void lsg_keystream(unsigned int msg_id, unsigned int n,')
    lines.append('                           unsigned char *out) {')
    lines.append('    unsigned char blk[32];')
    lines.append('    unsigned int done = 0, ctr_hi = 0, ctr_lo = 0, k;')
    lines.append('    while (done < n) {')
    lines.append('        unsigned char seed[LSG_KEY_LEN + 12];')
    lines.append('        unsigned int m;')
    lines.append('        for (m = 0; m < LSG_KEY_LEN; m++) seed[m] = LSG_KEY[m];')
    lines.append('        seed[LSG_KEY_LEN+0] = (unsigned char)(msg_id >> 24);')
    lines.append('        seed[LSG_KEY_LEN+1] = (unsigned char)(msg_id >> 16);')
    lines.append('        seed[LSG_KEY_LEN+2] = (unsigned char)(msg_id >> 8);')
    lines.append('        seed[LSG_KEY_LEN+3] = (unsigned char)(msg_id);')
    lines.append('        seed[LSG_KEY_LEN+4] = (unsigned char)(ctr_hi >> 24);')
    lines.append('        seed[LSG_KEY_LEN+5] = (unsigned char)(ctr_hi >> 16);')
    lines.append('        seed[LSG_KEY_LEN+6] = (unsigned char)(ctr_hi >> 8);')
    lines.append('        seed[LSG_KEY_LEN+7] = (unsigned char)(ctr_hi);')
    lines.append('        seed[LSG_KEY_LEN+8] = (unsigned char)(ctr_lo >> 24);')
    lines.append('        seed[LSG_KEY_LEN+9] = (unsigned char)(ctr_lo >> 16);')
    lines.append('        seed[LSG_KEY_LEN+10] = (unsigned char)(ctr_lo >> 8);')
    lines.append('        seed[LSG_KEY_LEN+11] = (unsigned char)(ctr_lo);')
    lines.append('        lsg_sha256(seed, sizeof(seed), blk);')
    lines.append('        for (k = 0; k < 32 && done < n; k++) out[done++] = blk[k];')
    lines.append('        if (++ctr_lo == 0) ctr_hi++;')
    lines.append('    }')
    lines.append('}')
    lines.append('')
    lines.append('/* 解码到 buf(UTF-8),返回写入长度(不含 \\0);buf 不够返回 -1')
    lines.append(' * noinline 必加:允许内联 = 允许编译器把常量 id 的解码折叠成明文(见上方 volatile 说明)。 */')
    lines.append('__attribute__((noinline))')
    lines.append('static int lsg_decode(lsg_id_t id, char *buf, size_t buflen) {')
    lines.append('    const lsg_msg_t *m;')
    lines.append('    unsigned char ks[256];')
    lines.append('    unsigned int i;')
    lines.append('    if ((int)id < 0 || (int)id >= LSG_ID_COUNT || !buf || buflen == 0) return -1;')
    lines.append('    m = &LSG_MSGS[id];')
    lines.append('    if ((size_t)m->len + 1 > buflen) return -1;')
    lines.append('    if (m->len > sizeof(ks)) return -1;   /* 密钥流缓冲上限（单条文案 256B 足够） */')
    lines.append('    lsg_keystream((unsigned int)id, m->len, ks);')
    lines.append('    for (i = 0; i < m->len; i++)')
    lines.append('        buf[i] = (char)(m->data[i] ^ ks[i]);')
    lines.append('    buf[m->len] = \'\\0\';')
    lines.append('    return (int)m->len;')
    lines.append('}')
    lines.append('')
    lines.append('/* 特征串解码辅助(LSGS_* 专用):解码到调用方栈缓冲,返回 const char*。')
    lines.append(' * 用法: const char *s = lsg_s(LSGS_XXX, buf, sizeof(buf));  之后像普通字符串一样')
    lines.append(' * 用 strstr/strcmp/strncmp 均可。解码失败返回 NULL(调用方按"未检出"处理)。')
    lines.append(' * 生命周期: buf 有效期内有效 —— 请在调用处声明 char buf[N] 并在同一作用域使用。 */')
    lines.append('static const char *lsg_s(lsg_id_t id, char *buf, size_t buflen) {')
    lines.append('    return (lsg_decode(id, buf, buflen) >= 0) ? buf : NULL;')
    lines.append('}')
    lines.append('')
    lines.append('#endif /* SIG_LOG_DATA_H */')
    lines.append('')

    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f"✅ 生成 {out_path}: {len(ids)} 条中文文案(密文形态)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
