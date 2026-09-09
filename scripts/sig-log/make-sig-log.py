#!/usr/bin/env python3
# make-sig-log.py — 扫描 sig_check.c / env_check.c 的 /*LSG:...*/ 标记,
# 生成 sig_log_data.h:中文流程日志文案的 XOR 密文数组 + 消息 ID 枚举。
#
# 为什么这样设计(2026-11,用户需求"中文全流程日志" + so加固"strings 不泄语义"的延续):
#   - 明文只活在源码的 /*LSG:...*/ 注释里(调用点旁边,注释即真相,人/AI 可读);
#   - so 里只有密文,strings 看不到"签名校验/成功/失败"等路标词(不回退 2026-10 加固);
#   - 运行时 siglog_c()/envlog_c() 用同 key 异或解码后写日志文件(哨兵开关控制);
#   - key 也随本文件生成进头文件(防御定位:让自动扫描(strings)失效,不抗人工逆向)。
#
# 用法: make-sig-log.py <sig_check.c路径> <env_check.c路径> <输出sig_log_data.h路径>
# 生成文件在流水线 WORK 目录(build 中间产物,不进 git);注释删除/改名 → 生成器 fail-fast。

import re
import sys

def main():
    if len(sys.argv) != 4:
        print("用法: make-sig-log.py <sig_check.c> <env_check.c> <out.h>", file=sys.stderr)
        return 2

    src_sig, src_env, out_path = sys.argv[1], sys.argv[2], sys.argv[3]

    # 8 字节 key(避免单字节 key 让密文呈现规律性;足够打散 UTF-8 中文)
    key = bytes([0x5A, 0xC3, 0x11, 0x9E, 0xF0, 0x37, 0xB2, 0x6D])

    # 匹配 /*LSG:...*/ 单行标记(文案内禁止 */ 换行等,正则天然限定)
    pat = re.compile(r'/\*LSG:(.+?)\*/')
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
        return 0

    if scan(src_sig, 'sig') != 0:
        return 1
    if scan(src_env, 'env') != 0:
        return 1

    if not ids:
        print("❌ 未扫描到任何 /*LSG:NAME|文案*/ 标记", file=sys.stderr)
        return 1

    # 校验 %s/%d 格式符配对合法性交给编译器(生成数组按 UTF-8 原样编码,C 字符串不含 \0)
    def enc(s: str) -> bytes:
        data = s.encode('utf-8')
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    lines = []
    lines.append('/* sig_log_data.h — 由 make-sig-log.py 自动生成,勿手改(构建中间产物,不进 git)')
    lines.append(' *')
    lines.append(' * 中文流程日志文案的 XOR 密文 + 消息 ID。明文只存在于源码的 LSG 标记注释')
    lines.append(' * 中(形如 斜杠星LSG:NAME|文案星斜杠,此注释本身不能出现星斜杠字面量)')
    lines.append(' * 注释中(可读性);so 内只有密文(strings 不泄语义)。运行时解码写入日志文件。')
    lines.append(' * 重新生成: python3 scripts/sig-log/make-sig-log.py <sig_check.c> <env_check.c> <out.h> */')
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
    lines.append('#define LSG_KEY_LEN 8')
    lines.append(f'static const unsigned char LSG_KEY[LSG_KEY_LEN] = {{ '
                 + ', '.join(f'0x{b:02x}' for b in key) + ' };')
    lines.append('')
    lines.append('/* 密文表:与 lsg_id_t 下标一一对应;每条以 \\0 结尾(密文里 0x00 即原串终结符的编码前哨) */')
    lines.append('typedef struct { const unsigned char *data; unsigned int len; } lsg_msg_t;')
    for full, _prefix, content in ids:
        e = enc(content)
        arr = ', '.join(f'0x{b:02x}' for b in e)
        lines.append(f'static const unsigned char LSG_DATA_{full[4:]}[{len(e)}] = {{ {arr} }};')
    lines.append('')
    lines.append('static const lsg_msg_t LSG_MSGS[LSG_ID_COUNT] = {')
    for full, _prefix, content in ids:
        e = enc(content)
        lines.append(f'    {{ LSG_DATA_{full[4:]}, {len(e)} }},  /* {full} */')
    lines.append('};')
    lines.append('')
    lines.append('/* 解码到 buf(UTF-8),返回写入长度(不含 \\0);buf 不够返回 -1 */')
    lines.append('static int lsg_decode(lsg_id_t id, char *buf, size_t buflen) {')
    lines.append('    const lsg_msg_t *m;')
    lines.append('    unsigned int i;')
    lines.append('    if ((int)id < 0 || (int)id >= LSG_ID_COUNT || !buf || buflen == 0) return -1;')
    lines.append('    m = &LSG_MSGS[id];')
    lines.append('    if ((size_t)m->len + 1 > buflen) return -1;')
    lines.append('    for (i = 0; i < m->len; i++)')
    lines.append('        buf[i] = (char)(m->data[i] ^ LSG_KEY[i % LSG_KEY_LEN]);')
    lines.append('    buf[m->len] = \'\\0\';')
    lines.append('    return (int)m->len;')
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
