#!/usr/bin/env python3
"""gen-jni-register.py — 从 NDK 工程源码自动生成 JNI 动态注册表

## 为什么需要它（2026-10-19，修实测报告 §1/§7.1）

实测报告用 `nm -D` 一条命令拿到了全部 JNI 入口名 + 每个函数的精确大小：

    Java_com_xixin_box_MainActivity_k__Landroid_os_Bundle_2       21692 B
    Java_com_xixin_box_MainActivity_onCreate__...                  5460 B
    Java_com_xixin_box_MainActivity_onConfigurationChanged__...     1084 B

`21692 B` 这种数字等于免费送出业务复杂度地图——加密层保护了代码内容，
却把地图摊开放在门口。报告据此「不解密就拿到业务方法清单」。

## 为什么不能用 objcopy 抹符号

dex2c 生成的函数是 `extern "C" JNIEXPORT ... JNICALL Java_xxx`
（`tools/Dex2C/dex2c/writer.py:111` 写死），ART 靠 `dlsym` 按名查找它们。
抹掉名字 = Java 侧 `UnsatisfiedLinkError`。

## 本工具做什么

扫描 NDK 工程里所有 `Java_<pkg>_<Class>_<method>` 形式的函数定义，
自动生成一张 RegisterNatives 表 + 一段注册代码：

  1. 从符号名推导 Java 类名与方法名，从参数列表推导 JNI 签名
  2. 生成 `nc_jni_gen_register.c`（含 `extern` 声明 + 方法表 + 注册函数）
  3. 原函数改名为 `ncg_d2c_<n>`（用 `-DJava_xxx=ncg_d2c_<n>` 编译宏实现，
     不改引擎产物源码）
  4. 链接期用 version script 只导出 `JNI_OnLoad`

于是 `.dynsym` 里只剩一个 `JNI_OnLoad`，业务方法名与大小全部消失。

## 安全边界（如实）

这不是"不可分析"，而是**提高定位成本**：符号名没了，攻击者要靠看
RegisterNatives 表的内容才能重建映射，而那张表在我们生成的 .c 里、
可以后续加密。真正的收益是消除"一条命令拿全清单"。

用法：
  gen-jni-register.py <jni目录> <输出.c路径>
"""
import os
import re
import sys

# Java_ 前缀 + 类路径 + 方法名（可能带 __签名后缀）
RE_JNI_NAME = re.compile(r'Java_([A-Za-z0-9_]+)')

# 从 C 源码里找 JNI 函数定义：
#   JNIEXPORT <ret> JNICALL Java_xxx(...)  或  extern "C" JNIEXPORT ...
RE_JNI_DEF = re.compile(
    r'JNIEXPORT\s+[A-Za-z_][A-Za-z0-9_*\s]*?\s+JNICALL\s+'
    r'(Java_[A-Za-z0-9_]+)\s*\(([^)]*)\)',
    re.MULTILINE,
)


def c_type_to_jni_sig(t):
    """把 C 参数类型映射成 JNI 签名字符。无法判断时返回 None。"""
    t = t.strip().replace('const ', '').replace(' ', '')
    if t in ('jboolean',):
        return 'Z'
    if t in ('jbyte',):
        return 'B'
    if t in ('jchar',):
        return 'C'
    if t in ('jshort',):
        return 'S'
    if t in ('jint',):
        return 'I'
    if t in ('jlong',):
        return 'J'
    if t in ('jfloat',):
        return 'F'
    if t in ('jdouble',):
        return 'D'
    if t in ('void',):
        return 'V'
    if t.startswith('jstring'):
        return 'Ljava/lang/String;'
    if t.startswith('jobject'):
        return 'Ljava/lang/Object;'
    if t.startswith('jclass'):
        return 'Ljava/lang/Class;'
    if t.startswith('jbyteArray'):
        return '[B'
    if t.startswith('jintArray'):
        return '[I'
    if t.startswith('jobjectArray'):
        return '[Ljava/lang/Object;'
    return None


def parse_defs(path):
    """返回 [(sym, ret_jni, params_jni, nparams)]"""
    try:
        src = open(path, encoding='utf-8', errors='ignore').read()
    except OSError:
        return []
    out = []
    for m in RE_JNI_DEF.finditer(src):
        sym = m.group(1)
        params = m.group(2)
        # 切参数（简单按逗号，JNI 参数里不会出现嵌套逗号）
        raw = [p.strip() for p in params.split(',') if p.strip()]
        # 前两个是 JNIEnv* / jobject|jclass
        if len(raw) < 2:
            continue
        ret_m = re.search(
            r'JNIEXPORT\s+([A-Za-z_][A-Za-z0-9_*\s]*?)\s+JNICALL\s+' + re.escape(sym),
            src)
        rj = c_type_to_jni_sig(ret_m.group(1)) if ret_m else None
        if rj is None:
            continue
        js = ''
        ok = True
        for p in raw[2:]:
            s = c_type_to_jni_sig(p)
            if s is None:
                ok = False
                break
            js += s
        if not ok:
            continue
        out.append((sym, rj, '(' + js + ')' + rj, len(raw)))
    return out


def load_compiled_methods(path):
    """解析 dex2c 的 compiled_methods.txt —— **签名的权威来源**。
    行格式：Lcom/a/B;->onCreate(Landroid/os/Bundle;)V
    返回 {(cls, method): signature}

    为什么必须用它而不是从 C 参数推导：C 侧参数全被转成 jobject，
    推导只能得到 Ljava/lang/Object;，与真实签名不符 → RegisterNatives
    必然失败。这个方法表由 dex2c 在转译时写出，是唯一准确的来源。"""
    out = {}
    try:
        fp = open(path, encoding='utf-8', errors='ignore')
    except OSError:
        return out
    with fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            # 兼容两种写法：`Lcom/a/B;->m(...)V`（dex2c 实际输出）
            # 与 `Lcom/a/B;m(...)V`（mark-native 的宽松解析）。
            m = re.match(r'^L([^;]+);-?>([^(]+)(\(.*\)\S+)$', line)
            if not m:
                continue
            out[(m.group(1), m.group(2))] = m.group(3)
    return out


def decode_jni_suffix(sym):
    """从 JNI 符号名的 `__` 后缀还原方法签名。
    Java_..._onCreate__Landroid_os_Bundle_2  →  (Landroid/os/Bundle;)V
    规则（JNI 规范）：`_` → `/`，`_1`→`_`，`_2`→`;`，`_3`→`[`，
    后缀里不含返回类型（返回类型由 C 侧 ret 推导）。

    只在无法从 compiled_methods.txt 取到唯一签名时使用。
    解不出来返回 None（调用方退回保守推导）。"""
    if '__' not in sym:
        return None
    tail = sym.split('__', 1)[1]
    if not tail:
        return None
    # 反转义（顺序重要：先 _1/_2/_3，再把单独 _ 变 /）
    out = []
    i = 0
    while i < len(tail):
        c = tail[i]
        if c == '_' and i + 1 < len(tail) and tail[i+1] in '123':
            out.append({'1': '_', '2': ';', '3': '['}[tail[i+1]])
            i += 2
        elif c == '_':
            out.append('/')
            i += 1
        elif c.isdigit():
            # 结尾的 _2 之类已处理；纯数字视为垃圾
            i += 1
        else:
            out.append(c)
            i += 1
    s = ''.join(out)
    # 去掉结尾的回车/空白；不做括号包裹（由调用方加，因为返回类型
    # 只能从 C 侧推导，不在符号名里）
    s = s.strip()
    if not s:
        return None
    return s


def sym_to_class_method(sym):
    """Java_com_nc_link_NcLink_ncVerify
       → ("com/nc/link/NcLink", "ncVerify")
       规则：从右往左，第一个「首字母大写」的段之前是包名。
       若带 __ 签名后缀（重载），去掉后缀。"""
    body = sym[len('Java_'):]
    # 去掉 __ 之后的重载后缀
    if '__' in body:
        body = body.split('__', 1)[0]
    parts = body.split('_')
    # 找最后一个「首字母大写」的段作为类名
    cls_idx = None
    for i in range(len(parts) - 1, 0, -1):
        if parts[i] and parts[i][0].isupper():
            cls_idx = i
            break
    if cls_idx is None:
        return None
    pkg = '/'.join(parts[:cls_idx])
    cls = parts[cls_idx]
    method = '_'.join(parts[cls_idx + 1:])
    if not pkg or not method:
        return None
    return pkg + '/' + cls, method


# 这些文件里的 JNI 入口由 nc_jni_register.c 【手工】注册（它们走
# NC_JNI_DYNAMIC_REG 的 visibility(hidden) 路径，不经 -D 改名）。
# 若再进生成表会重复注册 / 产生未定义符号 —— 实测踩过。
MANUAL_REGISTERED_FILES = {'nc_jni_register.c', 'nc_link.c', 'nc_guard_jni.c'}


def scan(jni_dir):
    """遍历 jni 目录下所有 .c/.cpp，收集 dex2c 产物的 JNI 定义。"""
    found = []
    for root, _dirs, files in os.walk(jni_dir):
        for fn in files:
            if not fn.endswith(('.c', '.cpp', '.cc')):
                continue
            # 跳过我们自己生成的文件，避免自引用
            if fn.startswith('nc_jni_gen'):
                continue
            # 跳过手工注册的（它们的实现函数名已是 nc_jni_xxx，
            # 由 nc_jni_register.c 直接取址注册）
            if fn in MANUAL_REGISTERED_FILES:
                continue
            found.extend(parse_defs(os.path.join(root, fn)))
    return found


def main(argv):
    if len(argv) not in (3, 4):
        print('用法: gen-jni-register.py <jni目录> <输出.c> [compiled_methods.txt]',
              file=sys.stderr)
        return 2
    jni_dir, out_c = argv[1], argv[2]
    cm_path = argv[3] if len(argv) == 4 else ''
    known = load_compiled_methods(cm_path) if cm_path else {}
    if known:
        print('   [jni-reg] 从 compiled_methods.txt 读到 %d 个方法签名（权威来源）'
              % len(known))

    defs = scan(jni_dir)
    if not defs:
        # 没有 dex2c 产物（例如只勾 sigcheck）：生成空表，链接期不报错
        with open(out_c, 'w', encoding='utf-8') as f:
            f.write('/* 无 dex2c JNI 定义，空表 */\n')
            f.write('void nc_jni_gen_register_placeholder(void) {}\n')
        print('   [jni-reg] 未发现 dex2c JNI 定义，生成空表')
        return 0

    # 按类分组
    by_class = {}
    skipped = []
    for sym, rj, sig, nparams in defs:
        cm = sym_to_class_method(sym)
        if cm is None:
            skipped.append(sym)
            continue
        cls, method = cm
        # 优先用 compiled_methods.txt 的权威签名。
        # ⚠️ 但符号名带 `__<短签名>` 后缀时（JNI 重载消歧，如
        #    Java_..._onCreate__Landroid_os_Bundle_2），说明同名方法有多个
        #    重载，而 compiled_methods 里每个 (cls,method) 只存一条 →
        #    直接用会把所有重载都写成同一个签名，RegisterNatives 必失败。
        #    这种情况下退回参数推导 + 后缀校验。
        has_overload_suffix = '__' in sym
        real = None if has_overload_suffix else known.get((cls, method))
        if real:
            sig = real
        elif has_overload_suffix:
            decoded = decode_jni_suffix(sym)
            if decoded:
                # 解码得到的是【参数列表】如 "Landroid/os/Bundle;"，
                # 需要包成 (…) + 返回类型。返回类型从 C 侧 ret 推导已得 rj。
                if not decoded.startswith('('):
                    decoded = '(' + decoded + ')'
                sig = decoded + rj
        elif known:
            # 有权威表但查不到此方法 —— 说明它不在 dex2c 转译清单里
            # （可能是 nc_link/nc_guard 手写的），保留推导值并提示
            print('   [jni-reg] ⚠️ %s.%s 不在 compiled_methods.txt，用推导签名 %s'
                  % (cls, method, sig), file=sys.stderr)
        by_class.setdefault(cls, []).append((sym, method, sig, nparams))

    lines = []
    lines.append('/* 由 gen-jni-register.py 自动生成 —— 不要手工编辑。')
    lines.append(' *')
    lines.append(' * 目的：把 dex2c 产物的 `Java_xxx` 符号从 .dynsym 摘掉。')
    lines.append(' * 那些符号带精确大小（`MainActivity.k` 21692 B 之类），等于把')
    lines.append(' * 业务复杂度地图免费送出。现在改成运行期注册，名字只在字符串表里。')
    lines.append(' *')
    lines.append(' * ⚠️ 本文件的 extern 声明依赖编译期 `-D<symbol>=ncg_d2c_<n>` 改名，')
    lines.append(' *    见 protect.sh 的 -DNCG_D2C_RENAME 段。不改名就仍是短名绑定，')
    lines.append(' *    version script 会把它们全隐藏 → Java 侧 UnsatisfiedLinkError。')
    lines.append(' */')
    lines.append('#include <jni.h>')
    lines.append('#include <string.h>')
    lines.append('')
    lines.append('/* 改名后的实现（编译期用 -D 宏把原名映射到这里） */')
    idx = 0
    rename_map = []
    for cls in sorted(by_class):
        for sym, method, sig, nparams in by_class[cls]:
            lines.append('extern void *ncg_d2c_%d(void);   /* %s */' % (idx, sym))
            rename_map.append((sym, idx))
            idx += 1
    lines.append('')

    idx = 0
    for cls in sorted(by_class):
        lines.append('static int nc_reg_%s(JNIEnv *env) {' % re.sub(r'[^A-Za-z0-9]', '_', cls))
        lines.append('    jclass c = (*env)->FindClass(env, "%s");' % cls)
        lines.append('    if (c == NULL) { (*env)->ExceptionClear(env); return 0; }')
        lines.append('    {')
        lines.append('        JNINativeMethod m[%d];' % len(by_class[cls]))
        for i, (sym, method, sig, nparams) in enumerate(by_class[cls]):
            lines.append('        m[%d].name = (char *)"%s";' % (i, method))
            lines.append('        m[%d].signature = (char *)"%s";' % (i, sig))
            lines.append('        m[%d].fnPtr = (void *)ncg_d2c_%d;' % (i, idx))
            idx += 1
        lines.append('        if ((*env)->RegisterNatives(env, c, m, %d) != 0) {'
                     % len(by_class[cls]))
        lines.append('            (*env)->ExceptionClear(env);')
        lines.append('            return 0;')
        lines.append('        }')
        lines.append('    }')
        lines.append('    return 1;')
        lines.append('}')
        lines.append('')

    lines.append('/* 由 JNI_OnLoad 调用。返回注册成功的类数。 */')
    lines.append('int nc_jni_gen_register(JNIEnv *env) {')
    lines.append('    int ok = 0;')
    for cls in sorted(by_class):
        lines.append('    ok += nc_reg_%s(env);' % re.sub(r'[^A-Za-z0-9]', '_', cls))
    lines.append('    return ok;')
    lines.append('}')

    with open(out_c, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    # 改名宏单独输出，供 protect.sh 拼进 CFLAGS
    print('   [jni-reg] 生成 %d 个类的注册表（共 %d 个方法）'
          % (len(by_class), sum(len(v) for v in by_class.values())))
    if skipped:
        print('   [jni-reg] ⚠️ 跳过 %d 个无法解析签名的符号：%s'
              % (len(skipped), ', '.join(skipped[:3])), file=sys.stderr)
    for sym, i in rename_map:
        print('D2C_RENAME:-D%s=ncg_d2c_%d' % (sym, i))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
