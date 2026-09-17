#!/usr/bin/env bash
# test-smali-params.sh — lib-smali-params 最小回归测试(无需 apktool/java)
# 钉死:① count_param_slots 全形态(基本/引用/数组/wide/嵌套数组/static/this)
#       ② 解析失败返回 None(宁缺勿滥契约)
#       ③ max_param_index 忽略指令外行、负向断言不误吞 pN
#       ④ 单一真相:anti-diff 的 _count_param_slots/_max_param_index 与 lib 同源
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
python3 - "$ROOT" <<'EOF'
import os, sys
root = sys.argv[1]

import importlib.util
def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(root, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

lib = load('lib_smali_params', 'scripts/lib/lib-smali-params.py')
cps, mpi = lib.count_param_slots, lib.max_param_index

fails = []
def eq(got, want, case):
    if got != want:
        fails.append(f"case {case}: got {got!r}, want {want!r}")

# ── ① count_param_slots 全形态 ──────────────────────────────────
sig = '.method public static foo(IJ[[Ljava/lang/String;Z)V'
eq(cps(sig), 0+1+2+1+1, 'static: I J [[Ljava/lang/String; Z = 5')
eq(cps('.method private foo(IJ)V'), 4, '非 static: this(1) + I(1) + J(2) = 4')
eq(cps('.method public foo(J[D)V'), 4, '非 static: this + J(2) + [D = 4')
eq(cps('.method public foo(Lcom/x/A;[I[[[B)V'), 4, '非 static: this + L + [I + [[[B = 4')
eq(cps('.method public static bar(JJD)V'), 6, 'static: J J D = 6')
eq(cps('.method public static bar()V'), 0, 'static 无参 = 0')
eq(cps('.method public bar()V'), 1, '非 static 无参 = this')
eq(cps('.method public static bar([[J)V'), 1, '[[J = 1 槽')
# 报错三十四回归钉子:静态 13 槽含 wide —— 红线 7 允许提升条件 4+13-1=16 > 15 → 拒绝
eq(cps('.method public static copy$default(Lcom/x/TaskEntity;ILjava/lang/String;JZILjava/lang/Object;)Ljava/lang/Object;'),
   8, 'copy$default 混合 wide 形态 = 8')

# ── ② 解析失败 = None(宁缺勿滥) ────────────────────────────────
for bad in ('.method public foo(IUnparseable)V',      # 未知类型符
            '.method public foo(Lcom/x)V',            # 引用缺分号
            '.method public foo([)V',                 # 数组后无类型
            '.method public foo(V)V'):                # V 不入参(非法形态)
    eq(cps(bad), None, f'bad sig → None: {bad}')
eq(cps('.method public foo)V'), None, '无参数括号 → None')

# ── ③ max_param_index ───────────────────────────────────────────
eq(mpi(['    and-int/lit16 p12, p12, 0xff', '.locals 0']), 12, '指令内最大 pN')
eq(mpi(['.locals 4', '# 注释 p99', '.field x:I', '', '.source "A.java"']), -1,
   '注释/field/source 行不计')
# 已知保守边界(与 anti-diff 原实现一致,非回归):字符串字面量内的 pN 会计入。
# 该函数只用作"最大 pN 兜底上界"(宁误判勿漏判方向),多算 = 更严,可接受;
# 钉死此行为,防止未来有人"顺手修"成更激进的正则(报错七教训反向适用)。
eq(mpi(['const-string p1, "xxx p2 yyy"']), 2, '字面量内 pN 计入(既有保守行为,钉死)')
eq(mpi(['invoke-virtual {p0, p1}, Lcom/demo/A$B;->m(I)V']), 1, '类名 $B 不干扰')
eq(mpi([]), -1, '空方法体')

# ── ④ 单一真相:anti-diff 的 _count_param_slots/_max_param_index 与 lib 同源 ──
# 注:anti-diff 经各自的 importlib 加载,模块对象不同,函数对象不 is 相等;
# 单一真相改验"源码身份":__module__ 指向 lib 模块名 + 行为逐例一致。
ad = load('anti_diff_libcheck', 'scripts/anti-diff/anti-diff.py')
assert ad.count_param_slots.__module__ == 'lib_smali_params', \
    'anti-diff.count_param_slots 必须来自 lib-smali-params(单一真相)'
assert ad.max_param_index.__module__ == 'lib_smali_params', \
    'anti-diff.max_param_index 必须来自 lib-smali-params(单一真相)'
assert ad._count_param_slots('.method public static foo(IJ)V') == cps('.method public static foo(IJ)V'), '别名行为等价'
assert ad._max_param_index(['p3']) == mpi(['p3']), '别名行为等价'

if fails:
    print('FAIL:', *fails, sep='\n  ')
    sys.exit(1)
print('test-smali-params: all green (%d assertions, incl. 8 sig forms + 5 reject forms + singleton-truth)' % (
    8 + 5 + 6 + 4))
EOF
