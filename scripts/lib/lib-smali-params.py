#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lib-smali-params.py — smali 方法参数槽计数的单一真相(报错七)。

提供两个纯函数,供 anti-diff 与 light-obf 共用(严禁各抄一份——
报错七:同一逻辑在两处各写一份,迟早被改得分叉):

  count_param_slots(method_sig)   解析 .method 行签名,返回参数寄存器槽总数
  max_param_index(method_lines)   方法体指令中实际引用的最大 pN 序号

本文件只依赖 re/标准库,不得 import 仓库内其他模块;两处消费者
(scripts/anti-diff/anti-diff.py, 未来的 scripts/light-obf/light-obf.py)
经 importlib 按路径加载本文件后使用(同 anti-diff 复用 inject-loadlib
`SMALI_DIR_RE` 的 _load_module 先例)。

红线 7(允许提升的条件:4 + 槽总数 - 1 ≤ 15)与红线 8(宽对完整性,
报错三十二)的实现基础。count_param_slots 原文迁移自 anti-diff.py
(报错三十四的修复,见 docs/变更历史.md),逐字符扫描逻辑零改动。
"""

import re

__all__ = ['count_param_slots', 'max_param_index']


def count_param_slots(method_sig):
    """解析 .method 行的参数列表,返回参数寄存器槽总数。

    报错三十四根基:提升 .locals 后参数物理号 pN = v(N' + 槽偏移),wide
    参数(J/D)占 2 个槽——不能按参数"个数"数,必须按槽。签名逐字符扫描:
    基本类型/引用类型 1 槽,J/D 2 槽数,数组 [X 按元素类型(引用数组仍
    1 槽);非 static 方法 this 再占 1 槽。
    解析失败(签名形态异常)返回 None,调用方按"不可提升"处理(宁缺勿滥)。"""
    m = re.search(r'\(([^)]*)\)', method_sig)
    if not m:
        return None
    is_static = bool(re.search(r'\bstatic\b', method_sig))
    args = m.group(1)
    slots = 0 if is_static else 1  # 非 static:p0 = this
    i = 0
    n = len(args)
    while i < n:
        c = args[i]
        if c in 'JD':
            slots += 2
            i += 1
        elif c in 'BCFISZ':
            slots += 1
            i += 1
        elif c == 'L':
            j = args.find(';', i)
            if j < 0:
                return None
            slots += 1
            i = j + 1
        elif c == '[':
            # 数组:引用数组 1 槽;跳过所有 '[' 后按一个类型算
            j = i
            while j < n and args[j] == '[':
                j += 1
            if j >= n:
                return None
            if args[j] == 'L':
                j = args.find(';', j)
                if j < 0:
                    return None
            slots += 1
            i = j + 1
        else:
            return None
    return slots


def max_param_index(method_lines):
    """方法体指令中实际引用的最大 pN 序号(兜底校验用);无引用返回 -1。"""
    mx = -1
    for ln in method_lines:
        s = ln.strip()
        if s.startswith('.') or s.startswith('#') or not s:
            continue
        for m in re.finditer(r'(?<![\w.$-])p(\d+)(?![\w.$-])', ln):
            mx = max(mx, int(m.group(1)))
    return mx
