#!/usr/bin/env python3
"""normdiff.py — MT 管理器式归一化对比工具(anti-diff 验证专用,只读)

【为什么存在】
验证 anti-diff 效果的标准做法:把处理前后两个 APK(或裸 dex → 反编译成
smali)逐方法对比,只看**语义层**差异。MT 管理器自带的 dex 对比支持四项
忽略(编译优化/寄存器数量/调试信息/nop),但每次让 AI 手写一遍过滤脚本
再测试太费 token 和时间,故固化于此。

【模拟 MT 的忽略项】
  * 忽略标签名       —— :label_0/:goto_1 等按出现顺序重新编号(变换 A
                        标签重命名在 dex 层是零痕迹的,忽略后才公平)
  * 忽略调试信息     —— .line/.param/.local/.end local/.restart/
                        .prologue/.epilogue 与全部注释行
  * 忽略寄存器数量   —— .registers/.locals 声明行本身不计入对比
  * 字符串字面量保护 —— 引号内的 ":xxx"(jsoup 选择器等)不当标签处理

【保留的差异(即真实语义差异)】
  全部真实指令及其寄存器操作数。若归一化后两方法仍有 diff,说明存在
  变换 A/B/C/E 之外的指令级变化——要么是变换落 dex 的预期产物
  (const/4、goto、if 反转),要么就是 bug(如报错三十二的 move v,v)。

【用法】
  normdiff.py <处理前.smali> <处理后.smali>
  (两个文件各自行数可以不同;按方法签名对齐,签名来自 .method 行)

  配套 dex 层实证(androguard 读回,验证"新增指令分类"):
  python3 - <<'EOF'
  import sys, re
  sys.path.insert(0, '<仓库根>/tools/dcc')
  from androguard.core.bytecodes.dvm import DalvikVMFormat as DEX
  ...  # 按 (name, descriptor) 对齐方法,双指针扫描找新增指令,按 opcode 分类
  EOF

【已知局限】
  * 标签按"出现顺序"重新编号而非按支配关系,因此"仅在标签重命名场景
    下目标偏移相同"的分支可能被错位报告(典型症状:if/goto 成对出现
    于 diff 中但目标编号连续一致)——人工复核时看指令寄存器操作数即可。
  * 归一化只到 smali 文本层;"汇编通过但 verifier 拒绝"类 bug(报错
    二十二/二十四/三十二)必须辅以 dex 层读回 + 数据流检查,本工具的
    输出只能证明"有差异",不能证明"差异合法"。

【验证记录】
  2026-09-17 报错三十二:用本工具 + dex 层 diff 定位处理版 13 处
  `move vN, vN` 读未初始化寄存器(见 docs/变更历史.md)。
"""
import difflib
import re
import sys

METHOD_RE = re.compile(r'^\.method')
END_RE = re.compile(r'^\.end method')
LABEL_DEF = re.compile(r'^\s*(:[\w.$-]+)\s*$')
LABEL_REF = re.compile(r'(?<![\w$-])(:[\w.$-]+)\b')
LINE_NOISE = re.compile(
    r'^\s*\.(line|param|prologue|epilogue|local|local[0-9]|restart|registers|locals)\b')
END_LOCAL = re.compile(r'^\s*\.end local\b')
STR_SPAN = re.compile(r'"(?:[^"\\]|\\.)*"')


def norm_method(lines):
    """方法体归一化:去噪声行、标签按出现顺序重编号、保护字符串字面量。"""
    out = []
    labmap = {}
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith('#') or LINE_NOISE.match(s) or END_LOCAL.match(s):
            continue
        if LABEL_DEF.match(ln):
            lab = LABEL_DEF.match(ln).group(1)
            labmap.setdefault(lab, f':L{len(labmap)}')
            continue
        strs = []

        def mask(mm):
            strs.append(mm.group(0))
            return f'\x00{len(strs) - 1}\x00'
        masked = STR_SPAN.sub(mask, s)

        def sub(mm):
            t = mm.group(1)
            labmap.setdefault(t, f':L{len(labmap)}')
            return labmap[t]
        masked = LABEL_REF.sub(sub, masked)
        masked = re.sub(r'\x00(\d+)\x00',
                        lambda mm: strs[int(mm.group(1))], masked)
        out.append(masked)
    return out


def parse(path):
    """解析 smali 文件 → {方法签名行: 归一化指令列表}。"""
    methods = {}
    cur, buf = None, []
    with open(path, encoding='utf-8') as f:
        for ln in f:
            if METHOD_RE.match(ln):
                cur = ln.strip()
                buf = []
            elif END_RE.match(ln):
                methods[cur] = norm_method(buf)
                cur = None
            elif cur is not None:
                buf.append(ln)
    return methods


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    a, b = parse(argv[1]), parse(argv[2])
    for n in a:
        if n not in b:
            print(f'!!! 仅在 {argv[1]}: {n}')
    for n in b:
        if n not in a:
            print(f'!!! 仅在 {argv[2]}: {n}')
    total = same = 0
    for n in a:
        if n not in b:
            continue
        d = list(difflib.unified_diff(a[n], b[n], lineterm='', n=1))
        if not d:
            same += 1
            continue
        total += 1
        nd = sum(1 for x in d if x.startswith(('+', '-'))
                 and not x.startswith(('+++', '---')))
        print(f'\n===== {n}  (差异行 {nd}) =====')
        for x in d:
            print(x)
    print(f'\n有指令差异的方法数: {total}/{total + same}'
          f'(归一化后仍相同: {same})')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
