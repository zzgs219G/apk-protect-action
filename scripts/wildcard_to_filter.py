#!/usr/bin/env python3
"""wildcard_to_filter.py — 把「一行一个类」的通配符规则转成 dcc filter 文件

输入(每行一个规则,支持 ! 开头排除,空行和 # 注释跳过):
  通配符语义(沿用用户提供的规则,按实际实现):
    **  匹配任意长度字符,包括包名分隔符(.)
    *   匹配任意长度字符,但不含包名分隔符(.)
    activity*  特殊关键字:匹配 APK 中所有 Activity 子类(需要 VM 类列表)
  其余字符按字面匹配。

示例:
  com.test.**          → com.test 包下所有类(含子包)
  com.test.*           → com.test 包下所有类(不含子包)
  com.test**           → 等价 com.test.**
  com.test*            → com 下 test 开头的所有类
  activity*            → 所有 Activity 子类
  !com.test.libs.**    → 排除 com.test.libs 包(排除行原样转为 dcc 的 ! 规则)

输出: dcc filter 格式,每行一条正则。类名规则会被转换为
  L<类名>.*  (匹配该类下的所有方法)
特殊关键字 activity* 需要 --classes 参数(由 gen_filter_from_apk.py 或
dcc 解析 dex 得到的类列表文件),逐个匹配后展开为具体类。

用法:
  wildcard_to_filter.py <规则文件> <输出filter> [--classes 类列表文件]
"""
import re
import sys


def wildcard_to_regex(pattern: str) -> str:
    """把类名通配符转成正则(匹配 dcc full_name: L类名;方法名(原型))。
    类名部分没有通配符时,精确锚定;有通配符时,通配符只作用于类名段。"""
    # ** → 任意字符(含 .)   * → 非 . 的任意字符
    out = []
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == '*':
            if i + 1 < len(pattern) and pattern[i + 1] == '*':
                out.append('.*')
                i += 2
                continue
            out.append('[^.]*')
            i += 1
            continue
        out.append(re.escape(ch))
        i += 1
    return ''.join(out)


def class_rule_to_filter(rule: str, has_wildcard: bool) -> str:
    """把一行类名规则转成 dcc filter 行。
    dcc full_name 的类名是【smali 斜杠格式】Lcom/demo/app/Main;onCreate(...),
    而用户输入/Manifest 是点号格式 → 统一在此转换: 点号 → 斜杠。
    所以类名规则 R → L R ;.*  (L 前缀锚定,分号后任意方法)

    关键语义(按用户定义):
      com.test*  匹配 com 下 test 开头的所有类(可带子包) → test 段允许
                 后面跟 .子包.路径,即 (test[^.]*)(\\..+)?; """
    core = wildcard_to_regex(rule)
    # 点号(包名分隔符)转斜杠(smali 格式)。注意 \. 已由 re.escape 产出,
    # 只需替换字面 \. → /
    core = core.replace('\\.', '/')
    # 无通配符:精确类名,分号后任意方法
    if not has_wildcard:
        return 'L' + core + ';.*'
    # 有通配符:core 是类名部分的正则。
    # 若规则以 * 结尾且该 * 转成了 [^.]*,需要允许其后再跟 /子包 路径
    if rule.endswith('*') and not rule.endswith('**'):
        # com.test* → Lcom/(test[^.]*)(/.+)?;.* 形式:
        # 把最后一段 [^.]* 拆出来,加可选的 (/..+)? 子包后缀
        if core.endswith('[^.]*'):
            head = core[:-len('[^.]*')]
            return 'L' + head + '[^.]*(/.+)?;.*'
        return 'L' + core + ';.*'
    # com.test** / com.test.** 等双星:直接类名段后跟 ;.*
    return 'L' + core + '[;].*' if not core.endswith('.*') else 'L' + core + ';.*'


def has_wildcard(rule: str) -> bool:
    return '*' in rule


def expand_activity_keyword(classes_file: str) -> list:
    """从类列表文件展开 activity* 规则。
    类列表文件: 每行一个类(两种格式都兼容):
      1. gen_filter_from_apk.py 生成: com.demo.app.MainActivity # activity
      2. smali 风格: Lcom/demo/MainActivity;
    返回统一为 smali 风格 L...; (供 class_rule_to_filter 剥壳使用)。"""
    result = []

    def to_smali(name: str) -> str:
        return name if name.startswith('L') else 'L' + name + ';'

    with open(classes_file) as fp:
        for line in fp:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            cls = line
            is_activity = line.endswith('# activity')
            if is_activity:
                cls = line.rsplit('#', 1)[0].strip()
            elif cls.endswith('Activity;'):
                is_activity = True
            if is_activity:
                result.append(to_smali(cls))
    return result


def main() -> int:
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    classes_file = None
    argv = sys.argv[1:]
    for i, a in enumerate(argv):
        if a == '--classes' and i + 1 < len(argv):
            classes_file = argv[i + 1]

    if len(args) < 2:
        print(__doc__, file=sys.stderr)
        return 1
    rules_path, out_path = args[0], args[1]

    lines_out = []
    # 通用排除:构造器/类初始化器永远不转译
    lines_out.append('!<clinit|init>')

    with open(rules_path) as fp:
        raw_rules = [l.strip() for l in fp]

    activity_mode = False
    for rule in raw_rules:
        if not rule or rule.startswith('#'):
            continue
        exclude = rule.startswith('!')
        body = rule[1:] if exclude else rule

        if body == 'activity*':
            activity_mode = True
            if not classes_file:
                print('❌ activity* 需要 --classes 类列表文件', file=sys.stderr)
                return 1
            for cls in expand_activity_keyword(classes_file):
                pat = class_rule_to_filter(cls[1:-1], has_wildcard=False)
                lines_out.append(('!' if exclude else '') + pat)
            continue

        prefix = '!' if exclude else ''
        lines_out.append(prefix + class_rule_to_filter(body, has_wildcard(body)))

    if activity_mode:
        print('ℹ️ activity* 关键字已展开(注意:非标准命名的 Activity 需 gen_filter_from_apk.py 提供类列表)', file=sys.stderr)

    with open(out_path, 'w') as fp:
        fp.write('\n'.join(lines_out) + '\n')
    print(f'✅ 已生成 dcc filter: {out_path}({len(lines_out)} 条规则)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
