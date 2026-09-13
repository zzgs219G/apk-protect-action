#!/usr/bin/env python3
"""make-filter-from-apk.py — 从 APK 的 AndroidManifest.xml 动态解析 LAUNCHER
activity,生成 dcc filter 文件(联合方案的"自动获取类名"环节)。

原理:
  1. 用 androguard 解析 Manifest,取带 MAIN+LAUNCHER intent-filter 的 activity
     (复用 dcc 内置 androguard,不引入新依赖);相对类名 .Foo / Foo 自动补全包名。
  2. 找不到唯一 LAUNCHER activity 时,按失败策略处理(--on-fail)。
  3. 输出 dcc filter(一行一个类),供 dcc.py --filter 使用。
  4. 顺带产出所有 Activity 类列表(供 activity* 通配符展开,--emit-classes)。

用法:
  make-filter-from-apk.py <apk> <输出filter> [--classes 类列表输出文件]
                         [--on-fail error|skip] [--all-activities]
"""
import os
import sys

# 本脚本位于 scripts/filter/,dcc 从 tools/dcc.zip 分发 → 解压产物在
# <仓库根>/tools/dcc(单层;缺失时从 zip 幂等解压)
# (更早教训 0f80c69: 移动脚本后基于 __file__ 的相对路径必须重算,
#  否则云端 ModuleNotFoundError: androguard)
DCC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                       '..', '..', 'tools', 'dcc')


def _ensure_dcc_dir():
    """dcc 摊开目录不存在时,从 tools/dcc.zip 解压(幂等)。返回绝对路径。"""
    dcc_dir = os.path.abspath(DCC_DIR)
    if not os.path.isfile(os.path.join(dcc_dir, 'dcc.py')):
        dcc_zip = os.path.normpath(os.path.join(dcc_dir, '..', 'dcc.zip'))
        if not os.path.isfile(dcc_zip):
            raise FileNotFoundError(f'dcc 分发包缺失: {dcc_zip}')
        import zipfile
        os.makedirs(os.path.dirname(dcc_dir), exist_ok=True)
        with zipfile.ZipFile(dcc_zip) as zf:
            zf.extractall(os.path.dirname(dcc_dir))
        if not os.path.isfile(os.path.join(dcc_dir, 'dcc.py')):
            raise FileNotFoundError(f'dcc.zip 解压后缺 dcc.py: {dcc_dir}')
    return dcc_dir


def load_apk(apk_path):
    dcc_dir = _ensure_dcc_dir()
    sys.path.insert(0, dcc_dir)
    from androguard.core.bytecodes.apk import APK
    return APK(apk_path)


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print(__doc__, file=sys.stderr)
        return 1
    apk_path = args[0]
    out_path = args[1] if len(args) > 1 else 'dcc_filter.auto.txt'

    on_fail = 'error'
    all_activities = False
    classes_out = None
    argv = args[2:] if len(args) > 2 else []
    i = 0
    while i < len(argv):
        if argv[i] == '--on-fail' and i + 1 < len(argv):
            on_fail = argv[i + 1]
            i += 2
        elif argv[i] == '--all-activities':
            all_activities = True
            i += 1
        elif argv[i] == '--classes' and i + 1 < len(argv):
            classes_out = argv[i + 1]
            i += 2
        else:
            i += 1

    if not os.path.exists(apk_path):
        print(f'❌ APK 不存在: {apk_path}', file=sys.stderr)
        return 1

    a = load_apk(apk_path)
    main_acts = set()
    try:
        main_acts = set(a.get_main_activities() or [])
    except Exception as e:
        print(f'⚠️ Manifest 解析异常: {e}', file=sys.stderr)

    package = a.get_package()
    # 补全相对类名(.Foo / Foo → 完整类名)
    def full_name(name: str) -> str:
        if name.startswith('.'):
            return package + name
        if '.' not in name:
            return package + '.' + name
        return name

    mains = sorted(full_name(x) for x in main_acts)

    if not mains:
        if on_fail == 'skip':
            print('⚠️ 未找到 LAUNCHER activity,跳过(--on-fail=skip)', file=sys.stderr)
            return 0
        print('❌ 未从 Manifest 解析到唯一 LAUNCHER activity;'
              '请在任务中手动指定类名(一行一个,支持通配符)', file=sys.stderr)
        return 2

    if len(mains) > 1:
        print(f'ℹ️ 检测到 {len(mains)} 个 LAUNCHER activity,全部纳入: {mains}',
              file=sys.stderr)

    # 产出 Activity 类列表(供 activity* 展开)
    if classes_out:
        try:
            acts = sorted(set(a.get_activities() or []))
            with open(classes_out, 'w') as fp:
                fp.write('# activity 类列表(由 Manifest 提取)\n')
                for act in acts:
                    fp.write(full_name(act) + ' # activity\n')
        except Exception as e:
            print(f'⚠️ Activity 类列表提取失败: {e}', file=sys.stderr)

    # 生成 filter:每行一个类
    # ⚠️ dcc full_name 的类名是 smali 斜杠格式(Lcom/demo/app/Main;),
    #    而 Manifest 是点号 → 转换后再写入
    lines = ['!<clinit|init>']
    if all_activities and classes_out and os.path.exists(classes_out):
        # 展开所有 Activity 为具体类规则
        with open(classes_out) as fp:
            for line in fp:
                line = line.strip()
                if line and not line.startswith('#'):
                    cls = line.split('#')[0].strip().rstrip(';')
                    lines.append('L' + cls.replace('.', '/') + ';.*')
    else:
        for m in mains:
            lines.append('L' + m.replace('.', '/') + ';.*')

    with open(out_path, 'w') as fp:
        fp.write('\n'.join(lines) + '\n')

    print(f'✅ 主 Activity: {", ".join(mains)}')
    print(f'✅ 已生成 dcc filter: {out_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
