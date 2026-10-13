#!/usr/bin/env python3
"""A/B 对比两份 atrace：提取启动窗口内关键指标。

用法: python3 ab.py <packed.txt> <official.txt> <包名>
"""
import re, sys, collections

LINE = re.compile(
    r"^\s*(?P<task>\S+?)-(?P<pid>\d+)\s+\(\s*(?P<tgid>[\d-]+)\)\s+\[(?P<cpu>\d+)\]\s+"
    r"(?P<flags>\S+)\s+(?P<ts>\d+\.\d+):\s+(?P<ev>[^:]+):\s*(?P<rest>.*)$"
)

def scan(path, target):
    main_pid = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            if target in line and "Open oat file" in line:
                m = LINE.match(line)
                if m:
                    main_pid = int(m.group("pid")); break
    if main_pid is None:
        print(f"{path}: 未定位主 pid"); return None

    r = {"main_pid": main_pid}
    t_open_oat = t_activity = t_perform = None
    verify = 0
    define = 0
    define_class = []
    verify_class = []
    gc_pause = collections.Counter()
    gc_total = 0.0
    jit = 0
    lock = 0
    dex_open = []
    verify_dex = []
    t_start = t_end = None
    marks = 0
    binder_tx = 0
    names = collections.Counter()
    oat_paths = set()

    with open(path, "r", errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            task, pid = m.group("task"), int(m.group("pid"))
            ts, ev, rest = float(m.group("ts")), m.group("ev").strip(), m.group("rest")
            if t_start is None: t_start = ts
            t_end = ts
            if ev == "binder_transaction" and pid == main_pid:
                binder_tx += 1
            if pid != main_pid:
                continue
            if ev == "tracing_mark_write":
                mm = re.match(r"([BEC])\|(\d+)\|(.*)", rest)
                if not mm: continue
                marks += 1
                txt = mm.group(3)
                if "Open oat file" in txt and t_open_oat is None:
                    t_open_oat = ts
                    oat_paths.add(txt.split(" ", 3)[-1])
                elif "Open dex file" in txt:
                    dex_open.append((ts, txt.split(" ", 3)[-1]))
                elif "Verify dex file" in txt:
                    verify_dex.append((ts, txt.split(" ", 3)[-1]))
                elif txt.startswith("VerifyClass "):
                    verify += 1
                    if t_activity is None or ts <= t_activity + 2.0:
                        verify_class.append((ts, txt[12:]))
                elif txt.startswith("DefineClass_L"):
                    define += 1
                    define_class.append((ts, txt[14:]))
                elif txt == "activityStart":
                    t_activity = ts
                elif txt.startswith("performStart:"):
                    t_perform = ts
                elif "Lock contention" in txt:
                    lock += 1
                elif "JitMemoryRegion" in txt or "jit" in txt.lower():
                    jit += 1
                elif "GC" in txt or txt.startswith("Heap size") or "garbage" in txt.lower():
                    gc_total += 1
                    gc_pause[txt[:60]] += 1

    r.update(dict(span=t_end - t_start, t_open_oat=t_open_oat, t_activity=t_activity,
                  t_perform=t_perform, verify=verify, define=define, jit=jit, lock=lock,
                  marks=marks, binder_tx=binder_tx, dex_open=dex_open, verify_dex=verify_dex,
                  define_class=define_class, verify_class=verify_class,
                  gc_total=gc_total, gc_pause=gc_pause, oat_paths=oat_paths,
                  t_start=t_start))
    return r

def window(a, b, name_a, name_b):
    print(f"# A/B 对比：{name_a} vs {name_b}\n")
    print("| 指标 | A(packed) | B(official) |")
    print("|---|---|---|")
    def row(label, x, y):
        print(f"| {label} | {x} | {y} |")
    row("主线程 pid", a["main_pid"], b["main_pid"])
    row("trace 跨度(s)", f"{a['span']:.3f}", f"{b['span']:.3f}")
    row("oat 打开时刻", f"{a['t_open_oat']:.3f}", f"{b['t_open_oat']:.3f}")
    row("activityStart 时刻", f"{a['t_activity']:.3f}", f"{b['t_activity']:.3f}")
    row("performStart 时刻", f"{a['t_perform']:.3f}", f"{b['t_perform']:.3f}")
    row("activityStart-oat(s)", f"{a['t_activity']-a['t_open_oat']:.3f}", f"{b['t_activity']-b['t_open_oat']:.3f}")
    row("performStart-oat(s)", f"{a['t_perform']-a['t_open_oat']:.3f}", f"{b['t_perform']-b['t_open_oat']:.3f}")
    row("VerifyClass 总数", a["verify"], b["verify"])
    row("DefineClass 总数", a["define"], b["define"])
    row("mark 总数", a["marks"], b["marks"])
    row("Lock contention", a["lock"], b["lock"])
    row("主线程 binder 事务", a["binder_tx"], b["binder_tx"])

    # 窗口内（oat → performStart+0.5）的类加载
    def win(r, lo, hi):
        return [c for c in r["define_class"] if lo <= c[0] <= hi]
    for label, r in ((name_a, a), (name_b, b)):
        lo = r["t_open_oat"]; hi = r["t_perform"] + 0.5
        dc = win(r, lo, hi)
        vc = [c for c in r["verify_class"] if lo <= c[0] <= hi]
        print(f"\n## {label} 启动窗口 [{lo:.3f}, {hi:.3f}]")
        print(f"- DefineClass {len(dc)} 条，VerifyClass {len(vc)} 条")
        # 每秒类加载密度
        buckets = collections.Counter(int(c[0] - lo) for c in dc)
        print("- 每秒 DefineClass 密度：", dict(sorted(buckets.items())))

    print("\n## dex 打开序列")
    for label, r in ((name_a, a), (name_b, b)):
        print(f"- {label}:")
        for ts, p in r["dex_open"]:
            print(f"    {ts:.3f} {p[:110]}")
        for ts, p in r["verify_dex"]:
            print(f"    [verify] {ts:.3f} {p[:110]}")

if __name__ == "__main__":
    a = scan(sys.argv[1], sys.argv[3])
    b = scan(sys.argv[2], sys.argv[3])
    if a and b:
        window(a, b, sys.argv[1].split("/")[-1], sys.argv[2].split("/")[-1])
