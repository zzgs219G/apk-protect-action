#!/usr/bin/env python3
"""解析 atrace 文本，输出目标进程启动阶段归因报告。

用法: python3 report.py <trace.txt> <包名>
要点：
- tracing_mark_write 的 B/E 由任意线程发出，但都带同一个 pid；配对时忽略发出线程。
- 主线程 pid 由 "Open oat file" 事件定位。
"""
import re, sys, collections

LINE = re.compile(
    r"^\s*(?P<task>\S+?)-(?P<pid>\d+)\s+\(\s*(?P<tgid>[\d-]+)\)\s+\[(?P<cpu>\d+)\]\s+"
    r"(?P<flags>\S+)\s+(?P<ts>\d+\.\d+):\s+(?P<ev>[^:]+):\s*(?P<rest>.*)$"
)

def main(path, target):
    # 第一遍：定位主 pid
    main_pid = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            if target in line and "Open oat file" in line:
                m = LINE.match(line)
                if m:
                    main_pid = int(m.group("pid")); break
    if main_pid is None:
        print("未定位主 pid"); return

    run = collections.Counter()        # pid -> running s
    tid_name = {}
    sched_switch = {}
    offs = []                          # 主线程被切走 (ts, prev_comm, dur)
    marks = []                         # 主线程所有 mark
    tmin = tmax = None
    # 需要第二遍算 run，先缓存主线程的 sched_switch
    main_switch = []

    with open(path, "r", errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            task, pid = m.group("task"), int(m.group("pid"))
            cpu, ts, ev, rest = m.group("cpu"), float(m.group("ts")), m.group("ev").strip(), m.group("rest")
            if tmin is None: tmin = ts
            tmax = ts
            tid_name.setdefault(pid, task)

            if ev == "sched_switch":
                pm = re.match(r"prev_comm=(\S+) prev_pid=(\d+) .*?next_comm=(\S+) next_pid=(\d+)", rest)
                if not pm: continue
                pcomm, ppid, ncomm, npid = pm.group(1), int(pm.group(2)), pm.group(3), int(pm.group(4))
                main_switch.append((cpu, ts, pcomm, ppid, ncomm, npid))
            elif ev == "tracing_mark_write" and pid == main_pid:
                mm = re.match(r"([BEC])\|(\d+)\|(.*)", rest)
                if mm:
                    marks.append((ts, mm.group(1), mm.group(3)))

    # 算 running：按 cpu 顺序配对
    by_cpu = collections.defaultdict(list)
    for cpu, ts, pcomm, ppid, ncomm, npid in main_switch:
        by_cpu[cpu].append((ts, pcomm, ppid))
    for cpu, lst in by_cpu.items():
        for i in range(len(lst) - 1):
            ts0, pcomm, ppid = lst[i]
            ts1 = lst[i + 1][0]
            d = ts1 - ts0
            if 0 <= d < 60:
                run[ppid] += d
                if ppid == main_pid:
                    offs.append((ts0, pcomm, d))
    # 主线程最后一次运行到 trace 尾
    for cpu, lst in by_cpu.items():
        if lst and lst[-1][2] == main_pid and tmax:
            d = tmax - lst[-1][0]
            if 0 <= d < 60:
                run[main_pid] += d
                offs.append((lst[-1][0], "RUN-TO-END", d))

    span = (tmax - tmin) if tmin and tmax else 0
    print(f"# {path}  包={target}")
    print(f"# 主 pid={main_pid}  跨度={span:.3f}s  主线程 Running={run[main_pid]:.3f}s  被切走 {len(offs)} 次")
    print(f"# mark 总数={len(marks)}")

    # 段耗时：忽略线程的栈式配对
    stack = []
    segs = collections.Counter()
    segn = collections.Counter()
    for ts, kind, txt in marks:
        if kind == "B":
            stack.append((ts, txt))
        elif kind == "E" and stack:
            s0, name = stack.pop()
            d = ts - s0
            if 0 <= d < 30:
                segs[name[:70]] += d
                segn[name[:70]] += 1
    print("\n## 主线程段耗时 Top35")
    print("| 耗时(ms) | 次数 | 段名 |")
    print("|---|---|---|")
    for name, d in segs.most_common(35):
        print(f"| {d*1000:9.1f} | {segn[name]} | {name} |")

    print("\n## 主线程 Running 之外的线程 Top15")
    print("| pid | 线程 | Running(s) |")
    print("|---|---|---|")
    for pid, d in run.most_common(15):
        print(f"| {pid} | {tid_name.get(pid,'?')} | {d:.3f} |")

    print("\n## 主线程被切走去向 Top15")
    top = collections.Counter()
    tot = collections.Counter()
    for ts, c, d in offs:
        top[c] += 1
        tot[c] += d
    print("| 被谁抢占 | 次数 | 累计(s) |")
    print("|---|---|---|")
    for c, n in top.most_common(15):
        print(f"| {c} | {n} | {tot[c]:.3f} |")

    # 关键事件
    print("\n## 关键事件")
    keys = ("Open oat file", "Open dex file", "Verify dex file", "VerifyClass",
            "DefineClass_L", "JitMemoryRegion", "activityStart", "performStart",
            "Lock contention", "code_cache", "xixin", "libxixin", "libnc")
    hits = collections.defaultdict(list)
    for ts, kind, txt in marks:
        for k in keys:
            if k in txt:
                hits[k].append((ts, txt)); break
    for k in keys:
        v = hits.get(k, [])
        if v:
            print(f"\n### {k}（{len(v)} 条）")
            for ts, txt in v[:8]:
                print(f"  {ts:.3f} {txt[:130]}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "com.xixin.box")
