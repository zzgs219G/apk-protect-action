#!/usr/bin/env python3
"""解析 atrace 文本，提取目标进程主线程时间线与线程占用汇总。"""
import re, sys, collections

TARGET = "com.xixin.box"
LINE = re.compile(
    r"^\s*(?P<task>\S+)-(?P<pid>\d+)\s+\(\s*(?P<tgid>[\d-]+)\)\s+\[(?P<cpu>\d+)\]\s+"
    r"(?P<flags>\S+)\s+(?P<ts>\d+\.\d+):\s+(?P<ev>[^:]+):\s*(?P<rest>.*)$"
)

def main(path):
    threads = collections.defaultdict(lambda: {"run": 0.0, "n": 0, "tgid": None, "name": ""})
    sched_switch = {}
    main_pid = None
    main_ts = []
    marks = []
    events = collections.Counter()
    tmin = tmax = None

    with open(path, "r", errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m:
                continue
            task, pid = m.group("task"), int(m.group("pid"))
            cpu, ts, ev, rest = m.group("cpu"), float(m.group("ts")), m.group("ev").strip(), m.group("rest")
            if tmin is None:
                tmin = ts
            tmax = ts

            if TARGET in task:
                d = threads[pid]
                d["tgid"] = m.group("tgid"); d["n"] += 1; d["name"] = task
                events[ev] += 1
                if main_pid is None and ev in ("tracing_mark_write",):
                    mm = re.match(r"([BEC])\|(\d+)\|(.*)", rest)
                    if mm:
                        main_pid = int(mm.group(2))

            if ev == "sched_switch":
                pm = re.match(r"prev_comm=(\S+) prev_pid=(\d+) .*?next_comm=(\S+) next_pid=(\d+)", rest)
                if not pm:
                    continue
                pcomm, ppid, ncomm, npid = pm.group(1), int(pm.group(2)), pm.group(3), int(pm.group(4))
                prev = sched_switch.get(cpu)
                if prev and prev[0] == ppid:
                    dur = ts - prev[1]
                    if 0 <= dur < 60 and TARGET in pcomm:
                        threads[ppid]["run"] += dur
                sched_switch[cpu] = (npid, ts)
                if TARGET in ncomm and npid == main_pid:
                    main_ts.append((ts, "RUN"))
                if TARGET in pcomm and ppid == main_pid:
                    main_ts.append((ts, "OFF->" + pcomm[:40]))
            elif ev == "tracing_mark_write":
                mm = re.match(r"([BEC])\|(\d+)\|(.*)", rest)
                if mm and main_pid and int(mm.group(2)) == main_pid:
                    marks.append((ts, mm.group(1), mm.group(3)[:70]))

    span = (tmax - tmin) if tmin and tmax else 0
    print(f"# 文件 {path}")
    print(f"# 跨度 {span:.3f}s  主线程 pid={main_pid}  mark={len(marks)}")
    print("\n## 目标进程线程 Running 时间 Top20")
    print("| pid | 线程名 | Running(s) | 事件数 |")
    print("|---|---|---|---|")
    for pid, d in sorted(threads.items(), key=lambda kv: -kv[1]["run"])[:20]:
        print(f"| {pid} | {d['name']} | {d['run']:.3f} | {d['n']} |")
    print("\n## 事件类型分布")
    for ev, c in events.most_common(25):
        print(f"  {ev}: {c}")
    print(f"\n## 主线程调度切换 {len(main_ts)} 次，mark {len(marks)} 条")

if __name__ == "__main__":
    main(sys.argv[1])
