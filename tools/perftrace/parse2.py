#!/usr/bin/env python3
"""解析 atrace 文本：提取目标进程主线程时间线、线程占用、ART/GC 事件。

用法: python3 parse2.py <trace.txt> [包名]
"""
import re, sys, collections

TARGET = sys.argv[2] if len(sys.argv) > 2 else "com.xixin.box"
LINE = re.compile(
    r"^\s*(?P<task>\S+?)-(?P<pid>\d+)\s+\(\s*(?P<tgid>[\d-]+)\)\s+\[(?P<cpu>\d+)\]\s+"
    r"(?P<flags>\S+)\s+(?P<ts>\d+\.\d+):\s+(?P<ev>[^:]+):\s*(?P<rest>.*)$"
)

def main(path):
    main_pid = None
    threads = collections.defaultdict(lambda: {"run": 0.0, "n": 0, "tgid": None, "name": ""})
    marks = []
    offs = []
    events = collections.Counter()
    art_events = collections.Counter()
    tmin = tmax = None
    pid_tgid = {}

    # 第一遍：找主线程 pid（dalvik/am 的 tracing_mark_write 里 tgid = 主 pid）
    with open(path, "r", errors="replace") as f:
        for line in f:
            if "tracing_mark_write" not in line or TARGET not in line:
                continue
            m = LINE.match(line)
            if not m:
                continue
            rest = m.group("rest")
            mm = re.match(r"([BEC])\|(\d+)\|(.*)", rest)
            if mm:
                main_pid = int(mm.group(2))
                break
    if main_pid is None:
        print("未找到主线程 pid"); return

    sched_switch = {}
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
            tgid = m.group("tgid")
            is_target = (TARGET in task) or (pid_tgid.get(pid) == main_pid) or (tgid != "-------" and tgid.isdigit() and int(tgid) == main_pid)

            if is_target:
                d = threads[pid]
                d["tgid"] = tgid; d["n"] += 1
                if not d["name"]:
                    d["name"] = task
                pid_tgid[pid] = main_pid
                events[ev] += 1

            if ev == "sched_switch":
                pm = re.match(r"prev_comm=(\S+) prev_pid=(\d+) .*?next_comm=(\S+) next_pid=(\d+)", rest)
                if not pm:
                    continue
                pcomm, ppid, ncomm, npid = pm.group(1), int(pm.group(2)), pm.group(3), int(pm.group(4))
                prev = sched_switch.get(cpu)
                if prev and prev[0] == ppid:
                    dur = ts - prev[1]
                    if 0 <= dur < 60 and is_target and TARGET in pcomm:
                        threads[ppid]["run"] += dur
                sched_switch[cpu] = (npid, ts)
                if TARGET in pcomm and ppid == main_pid:
                    offs.append((ts, pcomm[:40]))
            elif ev == "tracing_mark_write":
                mm = re.match(r"([BEC])\|(\d+)\|(.*)", rest)
                if mm and int(mm.group(2)) == main_pid:
                    kind, txt = mm.group(1), mm.group(3)
                    marks.append((ts, kind, txt))
                    if "art" in txt.lower() or "gc" in txt.lower() or "verify" in txt.lower() or "jit" in txt.lower():
                        art_events[txt[:70]] += 1

    span = (tmax - tmin) if tmin and tmax else 0
    print(f"# {path}")
    print(f"# 跨度 {span:.3f}s  主线程 pid={main_pid}  mark={len(marks)}  离线={len(offs)}")
    print("\n## 线程 Running Top20")
    print("| pid | 线程 | Running(s) | 事件数 |")
    print("|---|---|---|---|")
    for pid, d in sorted(threads.items(), key=lambda kv: -kv[1]["run"])[:20]:
        print(f"| {pid} | {d['name']} | {d['run']:.3f} | {d['n']} |")
    print("\n## ART/GC/JIT 相关 mark Top25")
    for k, v in art_events.most_common(25):
        print(f"  {v:5d}  {k}")
    print("\n## 主线程 mark 关键片段（前 60 条）")
    for ts, kind, txt in marks[:60]:
        print(f"  {ts:.3f} {kind} {txt}")

if __name__ == "__main__":
    main(sys.argv[1])
