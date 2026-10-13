#!/usr/bin/env python3
"""计算两份 trace 中目标进程主线程的 Running 时间与状态分布，并做 A/B 对比。

用法: python3 run.py <packed.txt> <official.txt> <包名>
"""
import re, sys, collections

LINE = re.compile(
    r"^\s*(?P<task>\S+?)-(?P<pid>\d+)\s+\(\s*(?P<tgid>[\d-]+)\)\s+\[(?P<cpu>\d+)\]\s+"
    r"(?P<flags>\S+)\s+(?P<ts>\d+\.\d+):\s+(?P<ev>[^:]+):\s*(?P<rest>.*)$"
)

def main_pid_of(path, target):
    with open(path, "r", errors="replace") as f:
        for line in f:
            if target in line and "Open oat file" in line:
                m = LINE.match(line)
                if m: return int(m.group("pid"))
    return None

def analyze(path, target):
    mp = main_pid_of(path, target)
    if mp is None: return None
    switches = []   # (cpu, ts, prev_pid, prev_comm, next_pid)
    tmin = tmax = None
    with open(path, "r", errors="replace") as f:
        for line in f:
            m = LINE.match(line)
            if not m: continue
            ts = float(m.group("ts"))
            if tmin is None: tmin = ts
            tmax = ts
            if m.group("ev").strip() != "sched_switch": continue
            pm = re.match(r"prev_comm=(\S+) prev_pid=(\d+) .*?next_comm=(\S+) next_pid=(\d+)", m.group("rest"))
            if not pm: continue
            switches.append((m.group("cpu"), ts, int(pm.group(2)), pm.group(1), int(pm.group(4))))
    by_cpu = collections.defaultdict(list)
    for s in switches: by_cpu[s[0]].append(s)
    run = 0.0
    offs = []   # (ts, dur, prev_comm)
    for cpu, lst in by_cpu.items():
        for i in range(len(lst)):
            _, ts, ppid, pcomm, npid = lst[i]
            end = lst[i+1][1] if i+1 < len(lst) else tmax
            d = end - ts
            if d < 0 or d > 60: continue
            if ppid == mp:
                run += d
                offs.append((ts, d, pcomm))
    return {"pid": mp, "run": run, "offs": offs, "tmin": tmin, "tmax": tmax}

def main():
    a = analyze(sys.argv[1], sys.argv[3])
    b = analyze(sys.argv[2], sys.argv[3])
    for name, r in ((sys.argv[1].split("/")[-1], a), (sys.argv[2].split("/")[-1], b)):
        print(f"# {name}: 主 pid={r['pid']} Running={r['run']:.3f}s 切换={len(r['offs'])}")
    diff = a["run"] - b["run"]
    print(f"\n# 主线程 Running 差值 = {diff*1000:.0f} ms（A - B）")
    print("\n## A 主线程被切走去向 Top20（累计 ms）")
    tot = collections.Counter(); cnt = collections.Counter()
    for ts, d, c in a["offs"]:
        tot[c] += d; cnt[c] += 1
    print("| 被谁抢占 | 次数 | 累计(ms) |")
    print("|---|---|---|")
    for c, t in tot.most_common(20):
        print(f"| {c} | {cnt[c]} | {t*1000:.1f} |")
    print("\n## B 主线程被切走去向 Top20（累计 ms）")
    tot = collections.Counter(); cnt = collections.Counter()
    for ts, d, c in b["offs"]:
        tot[c] += d; cnt[c] += 1
    print("| 被谁抢占 | 次数 | 累计(ms) |")
    print("|---|---|---|")
    for c, t in tot.most_common(20):
        print(f"| {c} | {cnt[c]} | {t*1000:.1f} |")

if __name__ == "__main__":
    main()
