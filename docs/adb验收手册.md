# adb 验收手册（AI 可直接执行版）

- **日期**：2026-10-13
- **设备**：Xiaomi 2602BRT18C / Android 16 (SDK 36) / arm64 / **user build（零售机）**
- **连接**：WiFi adb `192.168.1.5:46321`（断线重连：`adb connect 192.168.1.5:46321`）
- **本手册全部命令已在该设备实测**；已知陷阱见 §七。

---

## 一、环境检查

```bash
adb devices -l                                   # 确认设备在线
adb shell getprop ro.build.version.release       # Android 版本（16）
adb shell pm path com.xixin.box                  # 当前安装的包路径
adb shell dumpsys package dexopt 2>/dev/null | grep -A5 '^\s*\[com.xixin.box\]'
```

最后一行的预期输出（当前 L1 缓存版）：

```
[com.xixin.box]
  path: /data/app/.../base.apk
    arm64: [status=verify] [reason=install] [primary-abi]     ← verify = 只校验未编译（加壳现状）
```

> ⚠️ grep 必须用 `^\s*\[包名\]` 锚定行首方括号。不带锚点会把全设备
> "used by other apps" 巨型列表（几百行）全部带出来。

---

## 二、冷启动测量（标准方法，5 轮取中位数）

```bash
for i in 1 2 3 4 5; do
  adb shell am force-stop com.xixin.box
  sleep 2
  adb shell am start -W -n com.xixin.box/.MainActivity 2>&1 | grep TotalTime
done
```

- 首轮含安装后初始化开销（实测 603-1124ms），**取 2-5 轮中位数**为准。
- 基线数据：正式版 ~195ms；加壳版（无后台 dexopt）~427ms；首轮 603-1017ms 两版皆有。

---

## 三、编译档位 / profile 状态

```bash
adb shell dumpsys package dexopt 2>/dev/null | grep -A5 '^\s*\[com.xixin.box\]'
```

判读：
- `[status=verify]` = 只校验不编译（加壳现状，装包时系统降级：profile 失配）
- `[status=speed-profile]` / `[status=speed]` = 已 AOT（原生 App 的正常态）
- `[reason=install]` = 装包时决定；`bg-dexopt` = 后台空闲编译

**已废弃命令**：`cmd package compile --check-prof`（Android 12+ 移除该 flag，
报 `Ignoring obsolete flag`）。等价判据就是上面的 dumpsys。

---

## 四、轨迹录制（毫秒级「进程在干嘛」）

```bash
# 类别名先确认（本机实测：binder_driver/binder_lock/dalvik/sched 存在；没有裸 "binder"）
adb shell atrace --list_categories

# 冷启动轨迹录制（开始 → force-stop → 启动 → 6s → 停止）
adb shell atrace --async_start -b 16000 sched freq idle am wm gfx view dalvik binder_driver binder_lock
adb shell am force-stop com.xixin.box
adb shell am start -n com.xixin.box/.MainActivity
sleep 6
adb shell atrace --async_stop > startup_trace.txt
```

解析（仓库自带工具，主 pid 由 trace 内 `Open oat file` 事件定位）：

```bash
python3 tools/perftrace/report.py  startup_trace.txt com.xixin.box   # 单份：主线程 Running、段耗时
python3 tools/perftrace/ab.py      a.txt b.txt com.xixin.box         # A/B：窗口、类加载密度、dex 装载序列
python3 tools/perftrace/run.py     a.txt b.txt com.xixin.box         # A/B：主线程 Running 差值 + 被切走去向
```

关键指标（已实测基线）：

| 指标 | 正式版 | 加壳版 | 意义 |
|---|---|---|---|
| `Open dex file .../code_cache/xixin_dexes.zip` | 无 | 有（485 次提及） | 壳运行时解密落盘的证据 |
| VerifyClass | **0** | 1,660-2,304 | 装包期未校验 → 启动期现场补 |
| 主线程 Running | 0.950s | 1.177s（**+227ms**） | 与 am start -W 差值互证 |
| 被切走去向 | — | <2ms | 排除调度干扰（差距是真实 CPU 工作） |

---

## 五、方法级 CPU 归因（simpleperf，需 profileable）

user build 下 simpleperf 只能采样 **debuggable** 或声明了 **profileable** 的 App。
给加壳包开启（流水线 manifest 编辑器注入一行）：

```xml
<application ...>
  <profileable android:shell="true"/>   <!-- Android 10+，仅允许 adb/shell 侧采样 -->
```

然后：

```bash
adb shell simpleperf record --app com.xixin.box --duration 8 -g
adb shell simpleperf report --dsos 2>/dev/null | head -30
# 或拉取 perf.data 用 ui.perfetto.dev 的火焰图视图
```

价值：火焰图直接显示冷启动 6s 的 CPU 分布——解释器帧（`art::interpreter`）、
JIT、`VerifyClass`、GC、壳解密函数（libxixin.so）各自占比**一目了然**，
这是「一眼看到问题在哪」的终极形态。

---

## 六、后台 dexopt 功能验收（v1.1.3 壳，待新加壳包）

前置：用 v1.1.3 工具重新打包（全模块）→ adb 安装。

```bash
# ① 首次启动（触发后台 dexopt：attachBaseContext + 5s 后 quicken 编译）
adb shell am force-stop com.xixin.box
adb shell am start -W -n com.xixin.box/.MainActivity | grep TotalTime
sleep 12                                            # 等 quicken 后台跑完（~1-2s）

# ② 检查壳日志（dexopt 是否执行/成功）
adb logcat -d -s dpt_bgdx

# ③ 第二次冷启动 ×5 取中位数（通过标准：≤300ms）
for i in 1 2 3 4 5; do
  adb shell am force-stop com.xixin.box; sleep 2
  adb shell am start -W -n com.xixin.box/.MainActivity | grep TotalTime
done

# ④ 轨迹复录第二次冷启动，VerifyClass 应 ≈ 0
```

> ⚠️ odex 文件级检查（`code_cache/oat/<isa>/xixin_dexes.odex`）对 shell uid
> 不可见（`Permission denied`，App 私有目录 0700）；非 debuggable 也无法
> `run-as`。**验收判据 = ②③④ 的行为级证据**，不是文件存在性。

---

## 七、已知陷阱清单（全部本轮实测踩过）

| # | 陷阱 | 正确做法 |
|---|---|---|
| 1 | `dumpsys package dexopt` 裸 grep 包名 → 带出全设备列表 | `grep -A5 '^\s*\[包名\]'` 行首锚定 |
| 2 | `cmd package compile --check-prof` | Android 12+ 已移除；用 dumpsys 判读 |
| 3 | atrace 类别 `binder` 不存在 | 用 `binder_driver` / `binder_lock` |
| 4 | logcat `-s dex2oat PackageManager` 过滤抓取 | 会漏 `artd`/`ArtService`（决定性日志的 tag）；**全量抓再 grep** |
| 5 | atrace `-b 32000` 调 buffer | 本机不生效；输出大但可解析，接受 |
| 6 | 热启动 `am start -W` 返回 `TotalTime=0` | 失真；先回桌面（HOME）再启动才有效 |
| 7 | 读他 App 的 `code_cache/` | `Permission denied`（非 debuggable 无 run-as）；用行为级判据 |
| 8 | user build 轨迹看不到 Java 方法名 | 需 `<profileable>` 或 debuggable（§五） |
| 9 | 多进程 trace 的线程 Running 统计 | 必须处理**全部** sched_switch（按 tgid 过滤会破坏时长连续性）；主 pid 用 `Open oat file` 事件定位 |

---

## 八、当前基线（2026-10-13 实测，供后续对比）

| 版本 | 冷启动中位数 | 6s CPU | PSS(8s) | VerifyClass |
|---|---|---|---|---|
| 正式版（无保护） | ~195ms | ~2.75s | 280.6MB | 0 |
| 加壳 v1.1.2 全模块（L1 缓存前） | ~427ms | ~3.86s | 339.9MB | 1,660-2,304 |
| 加壳 v1.1.2 全模块（L1 缓存后） | ~427ms（持平） | ~3.7s | ~314MB | ~2,304 |
| 加壳 v1.1.3 全模块（+后台 dexopt） | ⏳ 待测 | ⏳ | ⏳ | ⏳ 预期第二次起 ≈0 |
