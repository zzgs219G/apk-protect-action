# atrace 启动轨迹归因报告（正式版 vs 加壳版）

- **日期**：2026-10-13
- **设备**：Xiaomi 2602BRT18C / Android 16 / SDK 36 / arm64-v8a / user build
- **方法**：`atrace` 录冷启动全量轨迹，程序化解析做 A/B 对质
- **上游**：`docs/adb任务.md`（本次任务书）、`docs/AOT损失验证记录.md`

---

## 一、结论速览

**+230ms 冷启动差距的归属已经找到，且是单一主因。**

| 维度 | 加壳版 | 正式版 | 差值 |
|---|---|---|---|
| 主线程 Running（trace 实测） | 1.177 s | 0.950 s | **+227 ms** |
| 冷启动 TotalTime（`am start -W`） | ~427 ms | ~195 ms | +230 ms |
| `VerifyClass` 次数 | **1,860** | **0** | — |
| `DefineClass_` 次数 | **5,269** | **1,242** | **4.2×** |
| `Lock contention` | 154 | 30 | 5.1× |
| 运行时 dex 校验 | **有**（`xixin_dexes.zip`） | 无 | — |

227ms（trace 主线程 CPU 占用差）与 230ms（`am start -W` 墙钟差）**两个独立测量手段互相印证**——差距几乎全部落在主线程的解释执行/类校验上，不是 I/O 等待、不是 binder、不是 GC。

**主因一句话**：壳在运行时把 dex 解密成 `code_cache/xixin_dexes.zip` 交给 ART，ART 必须**现场校验 + 解释执行**这 5,269 个类；正式版的 dex 装包时已被 dex2oat 校验过且编译档位更高，启动时 `VerifyClass` 为 0。

---

## 二、命令与踩坑

### 2.1 可用的命令序列（已修正）

`docs/adb任务.md` 给的类别 `binder` 在这台设备上**不存在**，会报错：

```
error: unknown tracing category "binder"
```

正确类别名是 `binder_driver` / `binder_lock`。可用全集见 `atrace --list_categories`。实测命令：

```bash
adb shell atrace --async_start -b 16000 -o /data/local/tmp/OUT \
    sched freq idle am wm gfx view binder_driver binder_lock aidl dalvik

adb shell am force-stop com.xixin.box
adb shell am start -W -n com.xixin.box/.MainActivity
sleep 6
adb shell atrace --async_stop -o /data/local/tmp/OUT.txt
adb pull /data/local/tmp/OUT.txt
```

### 2.2 两个坑

| 坑 | 现象 | 处理 |
|---|---|---|
| `-s dex2oat PackageManager` 过滤 tag 抓不到关键行 | 上一轮 AOT 验证只抓到 12 行，`artd`/`ArtService` 不在过滤名单 | **全量抓**再 grep |
| `-b 32000`（KB）不起作用 | 输出仍达 308 MB / 164 MB | 该参数在这台设备的 atrace 上未生效；文件大但可解析（1.3–1.5 M 行，解析约 5–8 s），接受 |

产物：`trace_packed.txt` 164 MB / 1,342,021 行；`trace_official.txt` 190 MB / 1,516,350 行。均在 `/tmp/perftest/`。

---

## 三、启动窗口对比

以 `Open oat file`（ART 开始装载本应用 dex）为 T0。

| 指标 | 加壳版 | 正式版 |
|---|---|---|
| T0 `Open oat file` | 119523.668 | 119557.821 |
| `activityStart` | 119523.883 | 119557.908 |
| `performStart` | 119523.912 | 119557.944 |
| **T0 → activityStart** | **0.215 s** | **0.087 s** |
| **T0 → performStart** | **0.244 s** | **0.123 s** |

窗口内类加载密度（每秒 `DefineClass`）：

| 版本 | 启动窗口 DefineClass_ | VerifyClass |
|---|---|---|
| 加壳版 | **4,533** | 1,648 |
| 正式版 | 577 | 0 |

（注：本表为启动窗口 [T0, performStart+0.5s] 内的数量；§一的总量为全 trace 口径 5,269 / 1,242。）

**窗口时长差 0.121s，类加载量差 7.9 倍。**

---

## 四、dex 装载序列差异（决定性）

### 4.1 加壳版

```
119523.670 Open dex file  /data/app/.../base.apk                              ← 壳 dex
119523.713 Open dex file  /data/user/0/com.xixin.box/code_cache/xixin_dexes.zip  ← 壳运行时解密产出
119523.713 Verify dex file /data/user/0/com.xixin.box/code_cache/xixin_dexes.zip  ← 现场校验
```

`xixin_dexes.zip` 在 trace 中出现 **485 次**（打开/校验/注册/DefineClass 全链路）。这是壳的核心机制：把真实 dex 藏进 APK，运行时解密落到 `code_cache` 再交给 ART。

### 4.2 正式版

```
119557.824 Open dex file  /data/app/.../base.apk
```

只有一条，直接读 APK 内 dex，**无运行期解密、无现场校验**。

---

## 五、为什么 `VerifyClass` 差 1,860 条

这是 AOT 损失假设（`docs/AOT损失验证记录.md`）与本次 trace 的**闭环**：

1. 装包时系统因 profile 失效，把编译档位从 `speed-profile` 降到 `verify`（已由装包日志实锤）；
2. `verify` 档**只做字节码校验，不产出机器码**（`executable 'false'`）；
3. 但加壳版的 dex 根本不在 APK 里——它在 `xixin_dexes.zip`，**装包时 dex2oat 完全看不到它**，所以对它连 verify 都没做过；
4. 运行时 ART 第一次装载这个 zip，只能**现场补做全部校验**：1,860 次 `VerifyClass` + 5,269 次 `DefineClass_`，且全程解释执行；
5. 正式版的 dex 装包时已被 dex2oat 校验并编译，运行时 `VerifyClass` = 0。

**修正一处上游表述**：`docs/AOT损失验证记录.md` §一假设 3「加壳版全程无 AOT」成立，但机理比"AOT 损失"更狠——**加壳 dex 连装包期校验都被绕过了**，校验成本整个后移到了启动路径上。

---

## 六、任务书里其余嫌疑的排查结果

`docs/adb任务.md` 列了 5 类嫌疑的 trace 长相，逐一对质：

| 嫌疑 | trace 实测 | 判定 |
|---|---|---|
| AOT 损失 | 主线程连续 Running + 大量 `VerifyClass`/`DefineClass` | **✅ 坐实（主犯）** |
| envcheck 看门狗 20s 周期唤醒 | 未见周期性唤醒块（trace 仅 9.6s，需更长窗口确认） | ⏳ 窗口不足，未证实也未证伪 |
| stringenc / dex2c | GC 事件 1,174 条，但正式版也有；无异常密集 | **❌ 非主犯**（与验收文档 §4.3 一致） |
| 壳自身解密（`libxixin.so` 线程块） | `NativeGuard` 子进程出现 2 次，但解密本身在主线程完成、耗时可忽略 | 机制存在，非耗时主因 |
| 正常等待 binder/I/O | 主线程 binder 事务 850 vs 863（基本持平） | **❌ 非差异来源** |

**GC 不是瓶颈**：加壳版 GC 相关 mark 1,174 条，Heap size 峰值 33 MB，与正式版同量级。

---

## 七、解析工具

新增 `tools/perftrace/`：

| 脚本 | 用途 |
|---|---|
| `report.py` | 单份 trace：主线程 Running、段耗时、线程占用、关键事件（oat/dex/VerifyClass/DefineClass/lock） |
| `ab.py` | A/B 对比：启动窗口、类加载密度、dex 装载序列 |
| `run.py` | 主线程 Running 时间 A/B + 被切走去向 |

定位主线程 pid 的技巧：grep 该进程的 `Open oat file` 事件，其 pid 即主线程（zygote fork 出的应用主线程）。

已知局限：
- atrace 文本的 B/E 配对因 E 可由任意线程发出，栈式配对会漏；本工具对 Running 时间用 `sched_switch` 计算（可靠），段耗时仅作参考。
- user build 看不到 Java 方法名（任务书已声明）；本报告的类名来自 ART 原生 trace 点，是 JVM 内部类名而非 Java 源码方法名。

---

## 八、下一步建议

trace 已经回答了"慢在哪"。要真正消掉这 227ms，方向在 `docs/验收文档.md` §4.3 的 ①②③，但按本次证据可重新排序：

| 方向 | 本次证据下的评价 |
|---|---|
| ② 有条件放行 dex2oat | **优先级最高**：现在连装包期校验都没做，若能对还原后 dex 走一次 dexopt，227ms 的大部分可直接消掉 |
| ① profile 重建 | 单独做不够——profile 只影响编译档位，不解决"壳 dex 不在 APK 里所以 dex2oat 看不到"这一层 |
| ③ dex2c 走 native | 有效但覆盖面有限，仅对转入 native 的类生效 |
| ④ 接受现状 | 427ms |

**若要进一步定量拆分**（解释执行 vs 类校验各占多少），建议在 `jian_box` manifest 加 `<profileable android:shell="true"/>`，再用 Perfetto 录 Java 方法级轨迹。这是任务书提到的"后话"，但现在是性价比最高的一步。

---

## 九、原始数据

| 文件 | 说明 |
|---|---|
| `/tmp/perftest/trace_packed.txt` | 加壳版 trace，164 MB |
| `/tmp/perftest/trace_official.txt` | 正式版 trace，190 MB |
| `/tmp/perftest/rec.sh` | 设备端录制脚本 |
| `tools/perftrace/*.py` | 解析工具 |

设备侧已重新装回加壳版（`简盒_加壳_新字符串加密_sign.apk`）。
