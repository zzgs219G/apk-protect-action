# AOT 损失假设验证记录（dex2oat / profile 链路）

- **验证日期**：2026-10-12
- **设备**：Xiaomi 2602BRT18C / Android 16 / SDK 36 / arm64-v8a / cortex-a55
- **被测 APK**：`简盒_加壳_新字符串加密_sign.apk`（6,335,204 B，含 L1 解密缓存）
- **对照 APK**：`简盒-正式版-v2.1.1_211-20261011-2048-18f9281_sign.apk`（4,663,620 B）
- **上游文档**：`docs/验收文档.md` §四（packer AOT 损失假设）、`docs/简盒-加壳对比测试报告.md` §六
- **验证性质**：本文件替代 `验收文档.md` §4.2 表中"待执行"的第 1、2 步；第 3 步（二分矩阵）仍需 jian_box 逐轮勾选，未做。

---

## 一、结论速览

| # | 假设 | 判定 | 关键证据 |
|---|---|---|---|
| 1 | 加壳版 profile 被判定失效，ART 忽略 | **成立（坐实）** | `ArtService: Adjusting the compiler filter ... from 'speed-profile' to 'verify' because there is no valid profile` |
| 2 | dpt 的 execve 钩子拦截 dex2oat，编译被跳过 | **不成立（证伪）** | dex2oat 正常启动、`returned code 0`、`status=PERFORMED`、`sizeBytes=8109096` |
| 3 | 加壳版全程无 AOT、解释/JIT 执行 | **成立** | 最终 `[status=verify] [reason=install]`，`executable 'false'` |

**净结论**：AOT 损失假设的**主体成立但成因需修正**——不是 dpt 拦了 dex2oat，而是**装包时系统自己把 `speed-profile` 降级为 `verify`**，因为 dex 被变换后 profile 校验不过。dpt 的 execve 钩子在本轮日志中**没有任何痕迹**，不应再作为归因链的一环。

---

## 二、`--check-prof` 命令已废弃

用户指定的命令：

```bash
adb shell cmd package compile --check-prof com.xixin.box
```

实测返回：

```
Warning: Ignoring obsolete flag '--check-prof'. It is unconditionally enabled now
Error: Argument expected after "com.xixin.box"
exit=1
```

`--check-prof` 自 Android 12 起无条件启用，`cmd package compile` 不再接受该 flag，且包名必须跟在 `-m <mode>` 之后。

**替代判据**：`dumpsys package dexopt` 看该包的编译档位与 reason：

```bash
adb shell dumpsys package dexopt | grep -A3 com.xixin.box
```

实测（安装后）：

```
[com.xixin.box]
  path: /data/app/~~57TwuzbV-ob1YXNbN3O_Ow==/com.xixin.box-B03ZLChYnchuWoz0GniBeg==/base.apk
    arm64: [status=verify] [reason=install] [primary-abi]
      [location is .../oat/arm64/base.odex]
```

---

## 三、装包 dex2oat 日志全链路

### 3.1 抓取方法

```bash
adb logcat -G 16M
adb logcat -c
adb logcat -v time > /tmp/perftest/full_install.log &   # 全量抓，不加 -s 过滤
adb uninstall com.xixin.box
adb install -r -d "/tmp/perftest/new_signed.apk"
```

> 踩坑记录：先前用 `adb logcat -v time -s dex2oat:D PackageManager:D ...` 只抓到 12 行，**`artd` / `ArtService` 不在过滤 tag 里**，而最关键的两行恰恰由这两个 tag 输出。必须全量抓再 grep。

### 3.2 决定性日志（按时间序）

```
10-12 23:54:53.710 I/artd    : Merge skipped because there are no existing profiles
10-12 23:54:53.710 I/ArtService: Adjusting the compiler filter for 'com.xixin.box'
                                from 'speed-profile' to 'verify'
                                because there is no valid profile
10-12 23:54:53.711 I/artd    : GetBestInfo: .../base.apk has no usable artifacts
10-12 23:54:53.718 I/artd    : Running dex2oat: .../dex2oat64 ...
                                --compiler-filter=verify --compilation-reason=install ...
10-12 23:54:53.844 I/dex2oat64: dex2oat took 89.084ms (80.225ms cpu) (threads: 6)
10-12 23:54:53.852 I/artd    : dex2oat returned code 0
10-12 23:54:53.856 I/ArtService: Dexopt result: [packageName = com.xixin.box]
                                actualCompilerFilter=verify, status=PERFORMED,
                                dex2oatWallTimeMillis=131, dex2oatCpuTimeMillis=110,
                                sizeBytes=8109096, sizeBeforeBytes=0
```

6 秒后二次查询（`cmd package compile -m verify -f` 之后）：

```
10-12 23:54:54.000 I/ArtService: Adjusting the compiler filter ... to 'verify'
                                because there is no valid profile
10-12 23:54:54.000 I/ArtService: Dexopt result: ... status=SKIPPED,
                                dex2oatWallTimeMillis=0, sizeBytes=0
```

### 3.3 逐条对质两个疑点

| 疑点 | 实测 | 判定 |
|---|---|---|
| 编译器被拦 | dex2oat 正常启动、`code 0`、`status=PERFORMED`、89ms 跑完 | **未拦** |
| 编译被跳过 | `sizeBytes=8109096`，odex/vdex 真实产出 | **未跳过** |
| 为何只有 verify | 第 2 行：系统主动从 `speed-profile` **降级** | **系统降级** |

`status=SKIPPED`（6 秒后那次）是 `GetBestInfo: ... is kOatUpToDate with filter 'verify'` 的正常短路，不是失败。

---

## 四、profile 失效的直接证据（本机 unzip 实查）

两版 APK 的 `assets/dexopt/baseline.prof` **字节级完全相同**：

| 项 | 正式版 | 加壳版（新字符串加密） |
|---|---|---|
| `assets/dexopt/baseline.prof` | 12,769 B | 12,769 B |
| prof md5 | `f9f52b7e29e962f6d6e4d86730d7724e` | `f9f52b7e29e962f6d6e4d86730d7724e`（**相同**） |
| `assets/dexopt/baseline.profm` | 1,448 B | 1,448 B |
| `classes.dex` magic | `dex\n038` | `dex\n035` |
| `classes.dex` md5 | `fefd49a6...` | `dc4960d9...` |

**同一份 profile 原样带进了 dex 已被改写的包**，而 profile 按 dex 校验和/方法索引绑定，dex 一变换即失配——这与日志第 2 行 "no valid profile" 完全吻合。

> 我尝试在 prof 二进制里直接搜 dex checksum（official `0x4ba0d99c` / 加壳 `0x636d8f11`，小端与大端都试）**均未命中**。prof 内部用的是它自己的编码布局（magic `pro\0` + ver `010\0` + 若干 u32 字段），不是明文 dex 校验和。因此本节结论建立在"两版 prof 字节相同 + dex 不同"这一对质上，**未做 prof 格式逐字段解析**——若需精确到"哪一条方法索引失配"，需按 ART `ProfileCompilationInfo` 格式另写解析器。

---

## 五、dpt execve 钩子假设被证伪

`验收文档.md` §4.1 第 4 条列的证据"dpt 的 execve 钩子拦截 dex2oat"，在本轮全量日志中**查无实据**：

- 无任何 `dpt` / `execve` / hook / `ptrace` 相关 tag 输出；
- dex2oat 从 `artd` 正常 fork，`/apex/com.android.art/bin/dex2oat64` 完整执行；
- 唯一的"拦截"来自系统自身的 `ArtService` 降级决策。

**修正归因**：降级发生在**装包阶段的 PackageManager/ArtService**，早于且独立于 dpt 壳运行（dpt 只在 App 进程启动后才活动）。这也解释了为何此前 `[status=verify] [reason=install]` 里 reason 是 `install` 而非 dpt 相关值。

---

## 六、影响与后续

### 6.1 对既有结论的影响

| 文档结论 | 需否修正 |
|---|---|
| 报告 §六 冷启动 ~427ms 数据 | 不变（真机实测有效） |
| 验收文档 §四"stringenc 非主犯" | 不变，且本文件**进一步支持**该结论 |
| 验收文档 §4.1 第 4 条（dpt 拦 dex2oat） | **需修正**：改为"系统因 profile 失效主动降级" |
| 验收文档 §4.2 第 1、2 步 | **本文件已完成**，可标记为已执行 |

### 6.2 尚未验证的部分

`验收文档.md` §4.2 第 3 步（二分矩阵：A=仅 packer / B=A+stringenc / C=B+dex2c）**未执行**，需要 jian_box 逐轮勾选出包。

本文件只证明"加壳版无 AOT"，**未证明"AOT 损失就是那 +230ms 的主因"**——两者不是一回事。要坐实主因，仍需二分矩阵里 A 轮（仅 packer、不含 stringenc/dex2c）单独测一次冷启动。

### 6.3 一个可快速做的确认实验（建议下一步）

手动强制 AOT，看冷启动是否显著下降：

```bash
adb shell cmd package compile -m speed-profile -f com.xixin.box
# 无 profile 时该命令也可能失败；更直接的是强制 speed：
adb shell cmd package compile -m speed -f com.xixin.box
adb shell dumpsys package dexopt | grep -A3 com.xixin.box
```

若 `status` 变 `speed` 且冷启动明显下降 → AOT 是主要瓶颈坐实；若无变化 → 瓶颈在 dex2c/壳运行时，方向需改。

---

## 七、原始数据存档

| 文件 | 说明 |
|---|---|
| `/tmp/perftest/full_install.log` | 装包全量 logcat（9,768 行，含 §3.2 全部关键行） |
| `/tmp/perftest/new_signed.apk` | 被测加壳 APK（自设备 `/storage/emulated/0/常用/工作台😡/` 拉取） |
| `/tmp/perftest/official.apk` | 正式版对照 APK |
| `/tmp/perftest/official.prof` / `new_signed.prof` | 两版抽出的 baseline.prof（md5 相同） |
| `/data/misc/profman/com.xixin.box-primary.prof.txt` | 设备端 dump-profiles 产物，220,455 B（profile 采集通道正常） |
