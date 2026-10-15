# XopProtector 对标调研（2026-10-16）

> 目的：借鉴成熟开源加固平台的设计，补强本项目 `apk-protect-action` 的防御面。
> 对标对象：`../XopProtector/`（Apache 2.0，native 层 27632 行 C++，DEX 加密 + 真 VMP + SO 保护 + RASP）。
> 本文档供下一任 AI 接手：记录「它有什么 → 我们缺什么 → 哪些值得抄 → 哪些明确不抄」。
> **阅读顺序**：先看 §3 结论表，再看 §2 逐项详述，§5 是我们自己的隐患清单。

---

## 0. 对标项目全貌（5 分钟版）

```
XopProtector 双端架构:
  构建期: packer (JVM CLI / Windows WPF 桌面端)
  运行期: native shell (libprotector.so) + Java 壳

核心模块 (native/src/main/cpp/):
  vm/      PVM2 解释器 (3192 行, 真 VMP, 不写回 DEX)
  so/      business_so.cpp (6052 行, 业务 SO 加密加载, 7 种加载策略)
  dex/     dex_file.cpp (1250 行, DEX 解密重组)
  risk/    risk.cpp (922 行, RASP 检测) + so_guard.cpp (301 行, SO 自守护)
  crypto/  key_ladder (HKDF 密钥阶梯) + aes/rc4/sha256 + apk_sign
  report/  threat_report (威胁遥测 JSON + crash 遗言)
  hook/    hooks.cpp (Dobby/bytehook 反向 hook ART, 691 行)
```

**与我们项目的定位差异**（先说清楚，避免错误对标）：

| | XopProtector | 我们 (apk-protect-action) |
|---|---|---|
| 类型 | **全量加固平台**（加密优先，可抽空整个 DEX） | **模块化流水线**（勾选式：sigcheck/dex2c/stringenc/envcheck/packer） |
| 密钥架构 | HKDF 密钥阶梯，构建期↔运行期双端同源 | 双轮派生指纹 + LSG 密文文案（各自独立） |
| 签名校验 | `apk_sign.cpp`（v3 优先，syscall 读） | `sig_check.c`（冻结）+ `sig_guard2.c`（双线） |
| 环境检测 | `risk.cpp` 10+ 探针 + 打分制 | `env_check.c` 10 探针（syscall 直调） |
| VMP | PVM2（morph 50 操作码） | 无（dex2c 转译，非解释器） |
| 处置 | RASP 三态（Alert/Degrade/Block） | 固定（延时 abort + SIGKILL） |

**不抄的**：VMP（工程量数月级）、全量 DEX 加密（与我们 dex2c 路线冲突）、SO 加密加载（`so/business_so.cpp` 6052 行的 7 种加载策略，依赖其 .bitcode 加密段前提）。

---

## 1. 已实证的攻防基线（本次会话的实验数据，供对照）

这些结论来自本会话的**真机攻防实验**（设备：Redmi dash / Android 16 / MIUI），
是评估「借鉴什么」的出发点：

| 实验 | 结果 |
|---|---|
| 原版 so + 重签名安装 | ❌ 死于 **SIGABRT**（`code -1 (SI_QUEUE)` = tgkill 直投，A 线 sig_check.c） |
| patch so 的 delayed_kill 4 字节（`sub sp → ret`）+ 重签名 | ✅ **绕过成功**，App 正常运行（修复前） |
| 同上，但部署 sig_guard2 后 | ❌ 死于 **SIGKILL**（signal 9，B 线接手） |
| 破解全程耗时 | 定位 sig_verify ≈90 秒；完整破解 ≈3 分钟；全程仅用 objdump+python3+zip+apksigner |

**我们自己的架构级缺口**（Xop 的心跳机制针对的正是这个）：

```
所有 native 防御 → 依赖 so 被加载 → 依赖 Java 调 NativeGuard.c() → 单点
攻击者删掉 xiApplication.onCreate() 里的一行调用 → so 不加载 → 全部 native 防御归零
（反编译证实: NativeGuard.c / NcLink.ensureLoaded / ncVerify 全在 dex 里,可被 smali 级移除）
```

---

## 2. 值得借鉴的 7 项（逐项详述）

### 2.1 Java 心跳机制 ★★★★★（堵我们最大的架构单点）

**出处**：`risk.cpp:244-283`

```cpp
void record_java_heartbeat() { g_last_heartbeat_ms.store(now_ms()); }
void arm_java_heartbeat() { ... }                    // init_app 时武装
static constexpr int64_t kHeartbeatKeepaliveMs = 15000;   // 之后每 15 秒必须 ping
static constexpr int64_t kHeartbeatFirstPingMs = 90000;   // 首次 90 秒宽限(冷启动解密慢)

static void check_heartbeat() {
    if (armed == 0) return;                 // 未武装(无保护资产) → 不误伤
    if (last == 0) { if (now - armed > 90s) handle_risk(...); return; }
    if (now - last > 15s) handle_risk("java_heartbeat", CrashKind::Abort);
}
```

**它解决什么**：Java 层必须**持续**喂 native；停止 = Java 壳被删/被绕过 → native 主动杀。
**方向反转**：我们是「Java 调 so 才校验」，它是「Java 不喂 so 就死」——**双向绑定**。

**我们怎么落地**（建议方案，未实施）：
- `sig_check.c` 或 `sig_guard2.c` 暴露一个 JNI 函数 `nc_heartbeat()`（幂等，只写时间戳）
- Java 壳的某个**高频回调**（如 `Application.ActivityLifecycleCallbacks`）周期性调用
- native 侧 risk 线程检查：armed 后 N 秒无心跳 → 走 `delayed_kill`
- **注意**：我们已有 LSG 中文日志机制，心跳丢失事件应走 `LSG` 上报，便于真机排障
- **风险点**：宽限期要覆盖我们流水线自身的耗时（stringenc 联动时 apktool 往返 1→2 次），建议首 ping 宽限 ≥90 秒照抄

**为什么排第一**：这是唯一能堵「删 Java 调用」这条实测绕过路径的方案。

### 2.2 检测特征串滚动 XOR ★★★★★（堵已实证的信息泄露）

**出处**：`doc/string-obfuscation.md` + `protector_macro.h`

```cpp
// 算法(明文标注 Not cryptographic —— 目标只是 strings 扫不出来):
c[i] = p[i] ^ (0x5A ^ ((i * 0x1B) & 0xFF))
// 用法(编译期密文,运行时解码):
strcmp(comm, OBSC_DECODE("\x3d\x34\x01\x26\x5c\xae\xd5\x8b\xed\xc6\x24"))  // "gum-js-loop"
```

**我们的痛点**（本会话实测）：

```
$ strings libnc.so | grep -E "frida|/proc|TracerPid"
frida-agent / frida-inject / gadget_frida / pool-frida
/data/adb/lspd / zygisk_lsposed / zygisk_edxposed / XposedBridge.jar
/proc/self/status / /proc/net/tcp / /proc/self/task/%s/comm
TracerPid:
→ 攻击者 10 秒拿到我们全部检测清单,针对性绕过
```

**我们怎么落地**：**机制已存在**——`scripts/sigcheck/log/make-sig-log.py` 的 LSG 密文体系
（XOR 密文 + 构建期生成 + 运行时解码）。只差把 `env_check.c` 的**探针特征串**接入：

- `frida_port_probe` 等所有探针里的特征串（`frida-agent`、`/data/adb/lspd`、`TracerPid:` 等）
- 改造方式：`make-sig-log.py` 扩展一个"检测特征串"类别（与现有中文文案分开编号），运行时解码后使用
- **成本估计**：`make-sig-log.py` + `env_check.c` 各一次改动，半天内
- **注意**：解码产物在内存里仍是明文（AI dump 内存可读），但至少 `strings` 静态扫描失效——这是「提高成本」不是「杜绝」

### 2.3 RASP 三态动作 ★★★★（解决用户明确提过的调试痛点）

**出处**：`runtime_state.h:44-52`

```cpp
enum class RaspAction : int {
    Alert   = 0,  // 只记录,永不 crash —— demo / 低误报风险场景
    Degrade = 1,  // 标记降级 + 延迟 crash(比立即杀软)
    Block   = 2,  // 立即杀(默认)
};
// std::atomic<int> rasp_action{Block};  ← 运行时可配,来自 config.json
```

**我们的痛点**（用户原话）：「这个延迟需要等3秒，非常不适合调试」「闪退太直白」。
Xop 的解法是**运行时配置动作而非写死**：调试包配 Alert（只打日志），发布包配 Block。
连延迟崩溃都能被 Alert 抑制（`check_delayed_crash` 里先查 action）。

**我们怎么落地**：`sig_check.c`/`env_check.c` 的 `handle_risk` 路径读取一个运行时开关。
**难点**：我们的配置来源是 schema（构建期），没有运行时 config.json 通道——
可以考虑复用**哨兵文件**机制（`/storage/emulated/0/xixin_debug` 已存在，
可扩展为「存在=Alert 模式」），**零新增基础设施**。

### 2.4 libc hook 指令检测（打分制）★★★★

**出处**：`risk.cpp:477-503`

```cpp
static bool libc_export_hooked(void* fn) {
    uint32_t w; safe_read_u32(fn, &w);   // 只读第一条指令 4 字节!
    // arm64: B(0x14xxxxxx) / BL(0x94xxxxxx) / BRK(0xD420xxxx) = 被 inline hook
    if ((w & 0xFC000000u) == 0x14000000u) return true;
    ...
}
static int libc_hook_score() {
    int score = 0;
    if (libc_export_hooked(libc_sym("fopen")))   score++;
    if (libc_export_hooked(libc_sym("open")))    score++;
    if (libc_export_hooked(libc_sym("connect"))) score++;
    if (libc_export_hooked(libc_sym("read")))    score++;
    return score;
}
```

**对比我们**：`libc_text_crc_probe` 读整个 libc `.text`（最大 64MB 守卫）算 CRC，
每次全量比对。**它只读 4×4 字节，微秒级，且语义更精确**（inline hook 必改入口指令）。

**我们怎么落地**：加进 `env_check.c` 作为 `libc_text_crc_probe` 的补充或替代。
注意我们已有 `self_text_crc_probe`（so 自身），这个是 libc 侧的廉价版。
**打分制思想**也值得抄：单函数被 hook 可能是正常优化，≥2 分才报警。

### 2.5 多探针聚合打分 ★★★★（检测架构思想）

**出处**：`risk.cpp:534-573` `detect_frida()`

```cpp
static void detect_frida() {
    // 强信号单命中即杀:
    if (frida_port_open())      { CRASH_SEGV("frida_port"); return; }
    if (maps_has_frida())       { CRASH_SEGV("frida_maps"); return; }
    // 弱信号聚合,≥3 分才杀:
    if (frida_unix_socket_hits()) score += 2;
    if (frida_tmp_files())        score += 1;
    int thr = frida_thread_hits(); if (thr >= 1) score += thr;
    if (frida_fd_hits())          score += 2;
    if ((score += libc_hook_score()) >= 3) CRASH_SEGV("frida_composite");
}
```

**设计精髓**：**强信号（端口/特征库）单杀；弱信号（fd/临时文件）攒分**。
单看任何一项都可能误报，组合 ≥3 分才动手——误报率与检出率的平衡点明确可调。

**我们现状**：`env_check_run` 是「任一探针命中即 hit」（OR 逻辑），
虽有「gum-js-loop 单杀、其余 ≥2」的局部分级，但整体不如它的**分层聚合**精细。

**我们怎么落地**：重构 `env_check_run` 为「强信号直接 hit + 弱信号累加 score≥3 才 hit」。
**涉及改动**：仅判定层（`env_check_run` + `env_watchdog`），探针本身不动——符合冻结纪律（只追加判定，不改探针）。

### 2.6 crash_hang —— 第五种死法 ★★★

**出处**：`risk.cpp:188`

```cpp
PROTECTOR_ENCRYPT void crash_hang() {
    // Busy-loop → ANR / watchdog kill. Avoid libc sleep/usleep — easily hooked.
    while (true) { volatile int sink = 0; for (int i = 0; i < 2000000; ++i) sink += i; }
}
```

**亮点**：不崩不退，**忙等耗 CPU → 系统 ANR/watchdog 机制杀进程**——
攻击者看到的是「App 卡死被系统杀」，与防御无关。且注释点明
**避开 sleep/usleep（易被 hook）**，用纯算术循环 + 定期 yield。

**与用户需求的呼应**：用户此前讨论过「阴间闪退」，嫌「秒闪退直白」。
Hang 是「看起来像性能 bug」的死法，且**零 syscall 特征**（无 kill/exit/abort 调用）。

**我们怎么落地**：可作为 `delayed_kill` 的**可选变体**（如多路径处置之一）。
**注意**：会真耗电（攻击者设备上），需与现有 SIGKILL 路径并存而非替换。

### 2.7 威胁遥测 + crash 遗言 ★★★

**出处**：`report/threat_report.h` + `doc/threat-telemetry.md`

```json
{"ts":1710000000,"reason":"frida_maps","rasp_action":2,"pid":1234,"sdk":30}
// Block 杀之前写 crash_reason.txt (遗言), Java 侧 CrashGuard 可链上 UncaughtExceptionHandler
```

**我们的痛点**：防御有没有被触发过，**完全不可见**——无法确认线上是否挡过攻击。
Xop 的环形缓冲 + JSON 导出 + 本地遗言文件，让「防御效果」可观测。

**我们怎么落地**：最小版——`env_check.c`/`sig_check.c` 检出时，在现有
`sigcheck_log.txt` 日志里追加一条结构化行（reason/pid/ts）。
**已有机制**：`siglog`/`envlog` 文件日志通道 + `xixin_debug` 哨兵开关，够用，无需新建。

---

## 3. 结论速查表（下一任 AI 从这里开始）

| 优先级 | 借鉴项 | 出处 | 成本 | 解决我们的什么 | 状态 |
|---|---|---|---|---|---|
| 1 | **检测特征串滚动 XOR** | §2.2 | 半天 | `strings` 泄露全部探针清单（已实证） | 未做 |
| 2 | **Java 心跳** | §2.1 | 1-2 天 | 「删 Java 调用」单点（已实证绕过路径） | 未做 |
| 3 | **libc hook 指令打分检测** | §2.4 | 半天 | 替代重 CRC 探针，快且准 | 未做 |
| 4 | **多探针聚合打分** | §2.5 | 半天 | 判定层精细化（只动判定，不动探针） | 未做 |
| 5 | RASP 三态（Alert/Degrade/Block） | §2.3 | 1 天 | 调试便利（复用 xixin_debug 哨兵即可） | 未做 |
| 6 | crash_hang 死法 | §2.6 | 2 小时 | 「闪退直白」的补充手段 | 未做 |
| 7 | 威胁遥测最小版 | §2.7 | 2 小时 | 防御可观测性 | 未做 |

**落地纪律提醒**（对下一任 AI）：
- `sig_check.c` 是**冻结区**——心跳若放它里面，只允许**追加**（`AGENTS.md` §2.4），改逻辑行需用户当次点名授权
- `env_check.c` 本会话已多次改动（A/C/F/B 四方案 + syscall 直调），**当前 HEAD 已全绿**，动判定层前先跑 `test-javacheck.sh`（11 大项）确认基线
- 所有借鉴项**先给设计再动手**——本会话的教训：用户叫停过一次未经确认的冻结区修改（延时参数）

---

## 4. 明确不抄的（及原因）

| 项 | 原因 |
|---|---|
| PVM2 真 VMP | 解释器 3192 行 + morph 引擎，数月工程量；我们走 dex2c 转译路线，定位不同 |
| 全量 DEX 加密 (PDX1) | 与我们 stringenc「只加密字符串常量」的轻量路线冲突；且我们实测 dex2c 联动已解决算法保密 |
| SO 加密加载（business_so 6052 行） | 依赖其 .bitcode 加密段 + Dobby hook linker + 7 种加载策略（L1m/L1/L2e/L2/L2b/L3/Skip），整套前提我们不具备 |
| HMAC 版 SO 自校验（so_guard） | 需要构建期 HMAC 密钥分发体系（key_ladder + config.json HMAC 通道）；我们此前自研的「烘焙期望 CRC」线 D 因编译器常量折叠问题已废弃（教训见 §6） |
| Dobby/bytehook 反向 hook ART | 我们无 DEX 加密/类重定向需求，hook ART（DefineClass 等）是为壳服务的 |
| NetGuard 证书固定 | 与加固正交（应用层 HTTPS 范畴），用户侧已有 AntiCapture |

---

## 5. 顺带发现：我们自己的隐患（不在借鉴清单里，是修 bug）

### 5.1 gmain/gdbus 误报风险（高优先级）

**出处**：Xop `risk.cpp:525` 注释原文：
> Do NOT match generic GLib names (gmain/gdbus) — **common on MIUI/OEM processes and cause false positives**.

**我们的问题**：`env_check.c` 的 `frida_thread_probe` 线程名清单**包含 `gmain`/`gdbus`**：
```c
static const char *names[] = { "gum-js-loop", "gmain", "gdbus", "pool-frida", "frida" };
```
虽然当前有「单命中不杀，≥2 才杀」的分级（`env_check.c:541`），**且 gum-js-loop 单杀**，
单靠 gmain 不会触发——但用户测试机就是 MIUI，若某 ROM 进程同时存在
gmain + 另一杂项命中，理论上可凑满 2 分误杀。

**建议修法**：从清单删除 `gmain`/`gdbus`（Xop 已实证它们在 MIUI 上常见且与 Frida 无关），
Frida 特征只保留 `gum-js-loop`/`pool-frida`/`frida`。
**改动成本**：一行。**但 `env_check.c` 探针清单是检测语义，建议用户确认后再动**。

### 5.2 `.init_array` 读取误判的教训（记录，防止重蹈）

本会话曾因「静态读 so 的 `.init_array` 内容为 0」误判「constructor 未执行」，
实际 `.init_array` 存的是需要重定位的占位，**静态读 0 是正常的**。
验证 constructor 是否执行的正确方法：**真机 logcat 看 LSG 日志输出**（如 `【流程】so 已加载`）。
此教训已在本会话当面向用户承认，此处留档防止下一任重犯。

---

## 6. 本会话已完成的防御资产（接手者必知的现状基线）

以下全部**已提交推送**（HEAD `802d7ab`），真机验证过：

| 提交 | 内容 | 真机验证 |
|---|---|---|
| `e33646f` | 方案 A：`PTRACE_TRACEME` + `PR_SET_DUMPABLE` 反调试抢占 | 编译在位 + App 无误伤（attach 测试因设备无 root 未完成） |
| `cb42766` | 方案 C：探针 syscall 直调（`safe_read_alloc`/`safe_lines_*`，13 处读取点） | LD_PRELOAD 对照实验：hook 下 libc 路死、syscall 路活 |
| `8ced267` | 方案 F：堆破坏 + `syscall(tgkill, SIGABRT)` 直投 | 对照组 SIGABRT 的 `SI_QUEUE` 代码证明生效 |
| `33f5940` | 方案 B：`self_text_crc_probe`（envcheck 内，内存 vs 磁盘） | 编译在位 |
| `802d7ab` | **sig_guard2 双线**：独立指纹校验 + SIGKILL + watchdog 反制 | **patch 掉 A 线后死于 signal 9（B 线接手）——实测有效** |

**已废弃**（不要再做）：
- sig_guard2 的「线 D」（构建期烘焙 so 期望 CRC）——`-O2 + --gc-sections` 下哨兵常量
  被编译器**内联折叠**（`used` + 独立 section 都拦不住，实测反汇编确认比较指令消失），
  且其攻击面（静态 patch so）已被 A/B 线的重签名检测覆盖。相关代码已全部回退。

**当前防线缺口**（§2 的借鉴项就是为它们准备的）：
1. `strings libnc.so` 泄露检测清单 → §2.2
2. 删 Java 调用 = 全防失效 → §2.1
3. 处置方式写死、调试不便 → §2.3
