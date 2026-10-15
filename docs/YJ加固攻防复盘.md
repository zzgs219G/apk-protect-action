# YJ 加固攻防复盘（2026-10-16）

> **性质**：外部商业加固（"简盒_v1.0.2.apk"，YJ 壳）的实战攻防演练。本方作为 AI 攻击者全程计时，
> 逐层侦察 → 绕过签名 → 撞上 VMP 天花板。本文记录全过程、每层防御的真实代价、
> 反推出的架构配方，以及**对我们项目（apk-protect-action）的直接启示**。
> 配套阅读：`docs/XopProtector对标调研.md`（开源对照）、`docs/防御升级评估与交接.md`（我方现状）。

---

## 0. 战报速览

| 阶段 | 耗时 | 结果 |
|---|---|---|
| 摸清防御全貌 | ~8 分钟（15+ 轮侦察） | 完成画像（见 §2） |
| 绕过签名校验 | **25 分钟** | ✅ 成功（入口劫持，App 存活） |
| 让 App 可用（完整破解） | 未达成 | ❌ 被「校验-业务耦合」挡住 |
| 源码还原 | 理论不可能 | ❌ VMP 熵 7.91（§5） |

**对比我方 APK 同期被破解的数据**：摸清全貌 1 分钟（strings 直接读穿）、绕过 3 分钟、
完整破解 3 分钟。差距不在单点强度，在**纵深**（§6）。

---

## 1. 目标画像

```
包名 com.xixin.box / v1.0.2 / launchable: SplashActivity
关键产物:
  lib/arm64-v8a/libyj-v3-pt-320.so   1.7MB（唯一业务 so）
  dex: SplashActivity.onCreate/clinit 是 native（被转译进 so）
       MainActivity / xiApplication  是纯 Java（未被转译）
```

## 2. 侦察拼图（每一步都是防御在付成本）

| 步骤 | 发现 | 耗时占比 | 是什么防御让我们多花时间 |
|---|---|---|---|
| dex 搜签名校验 | 6 个候选类逐一排除 → 全是系统库调用 | ~2 分钟 | （我方同样有此弯路，非增量） |
| so 导出符号 | **只有 `JNI_OnLoad` 一个** | ~2 分钟 | **RegisterNatives 动态注册**——静态搜不到任何 JNI 方法名 |
| 定位业务逻辑 | onCreate/clinit 被转译进 so（`YJ-Dex2C` 标记） | ~2 分钟 | **dex2c 转译**——逻辑不在 dex |
| 分析壳段 | `.yjaqvmp.text/.yjaqvmp/.yjaqvmp.sdk` 三段 284KB，64% 非可打印 | ~1.5 分钟 | **VMP 段加密** |
| 抽嵌套 ELF | `.so_protect.text` 开头是 `7f 45 4c 46`（嵌套完整 ELF），抽出 inner.so 但 section 头是乱的 | ~1 分钟 | **嵌套 ELF + 头抹除** |
| 识别攻击面 | `native onCreate` 的**声明**在 Java 层 → 可被顶掉 | 最后 | （防御盲区，见 §3） |

## 3. 破解过程：入口劫持（25 分钟）

**核心思路**：不碰 so（VMP/加密/反调试全都绕开），攻击 Java 层的**方法声明**。

```smali
原版（SplashActivity.smali）:
  .method public final native onCreate(Landroid/os/Bundle;)V   ← 逻辑全在 so 里

破解（改回 Java 空实现）:
  .method public final onCreate(Landroid/os/Bundle;)V
      invoke-super {p0, p1}, LN4/d;->onCreate(Landroid/os/Bundle;)V
      return-void
  .end method
  （同时删掉 clinit 里对 Loader;->registerNativesForClass 与
    Hidden0;->special_clinit_0_20 的调用 → 壳的初始化也被跳过）
```

**原理**：native 声明只是「绑定标记」。把声明改回普通方法，Java 侧再也不去 so 里找
实现——so 里那个被层层保护的校验函数**永远不会被调用**。不是攻破保险箱，是不给保险箱通电。

**实操坑（留档）**：
- apktool 回编后 `resources.arsc` 未 4 字节对齐 → 安装报 `-124`（R+ 要求 arsc stored+对齐）
  → `zipalign -f -p 4` 后签名即过（我们流水线已有此步骤，散装操作容易漏）
- 第一版空 onCreate 导致 App 存活但无主页 → 引出下一层的发现（§4）

## 4. 第二层发现：校验-业务耦合（他真正有效的防御）

空实现后 App「活着但进不去主页」。解包证据链：

```
SplashActivity.onCreate（native，在 so 里）= 校验 + 初始化 + 跳转 三合一
MainActivity / xiApplication          = 纯 Java，不依赖 native
```

攻击者面临的抉择：**要么把校验和业务一起删（App 不可用），要么全逆向 so**。
「只摘校验、保留业务」这条路被结构性堵死——这正是我方 APK 当时 3 分钟被完全破解的原因：
**我们的校验是独立模块，摘掉即绕过，业务照跑。**

第二版破解（跳过壳但保留跳转 MainActivity）App 能启动到桌面但业务仍不完整
（网络/初始化数据依赖被跳过的 native 启动逻辑）——再次印证耦合强度。

## 5. 源码还原为什么不可能（数学层面）

对 `.yjaqvmp` 段做了硬数据测量：

```
香农熵: 7.91 bits/byte（上限 8.0 = 纯随机）→ 统计上与强加密不可区分
8 字节块重复率: 3.6% → 无固定 stride 结构
解密器定位: 0x2a85c（双轮 XOR + 查 0x99000 密钥表）
密钥表现状: 静态包中为空 → 密钥运行时生成/下发 → 静态分析断头
解密产物: VMP 字节码（私有 VM 指令）→ 还需给私有 VM 写反编译器
```

三层叠加（强加密 → 密钥运行时 → VMP 字节码）使得**静态还原在任何意义上都不可能**。
这不是技术高低问题：加密数据不携带明文信息（香农），解不开就是解不开。
现实路径只剩运行时脱壳（root 环境下 hook 壳的解密点 dump 内存）——我方设备无 root，此路关闭。

## 6. 架构配方反推（指纹学成功案例）

「源码反推」不可行，但「架构反推」已经做到：

| 指纹 | 推断 |
|---|---|
| `libso_protect` / `SoProtectCheckPtraceSelf/TracerPid/NoNewPrivs/MmapFd/AllOrCrash` / `/data/local/tmp/so_protect.log` | **开源 so-protect 类反调试**（字符串全明文、实现极标准，未改名） |
| `yj/v3/pt` 包名 + `YJ-Dex2C` source 标记 + `registerNativesForClass(ILjava/lang/Class;)` | **dex2c 思路转译**（与我方工具同类） |
| `.yjaqvmp.text/.yjaqvmp/.yjaqvmp.sdk` + 熵 7.91 | **自研 VMP 引擎**（无开源指纹，真私有） |

**配方 = 开源反调试 + dex2c + 自研 VMP 三层拼装。**
想藏的（VMP）恰好藏住了，没打算藏的（反调试、dex2c）全是公开方案——
商业壳的护城河不在「藏住用了什么」，在「怎么实现」。

## 7. 对我方项目的启示（按可落地性排序）

### 7.1 我方仍领先的部分（这轮验证过的优势）

| 维度 | 他 | 我方 |
|---|---|---|
| 探针抗 hook | 走标准 libc（一个 LD_PRELOAD 全废） | **syscall 直调**（对照实验实证） |
| 反调试 | 标准 TracerPid/PtraceSelf | **PTRACE_TRACEME 抢占** + 同类探针 |
| 签名校验 | 单线（未实测其内部） | **双线 + watchdog 反制**（真机 signal 9 实证） |
| 检测特征泄露 | so_protect 字符串全明文 | **LSGS 密文化**（真机 so 零命中） |
| 体积 | 1.7MB（壳占大头） | ~43KB |

### 7.2 他领先我方、值得抄的部分

| 防御 | 他的效果 | 我方可落地方式 | 成本 |
|---|---|---|---|
| **RegisterNatives 动态注册** | 全 so 只导出 JNI_OnLoad，攻击者搜不到入口名 | `nc_link.c` 的 ncVerify/heartbeat 改为 JNI_OnLoad 里 RegisterNatives，导出面收缩到 1 符号 | **半天**（下个任务候选） |
| **校验-业务耦合** | 删校验 = 业务死，入口劫持无收益 | 注入器把校验调用与业务初始化绑进同一方法（需动 inject 路径，涉及冻结区边缘，需用户拍板） | 1-2 天 |
| **VMP** | 静态完全不可读（熵 7.91） | **不学**——数月工程，且本战报证明其入口仍在 Java 层可被劫持，收益/成本比差 | — |

### 7.3 教学要点（给下一任 AI / 复习用）

1. **保护了保险箱 ≠ 保护了电闸**。YJ 把校验函数保护到不可读，但「调用它」的声明在 Java
   层裸奔——入口劫持一发入魂。任何「逻辑在 native」的方案都要问一句：**触发它的入口在哪？**
2. **耦合是最便宜的强力防御**。校验+业务同生共死，攻击者「精确摘除」就变成「全有或全无」。
   我方方案的独立校验模块在这一点上是结构性弱点。
3. **熵是「能不能挖」的裁判**。7.91 bits/byte 直接宣判静态分析死刑——遇到高熵段别浪费时间，
   转向运行时路径（需要 root）或换攻击面。
4. **散装手工破解必踩 zipalign 坑**（arsc 对齐）。流水线的每一步自动化都在为这类事故兜底。
5. **他的反调试会写日志到 `/data/local/tmp/so_protect.log`**——自带调试后门路径。
   我方日志走哨兵开关（xixin_debug），默认关闭，设计上更干净。

## 8. 攻击产物位置（保留 / 清理待定）

```
.boss/                     本次攻防工作目录
  lib/arm64-v8a/…          原始 so 抽取
  dec/                     apktool 解包（含被改的 SplashActivity.smali + .bak）
  inner.so                 抽出的嵌套 ELF（加密态，section 头乱）
  cracked_final.apk        第一版破解（签名绕过，无主页）
  cracked2.apk             第二版（跳壳+保留跳转，业务仍不完整）
设备: 192.168.1.2:44675 当前安装的是第二版破解包
原版: /storage/emulated/0/常用/工作台😡/简盒_v1.0.2.apk
```
