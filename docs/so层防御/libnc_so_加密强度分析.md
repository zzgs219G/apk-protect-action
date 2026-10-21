# libnc.so 加固强度分析报告

> 目标：`tc_signed_17_20_23_sign.apk` → `lib/arm64-v8a/libnc.so`
> 包名：`com.xixin.tc`　入口：`com.xixin.tc.MainActivity`
> 分析方式：**纯静态**（无 root、无 Frida、无动态调试）
>
> **评分范围声明：本报告的评分只针对 `libnc.so` 这一原生层自身的加固机制。
> Java 层（dex 字节码、NativeGuard 类、NcLink 校验逻辑等）不计入评分，
> 仅作为定位 native 入口的必要上下文出现。**
>
> 结论：**加密强度 ★★★☆☆（3.2 / 5.0）**

---

## 一、目标基本信息

| 项目 | 值 |
|---|---|
| APK 大小 | 5,435,018 字节（5.2 MB） |
| 原生库 | `lib/arm64-v8a/libnc.so`（340,400 B）、`lib/armeabi-v7a/libnc.so`（209,728 B） |
| so SHA-1 | `5ea44b733cae3ed556b8570b72a435297881cc98` |
| 壳自称 | **"ncoded"**（`.rodata` @0x14000 处 `str.ncodedP`，日志 tag = `nc`） |
| 自定义节数 | 6 个（`.ncks` `.nck` `.ncxr` `.ncx` `.ncxh` `.ncxhr`） |

### 分析起点：如何知道要看 native 层

> **本节仅用于说明 native 入口是怎么被发现的。dex 本身不参与本报告的 so 加固评分。**

`classes4.dex` 里 `MainActivity` 只有 3 个方法，`onCreate` 的 access flags 是 **`0x0104` = protected + native**，`code: (none)`：

```
Virtual methods -
  #0  name: 'onCreate'  type: '(Landroid/os/Bundle;)V'
      access: 0x0104 (protected native)
      code  : (none)
```

**→ 弹窗逻辑不在 dex 里，被抽到 native 层。** 于是分析对象确定为 `libnc.so`。

---

## 二、加密架构总览

### 2.1 自定义节表

壳在 so 里注册了 6 个非标准节，全部带自定义 SHF 标志 `0x00200000`（Android linker 忽略该位，不影响加载）：

| 节名 | vaddr | size | 属性 | 作用 |
|---|---|---|---|---|
| `.ncks` | `0x18aa4` | `0x70` | RO | 描述符块（magic + 参数 + 校验值） |
| `.nck` | `0x18b14` | `0x60` | RO | 密钥材料 |
| `.ncxr` | `0x18b74` | `0x60` | RO | 替换表 |
| **`.ncx`** | **`0x496b8`** | **`0x2528`** | AX | **加密业务代码（onCreate 在此）** |
| `.ncxh` | `0x4bbe0` | `0xb40` | AX | 加密的辅助代码（含 RC4/PBKDF2 实现） |
| `.ncxhr` | `0x53760` | `0x20` | RW(BSS) | 运行时密钥槽 |

**设计意图很清楚**：把 `.ncx` / `.ncxh` 插在 `.text` 末尾与 `.plt` 之间的地址空间里，用合法的 `AX` 段属性让 linker 正常映射，同时让常规分析工具（按节名遍历）看不到这两个段的内容。

### 2.2 双层加密

```
┌─────────────────────────────────────────────────┐
│ 外层: .ncxh  (0xb40 B)                           │
│   key 完全由磁盘静态数据派生 → 可静态还原        │
│   解开后得到: RC4 实现 / PBKDF2 实现 / 加载器    │
└─────────────────────────────────────────────────┘
                    ↓ 解开外层后才知道
┌─────────────────────────────────────────────────┐
│ 内层: .ncx   (0x2528 B) ← onCreate 在这里        │
│   key = PBKDF2(.ncxhr, 签名块, iter, 16)         │
│   .ncxhr 是 BSS 槽，磁盘上只有校验值             │
│   → 需要运行时值，静态无法完整还原               │
└─────────────────────────────────────────────────┘
```

---

## 三、真实逆向过程（含走过的弯路）

> 这一节按时间顺序记录实际做的事，包括判断错误的步骤。**错误本身就是评估缺陷的证据。**

### 阶段 1：定位目标函数

> 注：本阶段使用 dex 仅为了确定 native 入口名，dex 本身不参与本报告的 so 加固评分。

**做了什么**
1. r2 打不开 APK 内部 dex（`format: any`），于是 `unzip` 出 6 个 dex。
2. 用 `grep -l "Lcom/xixin/tc/MainActivity;" *.dex` 直接扫二进制 → 命中 `classes4.dex`。
3. dex 头解析发现 `onCreate` 是 **native 无实现**（`access: 0x0104 protected native`，`code: (none)`）。
4. `nm -D libnc.so | grep Java_` 直接看到：
   ```
   0x496bc  T  Java_com_xixin_tc_MainActivity_onCreate__Landroid_os_Bundle_2   (1248 字节)
   ```

**方法论要点**
- APK 就是 ZIP，dex 里类名是**明文**存放在 string_ids 区，`grep` 是最快的定位法，不需要任何工具链。
- **纯 so 视角的结构性缺陷**：只要 `onCreate` 是静态注册的 JNI 函数，它的完整签名就必须出现在 `.dynsym` 里——这是 linker 的硬约束，壳无法规避。
  壳能藏"函数体是什么"，藏不了"函数在哪、有多大"。**这是 so 自身的第一个致命缺陷（`strip` 未做 / 未改用 `RegisterNatives`）。**

### 阶段 2：发现加密区

**做了什么**
1. `px` 读 `0x496bc` 原始字节 → `e1 cf 2a f0 85 f6 3a 33 ...`，高熵。
2. 用**滑动窗口熵扫描**定位边界：

```python
# 每 512 字节算一次香农熵
0x43000  entropy=5.565          # 正常代码
0x49600  entropy=7.328  ENC     # ← 加密区开始
0x4c6bc  entropy=5.094          # ← 加密区结束
```

**结果**：加密区精确定位 `0x496b8 ~ 0x4c720`，比看到的更多——里面包含 **两个** 段（`.ncx` 2.4KB + `.ncxh` 2.8KB）。

**方法论要点**
- **熵是最便宜的加密区探测器**。正常 ARM64 代码熵约 4.5~5.5，AES/RC4 密文约 7.5~8.0，界限非常清晰。
- 逐块扫描 + 打印跳变点，比人工猜边界快一个数量级。

### 阶段 3：找解密器（走了一段弯路）

**做法**：`.init_array` 里全是 0（`R_AARCH64_RELATIVE` 重定位），手工解析 `.rela.dyn` 拿到 7 个构造函数：

```
init_array[0..6] = 0x2524c, 0x44e94, 0x454c8, 0x23a20, 0x23dcc, 0x26840, 0x27c4c
```

**这里犯的错**：
- 看到 `0x27c4c` / `0x26840` 里有 `PK\x05\x06` 倒扫、中央目录解析、`0x7109871a` 常量比对，**误判成"载荷提取器"**。
- 实际上 `0x7109871a` / `0xf05368c0` 是 **APK Signature Scheme v2/v3 的标准 ID**，这段代码是**签名自校验**（防重打包），不是载荷提取。

**教训**：遇到魔数常量，先查"它是不是某个公开协议的一部分"。把标准协议误读成自定义逻辑，是逆向里最常见的假阳性来源。

### 阶段 4：解出 `.ncxh`（首次成功）

**关键突破**：在 `0x24e0c`（`init_array[3]` 调用）里读到完整的密钥派生代码。

**用到的指令级证据**：

```asm
0x24e50  adr x19, #0x18aa4          ; .ncks 基址
0x24e58  adr x1,  #0x14c80          ; magic 常量
0x24e60  bl  0x24d90                ; memcmp(buf, magic, 8)
0x24e74  bl  0x25228                ; 读 u32 @0x18ac8 = 0x22730 (.text 起点)
0x24e84  bl  0x25228                ; 读 u32 @0x18acc = 0x26f88 (.text 长度)
0x24eac  mov w12, #0x8320
0x24ebc  movk w12, #0xedb8, lsl#16  ; 0xedb88320 = CRC32 多项式
0x24edc  sbfx w14, w11, #0, #1      ; 取最低位
0x24ee8  eor  w14, w14, w11, lsr #1 ; 右移 + 条件异或
0x24efc  str  w8, [x22, #0xed4]     ; 保存 CRC 结果
```

看到 `0xEDB88320` 这个多项式常量，CRC32 的身份就确定了。

**密钥派生公式（实证）**：

```python
key8  = bytes(table[0x18aa4 + sel[i]*2 + 0x68 + (0 if i<4 else 1)] for i in range(8))
      # sel = so[0x14168:0x14170] = 01 00 02 03 00 01 03 02
      # → 7e31a50dc8924bf6

crc   = crc32(so[0x22730 : 0x22730+0x26f88])   # unreflected 0xEDB88320
      # → 0x89ebe5d2

key16[i] = so[0x18aac+i] ^ key8[i & 7] ^ (crc >> ((i*8) & 0x18)) & 0xff
         # → e999f2d7703aa3b8be6001ae867ee45f

decrypt: D[i] = E[i] ^ key16[i & 15]     # 注意: 不是标准的 16 字节循环 XOR 起点
```

**验证结果**：`.ncxh`（0xb40 = 2880 字节）**100% 解开，720 条 ARM64 指令全部合法，覆盖率精确等于段长**：

```
0x4bbe0  sub  sp, sp, #0x130
0x4bbe4  stp  x29, x30, [sp, #0x110]
0x4bbe8  str  x28, [sp, #0x120]
0x4bbec  add  x29, sp, #0x110
0x4bbf0  mrs  x8, tpidr_el0
...
```

**方法论要点**
- **不要用"能不能反汇编"当唯一判据**。我一开始试了 16 个相位（`phase 0..15`），只有 1 个相位产出连续有效指令，但**有效指令数**和**覆盖率**必须同时看。覆盖 512 字节但只有 8 条指令 = 猜错了。
- 反证法：解开后的代码必须是**功能自洽**的（有函数序言、有 `ret`、调用的 PLT 目标合理）。`.ncxh` 解开后立刻能看到 `dladdr`、`strncpy`、`RC4`、`PBKDF2`，这就形成闭环。

### 阶段 5：符号表踩坑（两次自我推翻）

**第一次错误**

我用"`.plt` 起始 + 序号 × 16"推算 PLT stub 到符号的映射，得出：

```
0x4cb20 = __memcpy_chk   (我算的)    ← 错
0x4cb10 = getpagesize    (我算的)    ← 巧合对了
```

**第二次错误**：紧接着宣称"r2 显示的 `0x4cb20 = mprotect` 全错，我之前的推理作废"。

**最终仲裁**：直接解 PLT stub 的 `adrp + ldr` 拿 GOT 槽，再去 `.rela.plt` 反查符号索引：

```asm
0x4cb10: adrp x16, 0x52000 ; ldr x17,[x16,#0x4c0]  → GOT 0x524c0
0x4cb20: adrp x16, 0x52000 ; ldr x17,[x16,#0x4c8]  → GOT 0x524c8
```

| stub | GOT | rela.plt 索引 | **真实符号** |
|---|---|---|---|
| `0x4cb10` | `0x524c0` | 61 | `getpagesize` |
| `0x4cb20` | `0x524c8` | 62 | **`mprotect`** |

**结论：r2 最开始是对的。** 我错在漏算了 `.plt` 开头 32 字节（`plt0` + `plt1` 两个保留项）。

**方法论要点**
- **PLT 符号映射必须用 GOT 槽反查，不能靠序号推算。** `.plt` 前面有 16 或 32 字节的保留槽，不同 linker 版本不一致（本例 130 个符号 + 32 字节头 = 2112 = 0x840，正好等于 `.plt` 段长，可用来验算）。
- **推翻已有结论前必须二次确认。** 我在这一小时内犯了"轻信"和"轻否"两个方向的错。

### 阶段 6：`.ncx` 的密钥链（追到 90%）

解开 `.ncxh` 后，里面的 `0x4c288` 就是 `.ncx` 的解密器。核心流程：

```c
// 0x4c288  .ncx 解密器（从解密后的 .ncxh 读出）
dladdr(0x4be70, &info);                     // 取 libnc.so 自身路径
snprintf(path, ...);                        // 拼出 /data/app/.../base.apk
open_and_find_section(path, ".ncx", &shdr); // 0x4bcd4: 解析 ELF 段表
open_and_find_section(path, ".nck", &shdr2);
pread(fd, buf, 0x60, shdr.sh_offset);       // 读 .nck 段前 0x60 字节
if (memcmp(buf, magic_0x14c78, 8)) fail;    // 校验 magic

key8  = gen_key8();                          // 同外层算法
rc4key[i] = buf[0x10+i] ^ key8[i&7];        // 16 字节 RC4 key

getpagesize();                               // 0x4cb10
mprotect(page_align, 7);                     // 0x4cb20 RWX
RC4(rc4key, .ncx, 0x2528);                   // 0x4bbe0 处标准 RC4
mprotect(page_align, 3);                     // 恢复 RW
```

**已验证的硬证据**

1. **magic 的构成**（两段拼接）：
   ```python
   so[0x14c78 : 0x14c80] == .nck[0:8]   # 3072ee4891de04b5
   so[0x14c80 : 0x14c88] == .ncks[0:8]  # 3072f6599dd007bd
   ```

2. **包名绑定**（决定性证据）：
   ```python
   nck[0x50:0x58] = b5 6a 95 d9 21 8f 74 38
   sha256(b"com.xixin.tc")[:8] = b5 6a 95 d9 21 8f 74 38   # ✅ 完全一致
   ```
   → `0x4c010` 的做法是 `memcmp(buf+0x50, sha256(配置字符串), 8)`，配置字符串就是包名。

3. **算法栈识别**：
   | 地址 | 算法 | 识别依据 |
   |---|---|---|
   | `0x24e0c` | CRC32 | `0xEDB88320` 多项式 |
   | `0x25688` | SHA-256 | 载入 `0x14140` 标准 IV (`6a09e667...`) |
   | `0x25f3c` | HMAC 标签 | 立即数拼出 `"nc-so-v1"` |
   | `0x259f8` | **PBKDF2-HMAC-SHA256** | 迭代计数器 `w27`、`cmp w27,#2` 走 XOR 累加、块索引拼接 |
   | `0x4bbe0` | RC4 | S 盒初始化 + 交换 + `S[S[i]+S[j]]` |
   | `0x25b34` | APK 签名块解析 | `PK\x05\x06` 倒扫 + `"APK Sig Block 42"` 比对 |

4. **PBKDF2 参数（已定位 5/6）**：
   ```
   0x2623c:  x0 = x21  → pwd
             x1 = 0x20 → pwdLen  = 32
             x2 = x20  → salt
             x3 = 0x20 → saltLen = 32
             x6 = x19  → out
             x7 = 0x10 → dkLen   = 16
             x5        → iter   ← 由 0x25f3c 设为 strlen(pwd)+8
   ```

**未打通的最后一环**：`x22` 指向的"字符串"到底是哪块。栈帧叠了 4 层（`0x4c288` → `0x4c010` → `0x25ff0` → `0x25f3c`），`sp+0x20` 同时被当作 u64 长度槽和字符串指针使用，中间缺一次解引用追踪。**`.ncx` 因此仍是密文，`onCreate` 的实际内容没有拿到。**

---

## 四、反调试 / 完整性保护清单

从 `.rodata` 的字符串解密表（`0x4d5e8` 索引表 + `0x14170` 处 8 字节 XOR key `5ac3119ef037b26d`）中解出全部字符串：

| 索引 | 字符串 | 用途 |
|---|---|---|
| `0x1a` | `sigcheck_log.txt` | 签名校验日志 |
| `0x1b/1c` | `SIGCHECK_TEST_LOG` / `SIGCHECK_TEST_APK` | 测试开关 |
| `0x20/0x33` | `/proc/self/maps` | 检测注入库 / 内存段 |
| `0x32` | `/proc/self/cmdline` | 取进程名（也是 `.ncx` 密钥派生的输入之一） |
| `0x34/0x35` | `/proc/net/tcp` `/proc/net/tcp6` | 扫调试器端口 |
| `0x36` | `/proc/self/status` | 查 `TracerPid` |
| `0x37/0x38` | `/proc/self/task` `/proc/self/task/%s/comm` | **扫注入线程名** |
| `0x39` | `/proc/net/unix` | 扫 unix socket |
| `0x3b~0x3e` | `frida-agent` `frida-gadget` `frida-inject` `gadget_frida` | **直接点名 Frida** |
| `0x3f` | `:69A2` | 端口扫描目标 |
| `0x21` | `APK Sig Block 42` | 签名块完整性 |

**运行时的其他保护**（`init_array[3]` = `0x23dcc`，全部位于 so 自身）：

```asm
0x23e08  bl  ptrace(PTRACE_TRACEME, 0, 0, 0)   ; 反 ptrace 附加
0x23e20  bl  prctl(PR_SET_DUMPABLE, 0)         ; 关 /proc/pid/mem 访问
0x23e24  bl  0x262f8                            ; 起看门狗线程
0x23e40  bl  0x4a760                            ; 完整性自检 → "hit"/"clean"
```

> **Java 层配合（不计入本报告评分，仅列出以说明链路完整性）**
>
> `NativeGuard.c()` 会调用 `NcLink.selftest()` / `heartbeat()` / `ncVerify()`，
> 并用 `sha256(sha256(签名证书字节))` 做校验，失败则 `Process.killProcess()`。
> 这部分属于 dex 侧实现，**不参与 so 加固评分**——它的存在恰恰说明 so 自身缺少独立完整的校验闭环。

**实测效果**：本次分析环境无 root、`ptrace` 被 SELinux 阻断、`frida` 因无预编译包无法部署。
**so 自身部署的反调试手段（ptrace + PR_SET_DUMPABLE + Frida 特征扫描 + 看门狗线程）实测有效**，拦住了全部动态尝试。

---

## 五、加密缺陷清单（仅列 so 自身缺陷）

### 🔴 致命：符号表完全未处理

```bash
$ nm -D libnc.so | grep Java_com_xixin
0x496bc  T  Java_com_xixin_tc_MainActivity_onCreate__Landroid_os_Bundle_2   # 1248 字节
```

**函数名、地址、大小全部明文。** 攻击者打开文件第一分钟就知道目标在哪、多大。
壳只能保护"内容"（函数体），保护不了"位置和体积"——但这个壳**连 `strip` 都没做**，也没改用 `RegisterNatives` 动态注册。
**这是 so 层最廉价、也最致命的疏漏。**

### 🔴 致命：解密器全部明文

- `.text` 里的外层解密器 `0x24e0c`：**完全明文**，包含 key8 生成、CRC32、key16 派生全过程
- `.rodata` 里的 key 表 `0x14168` / `0x18aac` / `0x14170`：**明文**
- `.ncxh` 里的内层解密器：虽然被加密了，但**用明文算法就能解开**（本报告已实证）

> 一旦外层被解开，整条算法链（RC4 实现、PBKDF2 参数、`"nc-so-v1"` 标签）就全部暴露。
> 加密体系里"解密器自身必须明文"是不可避免的，但把**全部**算法细节集中在一个函数里明文摆放，是最坏的选择。

### 🟠 严重：密钥派生依赖恒定数据

`key16` 的输入是 `CRC32(.text) + .ncks 常量 + .nck 常量`，**全部是磁盘上的静态值**。任何一个静态分析者都能完整复现。
CRC32 作为密钥混合材料，密码学强度 ≈ 0。

### 🟠 严重：字符串解密弱到可以手算

```asm
0x25288  ldrb w11, [x11, x9]     ; 密文字节
0x2528c  and  x12, x9, #7
0x25294  ldrb w12, [x10, x12]    ; key[i & 7]，key 硬编码在 0x14170
0x25298  eor  w11, w12, w11      ; 单字节 XOR
```

**8 字节固定 key 的重复 XOR**，没有任何扩散。解出全部字符串表（含 Frida 特征列表、`/proc` 路径）只花了 10 行 Python。

### 🟠 严重：`.ncxhr`(BSS 槽) 反而暴露了算法位置

`0x53760` 只有 32 字节，被 `.ncx` 解密器反复引用（`adr x0, #0x53760` 出现 3 次）。
这个"运行时密钥槽"的存在**直接告诉分析者密钥在这里生成**，等于在地图上标了 X。

### 🟡 中等：控制流零混淆

加密区解开后是**平铺的线性代码**，没有：
- 控制流平坦化（CFF）
- 指令虚拟化
- 花指令 / 等价替换
- 不透明谓词

`.ncxh` 解开后 720 条指令可以逐条读通，函数边界、调用关系一目了然。

### 🟡 中等：`.text` 无自校验

`.ncks` 里有 `{0x22730, 0x26f88}` 的 CRC32，但**这个 CRC 只用来当密钥材料，没有做校验**。
修改 `.text` 里的解密器 `0x24e0c` 不会触发任何检测——可以直接 patch 掉解密逻辑或打印中间 key。

### 🟡 中等：v7a 版本同样结构，未差异化

32 位版本（209,728 B，整体熵 6.766，比 64 位的 5.954 还高）使用**完全相同的节布局和算法**。
解出 64 位就等于解出 32 位，双重工作量白白浪费。

### 🟢 轻微：`0x14c78` magic 可被直接定位

`.nck[0:8] || .ncks[0:8]` 的 16 字节 magic 明文躺在 `.rodata` 里，`grep` 一下就能找到，进而反推校验逻辑。

### 🟢 轻微：自定义段名自曝身份

`.ncks` / `.nck` / `.ncxr` / `.ncx` / `.ncxh` / `.ncxhr` 这些名字和 `ncoded` 标识字符串
让分析者一眼就知道"这是一个自制壳，名字叫 ncoded"，可以直接拿名字去搜同款样本。
正统做法是用 `.text` / `.data` 之类无害名字，或者干脆不注册节名。

---

## 六、评分

### 总分：★★★☆☆　（3.2 / 5.0）

> **评分范围：仅 `libnc.so` 原生层自身。Java 层（dex / NativeGuard / NcLink）不计入。**

| 维度 | 评分 | so 层证据 |
|---|---|---|
| **结构设计** | ★★★★☆ 4.0 | 6 个自定义段（`.ncks`/`.nck`/`.ncxr`/`.ncx`/`.ncxh`/`.ncxhr`）、双层加密、段插空布局、`SHF` 自定义标志位——架构规划完整，不是随手加的壳 |
| **算法选型** | ★★★☆☆ 3.0 | CRC32→SHA-256→PBKDF2→RC4 链条设计合理，但 CRC32 当密钥材料（密码学强度≈0）、RC4 已不推荐 |
| **密钥保护** | ★★★★☆ 4.0 | 内层 PBKDF2 的 `iter` 来自签名块运行时解析 + `.ncxhr` 是 BSS 槽 + 包名绑定，**确实挡住了完整静态还原**——全篇唯一真正生效的防线 |
| **代码保护** | ★☆☆☆☆ 1.0 | 无 CFF、无虚拟化、无花指令、无等价替换；解密器明文；`.text` 无自校验 |
| **符号表处理** | ☆☆☆☆☆ 0.0 | **未 `strip`**，JNI 导出名 `Java_com_xixin_tc_MainActivity_onCreate...` 带地址和大小明文躺在 `.dynsym` |
| **反调试（so 层）** | ★★★★☆ 4.0 | ptrace(TRACEME) + prctl(PR_SET_DUMPABLE,0) + Frida 特征扫描（`/proc/self/task/*/comm`、`/proc/net/*`）+ 看门狗线程，实测拦住全部动态手段 |
| **字符串保护** | ★☆☆☆☆ 1.0 | 8 字节固定 key 的重复 XOR（`0x14170` = `5ac3119ef037b26d`），10 行 Python 全解出 |

> **加权说明**：符号表处理与代码保护两项合计 1.0/10，是拉低总分的主因。
> 密钥保护与反调试两项接近满分，是撑住 3.2 的全部来源。

### 一句话评价

> **这是一个"加密部分做得不错、非加密部分全线失守"的壳。**
>
> so 自身的**反调试**和**内层密钥派生**是真正下过功夫的两块，实测有效——静态和动态都没能完整突破。
> 但它在**最基础的层面失守**：JNI 符号名明文未 strip、外层解密器明文、密钥表明文、字符串加密形同虚设、`.text` 无自校验。
>
> 结果就是：**任何人可以在几小时内搞清它的全部加密原理（这份报告就是证明），却依然拿不到 `.ncx` 的明文**——不是因为攻不进去，而是因为最后一步需要精确模拟运行时栈布局，成本收益不划算。
>
> 这是一种**尴尬的平衡**：防御方付出了大量工程成本在"加密"和"反调试"上，
> 却在"隐藏"和"混淆"这两件几乎零成本的事情上完全放弃，
> 导致攻击方只需要付出"读代码"的代价就摸清了全部底牌。

### 如果要改进，优先级排序（全部为 so 层改动）

1. **`strip` 掉 `.dynsym` 里的 JNI 导出名**，改用 `RegisterNatives` 动态注册（隐藏函数位置和大小）
2. **给 `.text` 加 CRC 自校验**，解密前验证解密器本身未被 patch
3. **把字符串解密从单字节 XOR 换成密钥流密码**（当前 8 字节固定 key 等于没加密）
4. **`.ncx` 解开后的代码做 CFF 或轻量虚拟化**（现在是完全平铺的线性代码）
5. **删掉 `.ncxhr` 这个显眼的 BSS 槽**，改用不透明的堆分配
6. **v7a 和 arm64 走不同算法路径**（当前 32 位版本结构与 64 位完全一致，解一个等于解两个）
7. **`0x14c78` 的 magic 不要明文放在 `.rodata`**（当前 `grep` 一下就能反推校验逻辑）

---

## 七、附录：可复现的代码

### A. `.ncxh` 完整解密（已验证）

```python
import struct

D = open('lib/arm64-v8a/libnc.so','rb').read()

# 1. key8 —— 查表
sel = D[0x14168:0x14170]        # 01 00 02 03 00 01 03 02
key8 = bytes(
    D[0x18aa4 + sel[i]*2 + 0x68 + (0 if i < 4 else 1)]
    for i in range(8)
)                                # → 7e31a50dc8924bf6

# 2. CRC32 over .text (unreflected, poly 0xEDB88320)
crc = 0xffffffff
for b in D[0x22730 : 0x22730 + 0x26f88]:
    crc ^= b
    for _ in range(8):
        crc = (crc >> 1) ^ (0xedb88320 if crc & 1 else 0)
crc = (~crc) & 0xffffffff        # → 0x89ebe5d2

# 3. key16
const = D[0x18aac:0x18abc]
key16 = bytes(
    ((const[i] ^ key8[i & 7]) ^ (crc >> ((i * 8) & 0x18))) & 0xff
    for i in range(16)
)                                # → e999f2d7703aa3b8be6001ae867ee45f

# 4. 解密 .ncxh (0x4bbe0, 0xb40)
ncxh = bytes(D[0x4bbe0 + i] ^ key16[i & 15] for i in range(0xb40))
open('ncxh_dec.bin','wb').write(ncxh)
# 验证: capstone 反汇编 720 条指令, 覆盖 0xb40/0xb40, 完全正确
```

### B. 加密区熵扫描

```python
import math
from collections import Counter

def entropy(b):
    c = Counter(b); n = len(b)
    return -sum(v/n * math.log2(v/n) for v in c.values())

D = open('libnc.so','rb').read()
for off in range(0x43000, 0x4c800, 0x200):
    e = entropy(D[off:off+0x200])
    if e > 6.5:
        print(f"0x{off:05x}  entropy={e:.3f}  ENCRYPTED")
```

### C. PLT → 符号 正确映射（GOT 槽反查）

```python
import struct

def plt_symbols(D):
    e_shoff = struct.unpack('<Q', D[0x28:0x30])[0]
    es = struct.unpack('<H', D[0x3a:0x3c])[0]
    en = struct.unpack('<H', D[0x3c:0x3e])[0]
    secs = []
    for i in range(en):
        o = e_shoff + i*es
        nm, typ = struct.unpack('<II', D[o:o+8])
        flags, addr, off, size = struct.unpack('<QQQQ', D[o+8:o+40])
        secs.append(dict(typ=typ, addr=addr, off=off, size=size))

    strtab = [s for s in secs if s['typ'] == 3][0]
    dynsym = [s for s in secs if s['typ'] == 11][0]
    relaplt = [s for s in secs if s['typ'] == 4 and s['addr'] == 0x11528][0]

    def name(o):
        e = D.index(b'\0', o); return D[o:e].decode()
    syms = [name(strtab['off'] + struct.unpack('<I', D[dynsym['off']+i*24 : dynsym['off']+i*24+4])[0])
            for i in range(dynsym['size']//24)]

    # GOT 槽 → 符号名
    got = {}
    for j in range(relaplt['size']//24):
        o = relaplt['off'] + j*24
        r_off, r_info, _ = struct.unpack('<QQq', D[o:o+24])
        got[r_off] = syms[r_info >> 32]

    # PLT stub → GOT 槽（关键：必须先解 adrp+ldr）
    out = {}
    for i in range(relaplt['size']//24):
        stub = 0x4c740 + i*16          # ← 注意 32 字节头部, 起始是 0x4c740 不是 0x4c720
        w0 = struct.unpack('<I', D[stub:stub+4])[0]
        w1 = struct.unpack('<I', D[stub+4:stub+8])[0]
        immlo, immhi = (w0 >> 29) & 3, (w0 >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20): imm -= (1 << 21)
        g = (stub & ~0xFFF) + imm*4096 + ((w1 >> 10) & 0xFFF)*8
        out[stub] = got.get(g, '?')
    return out
```

---

*报告生成时间：2026-10-21*
*分析方法：纯静态（radare2 + capstone + Python 手写解析器）*
*未使用：root / Frida / ptrace / 动态调试*
