# 简盒 SO 层防御实测报告（静态 + 实战）

> **本文是 so 层防御的唯一定稿。** 2026-10-19 起，原 02~07 号文档（含 06b）已删除，
> 其结论要么错误、要么被本文推翻。仓库中不再保留那些文档的任何副本。
>
> **本文的判断基准**：二进制实测 + 真机实测 + 源码核对。三者冲突时以**实测**为准。
> 任何既有文档的说法都不作为依据——包括本文的早期版本。
>
> - 被测样本：`简盒_signed_23_59_49_sign.apk`
> - SHA-256：`9a82f0e209f96eb2878f17f22d1b9331d12e7686995e1908df299f8a7897745f`
> - 分析环境：Termux aarch64 / LLVM 18.0.4 工具链
> - 真机环境：Redmi 2602BRT18C / Android 16（API 36）/ arm64-v8a
> - 机读二进制：`lib/arm64-v8a/libnc.so`（348,128 B）
>
> ## 结论速览
>
> | 项 | 结果 |
> |---|---|
> | 盲测定位签名校验核心 | **4 分 1 秒** |
> | 完整离线破解（解密两段 + 反推算法） | **约 40 分钟** |
> | 从零到产出可在真机运行的绕过包 | **约 70 分钟** |
> | **静态防御综合评分** | **★★☆☆☆ 2.5 / 10** |
> | **实战（真机验证）评分** | **★☆☆☆☆ 1.5 / 10** |
> | 最致命缺陷 | ① `master[32]` 全是 `0x11`；② 真正判定算法不在加密段；③ kill 链全走 PLT 软目标 |
>
> **一句话结论**：签名校验逻辑本身写对了、也真的检出了，但**杀掉进程的手段全部集中在
> `abort` / `_exit` / `raise` 三个 PLT 表项上**——改 4 个字节，30+ 个调用点全废。
> 最终产物在同签名校验全开的情况下，**稳定运行在前台，无崩溃、无 ANR**。
>
> **本文分两部分**：
> - **第一部（§0–§9）静态分析**：只读逆向，全程不运行，不修改 APK
> - **第二部（§10–§13）实战修改**：真机 patch + 重打包 + 重签名 + 运行验证

---

## 0. 操作边界与可复现路径

工作目录集中在 `~/jianhe_re_work/`：

```
jianhe_re_work/
├── target.apk              # 原 APK 副本（原文件未被修改）
├── T0_start.txt            # 计时起点 2026-10-19 00:52:28
├── probe_ncguard.py        # 离线解密验证脚本
├── ncguard_dec.bin         # 解密后的 .ncguard（32,540 B）
├── libnc_unlocked.so       # .ncguard 已被明文替换的 so（用于反汇编）
├── backup_docs/            # 已删除的 02~07 号文档备份（仅本地，仓库无）
└── ex/                     # 解包工作区
    ├── classes.dex                     7,083,500 B
    ├── lib/arm64-v8a/libnc.so            348,128 B
    └── lib/armeabi-v7a/libnc.so          214,644 B
```

原 APK 仅做过一次 `cp` 读取，未被改动。

---

## 1. 时间线

| 阶段 | 起止 | 耗时 | 产出 |
|---|---|---|---|
| 盲测定位（不知源码） | 00:52:28 → 00:56:29 | **4 分 1 秒** | 找到签名校验核心逻辑 |
| 源码核对 | — | ~25 分钟 | 确认 `master` 占位符、诱饵机制 |
| 离线解密 `.ncguard` | — | ~8 分钟 | 32,540 B 明文 |
| 反推校验算法 | — | ~5 分钟 | 通过校验所需的 32 字节输入 |
| **合计** | | **约 40 分钟** | 完整攻破 |

「4 分 1 秒」这个数字的含义要说清楚：它只统计到**找到关键逻辑**。
完整攻破是 40 分钟。两者都重要——前者衡量防御能否拖住「快速试探」，后者衡量能否拖住「认真破解」。

---

## 2. 防御逐条实测

按实际发现顺序编号，与当次汇报一一对应。

### #0 自定义节布局实名暴露

`readelf -SW lib/arm64-v8a/libnc.so`：

| 节 | 地址 | 大小 | 属性 | 实际含义 |
|---|---|---|---|---|
| `.nckey_stub` | 0x16634 | 0x60 (96B) | `AR` | stub 的密钥槽 |
| `.nckey` | 0x16694 | 0x60 (96B) | `AR` | so 的密钥槽（含诱饵） |
| `.ncguard` | 0x46ac8 | 0x7F1C (32,540B) | `AXR` | 加密代码段 |
| `.ncguard_head` | 0x4e9e4 | 0xA28 (2,600B) | `AXR` | 二级锁箱（unlock 本体） |
| `.text` | 0x1ffe0 | 0x26AE8 (158,440B) | `AX` | 明文代码 |
| `.bss` | 0x565d0 | 0x23AD8 (146,136B) | NOBITS | 运行时缓冲 |

**对照实验**（同 APK 另外两个 so）：

```
libxcrash.so:                  .plt .text .rodata .eh_frame_hdr .eh_frame
                               .note.android.ident .fini_array .data.rel.ro
                               .dynamic .got .data .bss .comment .shstrtab

libandroidx.graphics.path.so:  .rela.dyn .rela.plt .rodata .eh_frame_hdr
                               .eh_frame .text .plt .data.rel.ro .fini_array
                               .dynamic .got.plt .bss .comment .shstrtab
```

**同 APK 其他 so 一个自定义节都没有**，全是 NDK 标准节。`libnc.so` 独有 4 个非标准节，名字全是自解释英文。

源码注释（`so-section-lock.py:46`）写：

```python
SECTION_NAME = '.ncguard'   # 加密代码段（Xop 用 .bitcode，改名避开指纹）
```

**「改名避开指纹」这个目的没有达到。** 换个角度想：Xop 用 `.bitcode` 能躲，是因为 `.bitcode` 是 LLVM 的标准节名，混在正常产物里不显眼；`.ncguard` 恰好相反——任何见过 Android so 的人都知道 `.ncguard` 不是标准节。改了一个「明显不像标准」的名字，比不改更容易被注意到。

**正确做法**：让节名混入标准集合（`.rodata`、`.data.rel.ro`），或 `objcopy --rename-section .ncguard=.rodata` 合并进只读段，运行时靠 `mprotect` 补执行权限（`mprotect` 本来就已导入）。

---

### #1 导入符号表完整暴露防御清单

`nm -D --undefined-only` 筛出的敏感符号：

| 符号 | 暴露的防御意图 |
|---|---|
| `ptrace` | 反调试 |
| `dl_iterate_phdr` | 遍历已加载模块 → 检测 frida / xposed |
| `open` / `fopen` / `opendir` / `readdir` | 读 APK、扫 `/proc/self/maps`、扫目录 |
| `fstat` / `access` | 文件状态 / 完整性 |
| `mprotect` | 运行时改段权限 |
| `syscall` | 直接系统调用，绕过 libc hook |
| `pthread_create` / `pthread_once` | 独立校验线程 |
| `__open_2` / `__read_chk` | 带 FORTIFY 的读写 |

**不反汇编一行代码，防御清单已经公开。** `.dynstr` 未抹除、未加密。

---

### #2 `.comment` 泄漏编译器指纹

```
Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4
Linker: LLD 18.0.4
```

`.note.gnu.build-id`：`b6aa57b4a65f9f712adc9e12ae573b5f975d7ea4`

build-id 是原始构建的稳定指纹。改了字节但 build-id 对不上，就能判定被 patch 过。

---

### #3 `.ncguard` 段确实加密（但见 §4 的破解）

```
000000000004e8c4 <Java_com_nc_link_NcLink_ncVerify>:
   4e8c4: 702da388     	adr	x8, 0xa9d37
   4e8c8: 7b561c36     	<unknown>
   4e8cc: 595d0820     	<unknown>
   4e8d0: 0d564a85     	<unknown>
   ...
```

仅首条指令合法，后续全部 `<unknown>`。**加密本身有效**，静态反汇编直接失败。

**但注意**：这只说明「我没有立刻读出明文」，不说明「读不出来」。见 §4。

---

### #4 错误日志字符串把防御架构完整泄底

`.rodata` 明文，一条未加密，且不是零散泄漏，是完整算法决策树：

```
10d96  /proc/self/status
10dc6  opendir /data/app failed: errno=%d
10edf  /proc/self/maps
10eef  base.apk
10fff  /base.apk
11009  open apk failed: %s errno=%d(%s)
1102a  APK Sig Block 42
11140  maps candidate not accessible: %s errno=%d
11436  maps has no base.apk!/...so line, try lib-path fallback
1146e  /proc/self/root%s/base.apk
11489  /data/app
1152c  %s/%s/base.apk
11667  Couldn't find field "%s" with signature "%s"
116c0  apk path from maps: %s
118c2  /proc/net/tcp
11b00  /proc/net/tcp6
11c58  apk path from so dir: %s
1205c  /proc/net/unix
121a9  data/app scan exhausted: no <pkg>*/base.apk accessible
123ba  /proc/self/cmdline
124b6  fopen /proc/self/maps failed: errno=%d
126cc  %s/base.apk
1282a  /data/app/%s
12a51  /proc/%d/root%s
12eb3  /proc/self/task
12edd  read /proc/self/cmdline failed: errno=%d
1300d  cannot resolve self so path (dladdr+maps both empty)
13042  apk path from data/app: %s
1317f  /proc/self/task/%s/comm
149e0  APK Sig Block 42
```

由此反推完整防御架构：

1. **反调试**：读 `/proc/self/status` 找 `TracerPid`
2. **反注入**：`/proc/self/maps` 找 frida/xposed
3. **反双开/虚拟机**：`/proc/net/tcp`、`/proc/net/tcp6`、`/proc/net/unix`、`/proc/self/cmdline`
4. **线程级反调试**：遍历 `/proc/self/task/*/comm`
5. **APK 定位四级 fallback**：maps → so 目录 → data/app 扫描 → dladdr
6. **签名校验**：直接解析 `APK Sig Block 42`，不走 `PackageManager`
7. **反射**：`Couldn't find field "%s" with signature "%s"`

第 6 条设计正确——直接读 v2 签名块使 hook `PackageManager` 失效。但 `APK Sig Block 42` 明文字符串躺在 `.rodata`，等于告诉了攻击者从哪儿下手。

---

### #5 `.nckey` 存在明文段表描述符

`.nckey_stub`（0x16634，96B）第 28 字节起是一段小端 32 位整数：

```
01664c  34 66 01 00  → 0x00016634 = 91700    ← .nckey_stub 自身偏移
016650  e4 e9 04 00  → 0x0004e9e4 = 321508   ← .ncguard_head 偏移
016654  28 0a 00 00  → 0x00000a28 = 2600     ← .ncguard_head size
016658  e0 ff 01 00  → 0x0001ffe0 = 131040   ← .text 偏移
01665c  e8 6a 02 00  → 0x00026ae8 = 158440   ← .text size
```

**明文段表描述符**：`{self_offset, guard_head_offset, guard_head_size, text_offset, text_size}`。加密器的元数据原封不动写进了二进制。

两个槽都以固定魔数 `30 72` 开头（见 §6.3），固定 96 字节，相邻偏移。**定位成本 = 0。**

---

### #6 加密覆盖错位——判定分支留在明文段

| 段 | 状态 | 反汇编 |
|---|---|---|
| `.text`（158KB） | 明文 | `JNI_OnLoad`、`selftest` 标准可读 AArch64 |
| `.ncguard`（32KB） | 加密 | `ncVerify` 等 JNI 入口全是 `<unknown>` |

`JNI_OnLoad`（0x20570，明文）含标准栈金丝雀序言：

```asm
20570: sub  sp, sp, #0x60
2057c: stp  x20, x19, [sp, #0x50]
20584: mrs  x20, TPIDR_EL0
20590: ldr  x8, [x20, #0x28]        ← 栈金丝雀
205a0: stur x8, [x29, #-0x8]
205ac: blr  x8
205b0: cbz  w0, 0x205bc
205b4: mov  w0, #-0x1              ← 失败返回 -1
```

`selftest`（0x22998，明文）：

```asm
22998: stp  x29, x30, [sp, #-0x10]!
229b0: bl   0x42270
229b4: cmp  w0, #0x0
229b8: b.ne 0x229cc
229bc: bl   0x2265c
229c0: cbnz w0, 0x229d0
229c8: b    0x4e8ac                ← 跳进 .ncguard
229cc: mov  w0, #-0x64             ← 失败码 -100
```

**失败逻辑一目了然**：`cmp w0, #0` / `b.ne` / `mov w0, #-100`。返回值 `0` 成功、`-100` 失败。

**架构错位**：`.text` 明文装调度逻辑、返回值判定；`.ncguard` 加密只装被调用的函数体。逆向者不需解开 `.ncguard`，读明文就能画出流程。

---

### #7 `.text` 存在函数级代码块置换（唯一真挡住一轮的防御）

`0x42270` 落在 `__emutls_get_address` 名下，但内容不是它：

```asm
42270: bti  c
42274: adrp x16, 0x79000
42278: ldrb w16, [x16, #0x858]
4227c: cbz  w16, 0x42288
42280: casal w0, w1, [x2]           ← __cxa_guard_acquire 的 CAS
42284: ret
42288: mov  w16, w0
4228c: ldaxr w0, [x2]
42294: b.ne 0x422a0
42298: stlxr w17, w1, [x2]
422a0: ret
422a4: paciasp                      ← 突然变成带 PAC 的完整函数
422a8: sub  sp, sp, #0x70
422b0: mov  w0, #0x10
422b4: bl   getauxval@plt           ← getauxval(AT_HWCAP)
422b8: tbnz w0, #0x8, 0x422d4
...
422d8: adr  x0, 0x114bd             ← "ro.arch"
422e0: bl   __system_property_get@plt
422f0: add  x1, x1, #0x921          ← 0x11921
422f8: mov  w2, #0xa
422fc: bl   strncmp@plt             ← strncmp(prop, "exynos9810", 10)
42304: cset w8, ne
```

这是**函数级代码块置换**：校验逻辑塞进 libc++ 静态链接函数中间，符号表标成 `__emutls_get_address` / `__cxa_guard_acquire`，属于**符号欺骗**。

相关 `.rodata` 内容：

```
0114bd  ro.arch
0114cd  getULEB128
0114d7  fp
0114da  d7
011921  exynos9810
011931  unsupported arm64 reg
```

`exynos9810` 是三星 Exynos 9810，ARM64 已知的 UMO（Unpredictable Memory Ordering）芯片，常用于真机/模拟器判定。`getULEB128` 说明有 DWARF unwind 解析。

**这是本样本唯一有效的静态防御层**——我第一次读 `0x42270` 时确实误判成「明文业务逻辑」，看到 `paciasp` 突兀出现才纠正。

**判据**（给后来者）：如果某函数中途出现 `paciasp`/`autiasp` 且前后风格不一致，就是置换点。

---

### #8~#9 签名校验函数全貌（明文 `.text` 内）

`0x23bxx–0x23fxx`，落在 `Java_com_nc_link_NcLink_selftest` 范围内。

关键指令：

| 位置 | 指令 | 含义 |
|---|---|---|
| `23c68` + `23c6c` | `mov w22, #0x4b50` / `movk w22, #0x605, lsl 16` | `0x06054B50` = ZIP EOCD `PK\x05\x06` |
| `23cc0` | `cmp w8, #0x21` | EOCD 长度合法性（≥33） |
| `23ce4` + `23cf0` | `adr x1, 0x149e0` / `memcmp(...,16)` | 比对 `APK Sig Block 42` |
| `23d30` + `23d38` | `mov w27, #0x871a` / `movk w27, #0x7109, lsl 16` | **`0x7109871A` = APK Signature Scheme v2 ID** |
| `23d70` + `23d78` | `ldur w9` / `cmp w9, w27` / `b.eq` | 线性搜索 v2 块 |
| `23d88` | `bl malloc@plt` | 分配 v2 块缓冲 |
| `23df4`–`23e5c` | 嵌套 length-prefix 边界检查 | v2 内部结构解析 |

这是一段**逐字节手工实现的 APK Signing Block v2/v3 解析器**。实现质量不错：有下溢保护（`csel x21, xzr, x8, lo`）、有边界检查、有标签精确匹配。**绕过 `PackageManager` 的常规 hook 确实无效**。

**但定位成本近乎为零**，三个原因：

1. **符号表直接点名**：整个校验是 `selftest` 的内联体，跨约 5.7KB
2. **魔数全在明文立即数里**：`0x06054B50`、`0x7109871A`，`grep` 即中
3. **失败汇聚点可见**：`23cf4: cbnz w0, 0x23ae4`

---

### #10 单一失败出口 = 单点绕过

`0x23ae4` 不是 return，是「日志 + 继续」：

```asm
23ae4: mov  w0, w19
23ae8: bl   close@plt
23af0: mov  w0, #0x1e
23af4: mov  w2, #0x40
23af8: bl   0x24884                  ← 格式化日志
23b04: adrp x20, 0x10000
23b08: add  x20, x20, #0xc95        ← 日志 TAG
23b20: bl   __android_log_print@plt
23b58: b    0x23bdc                 ← 继续
```

统计：`0x22998–0x24b00` 区间共 **2,138 条指令**，其中 **13 条**跳 `0x23ae4`。

**13 个校验分支 → 1 个汇聚点。** 处理一处，13 个全失效。典型 patch：在 `0x23ae4` 写 `b 0x23bdc`。

**设计缺陷**：校验分散、失败路径集中。良好的反篡改设计应使失败路径分散且各不相同。

---

### #11 第二层：后台 detached 校验线程

`0x23bdc` 之后是一个完整状态机：

```asm
23bdc: bl   0x24044
23be4: bl   pthread_attr_init@plt
23bf0: bl   pthread_attr_setdetachstate@plt   ← w1=1, DETACHED
23bf8: adr  x2, 0x24b20                       ← 线程入口
23c08: bl   pthread_create@plt
23c0c: cbnz w0, 0x23f0c
23c18: ldr  x8, [x24, #0x28]                  ← 栈金丝雀
23c1c: bl   0x24ff8
23c20: b.ne 0x23f10                           ← 金丝雀被改
23c30: ret
```

`0x24b20` 是后台校验线程入口——反调试 + maps 扫描 + `/proc/net/tcp` 实际跑的地方。这解释了 `.bss` 的 146KB。

线程为 **detached**，patch 返回值时它可能已在运行。这是设计上的一个真实优势。

---

## 3. 完整破解过程（本文的核心）

### 3.1 破解链总览

```
APK 签名块（明文）
  └─ certDER ──SHA256──┐
                       ├─→ HKDF-SHA256(ikm=master, salt, info="nc-so-v1"+pkg, 16)
master[32]（.rodata）  │        └─→ k_so
包名（Manifest）───────┘             └─→ RC4 解 .ncguard（32,540 B）→ 明文
                                                              └─→ 读出 ncVerify
```

### 3.2 密钥派生参数（源码静态阅读 + 二进制验证）

`nc_guard_key.c:331` / `:378`：

```
k_so  = HKDF-SHA256(ikm=master(32B), salt=SHA256(certDER), info="nc-so-v1"+pkg,      16)
k_mac = HKDF-SHA256(ikm=master(32B), salt=SHA256(certDER), info="nc-so-mac-v1"+pkg,  16)
```

四个输入全部静态可得：

| 输入 | 位置 | 获取方式 | 难度 |
|---|---|---|---|
| `master` | `.rodata 0x13e80` | `static const`，**`0x11` × 32** | `od` 一眼 |
| `SHA256(certDER)` | APK 签名块，明文 | 解析 v2/v3 块 | 一条命令 |
| `"nc-so-v1"` | `.rodata` 明文字符串 | `strings` | 零 |
| 包名 | `AndroidManifest.xml` | `aapt2 dump packagename` | 零 |

**不需要运行 App，不需要真机，不需要动态调试。**

### 3.3 `master[32]` 是占位符（最致命缺陷）

`nc_guard_boot.c:423`：

```c
static const uint8_t master[32] = {
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
    0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11};
```

**产物里就是这个值，没有被替换。** 实测：

```
$ od -A x -t x1 -v libnc.so | grep -c '11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11'
1
013e80  11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
```

构建脚本无任何注入：

```
$ grep -rn 'master' scripts/pipelines/protect.sh scripts/lib/*.sh
(无输出)
```

`master` 全项目只出现在 `nc_guard_boot.c:423` 一处，`static const` 硬编码，**没有任何构建期替换机制**。

### 3.4 实测解密成功

`probe_ncguard.py` 执行结果：

```
signing block id = 0x7109871A
certDER len = 666
certDER sha256 = d82e48dae7ce6268ebcefd61feb8128fdf1a55f574cbbbc788db7be4491b689e
k_so = 81830c13771b64b8de9a2d4642e19029
.ncguard addr=0x46ac8 off=0x46ac8 size=0x7f1c
decrypted head: c0035fd6fd7bbaa9fc6f01a9fd030091fa6702a9f85f03a9f65704a9f44f05a9
```

解密首字节 `c0 03 5f d6` = `ret`；接 `fd 7b ba a9` = `stp x29,x30,[sp,#-0x60]!`——**标准函数序言**。

32,540 字节全部解开。

### 3.5 `ncVerify` 解密后：只是个转发壳

```asm
000000000004e8c4 <Java_com_nc_link_NcLink_ncVerify>:
   4e8c4: stp  x29, x30, [sp, #-0x30]!
   4e8d4: cbz  x2, 0x4e944              jstring == NULL → 返回 0
   4e8d8: ldr  x8, [x0]
   4e8e8: ldr  x8, [x8, #0x558]         GetStringUTFLength
   4e8ec: blr  x8
   4e8f0: cmp  w0, #0x20                长度必须 == 32
   4e8f4: b.ne 0x4e944
   4e8f8: ldr  x8, [x20]
   4e908: ldr  x8, [x8, #0x5c0]         GetStringUTFChars
   4e90c: blr  x8
   4e910: cbz  x0, 0x4e944
   4e914: mov  w1, #0x20
   4e91c: bl   0x238bc                  ← 真正的判定函数
   4e924: mov  w22, w0
   4e934: mov  w3, #0x2                 JNI_ABORT
   4e938: ldr  x8, [x8, #0x600]         ReleaseStringUTFChars
   4e93c: blr  x8
   4e948: mov  w0, w22
   4e958: ret
```

**它只做 JNI 类型转换 + 长度检查 + 转调。判定逻辑一行都不在里面。**

`heartbeat` 同理：

```asm
4e978: adr  x1, 0x116a6     ← "com/nc/link/NcLink"
4e9a8: tst  w0, #0xff
4e9ac: b.eq  0x4e9b4
4e9b0: bl   0x23824         ← 判定
```

### 3.6 真正的判定算法在明文 `.text 0x238bc`

**这个函数从未被加密**，在原始未解密的 so 上就能读：

```asm
238bc: sub  sp, sp, #0x40
238c8: mrs  x9, TPIDR_EL0                 栈金丝雀
238d8: cbz  x0, 0x23960                   入参非空
238dc: cmp  w1, #0x20                     长度==32
238ec: adr  x10, 0x13400                  ← 表A
238f0: mov  w11, #-0x62                   -98 = 0x9E
238f8: 循环 i = 0..31:
23900:   and  x13, x8, #0xf               i & 0xF
23904:   ldrb w14, [x0, x8]               输入字节
23908:   mul  w15, w8, w11                i * (-98)
2390c:   ldrb w13, [x10, x13]             表A[i & 0xF]
23910:   eor  w13, w14, w13
23914:   eor  w13, w13, w15
23918:   strb w13, [x12, x8]              存临时缓冲
23924: 第二个循环 j = 0..31:
23934:   adr  x12, 0x13fa4                ← 表B
23940:   ldrb w13, [x11, x10]
23944:   ldrb w14, [x12, x10]
2394c:   eor  w13, w14, w13
23950:   orr  w8, w8, w13                 累积差异
23958: cmp  w8, #0x0                     全 0 → 相等
2395c: cset w8, eq
```

**这是一个 32 字节固定值比较器。** 变换算法：

```
expected[i] = 表B[i] ^ (input[i] ^ 表A[i & 0xF] ^ ((i * 0x9E) & 0xFF))
判定条件   = 所有 expected[i] == 0
⇒ input[i] = 表B[i] ^ 表A[i & 0xF] ^ ((i * 0x9E) & 0xFF)
```

两个表都在明文 `.rodata`：

```
表A @0x13400 (只用前16B，因为 & 0xF):
  3b 66 3b 1a d8 27 c0 83 50 01 c3 fd fe 63 b0 d9

表B @0x13fa4 (32B):
  99 31 bd 8e f7 66 13 f1 73 f5 ef 7a c3 6f 92 2f
  27 48 69 38 a9 d7 7e d5 9c 46 6d 76 34 6c e5 0e
```

反推得到的 32 字节通过值**不在本文记录**（避免给出可直接使用的绕过凭据）。正向自检 `True`，算法正确。

### 3.7 破解结论

**两条路通向同一结论：**

- **不解密 `.ncguard`**：`ncVerify` 的符号名已暴露，读 `0x4e8c4` 附近的明文 xref 就知道它转调 `0x238bc`，直接看明文判定函数
- **解密 `.ncguard`**：确认 `ncVerify` 确实是转发壳

**`.ncguard` 加密对这次破解的贡献是零。** 8 分钟的解密只换来一个「原来里面是转发器」的确认。

---

## 4. `.nckey` 诱饵机制（真实有效的防御）

必须明确记一笔：`nc_guard_boot.c:456` 的设计**成功误导了我一轮**。

```c
/* 用证书派生的 k_so 覆盖 slot 里的诱饵值 */
memcpy(key, k_cert, 16);
```

`nc_guard_boot.c:401-412`：

```
/* ═══ P1-a（2026-10-19）：运行期证书派生，取代 slot 里的 wrapped k_so ═══
 *
 * 修的是强度报告的核心指控「证书绑定是构建期属性、运行期零参与」——
 * 此前 k_so 直接由 slot[16:32] ^ XOR_KEY 得到，意味着【拿到 so 就能离线解密，
 * 不需要 APK 也不需要证书】。
 *
 * 现在：从【已安装的 APK】读第一签名者证书 → SHA256 → HKDF 派生 k_so。
 * fail-closed（用户拍板）：证书读不到 / 派生结果与...不符 → 不解密
 */
```

我在分析中段曾用 `wrapped_k_so ^ XOR_KEY` 算出过一个「k_so」，并据此断言能解开——那个值是**诱饵**，解出来是乱码。这是真实有效的防御。

**但诱饵的强度止步于此**：它只挡住「不懂源码结构的人」。一旦知道真实派生公式（公式就在 `.rodata` 字符串和明文代码里可推），诱饵就失效了。

---

## 5. `XOR_KEY` 碎片化：实测未生效

`nc_guard_boot.c:155-158`：

```c
static volatile uint16_t ncg_frag_a = 0xc831u;  /* 逻辑 1,4 */
static volatile uint16_t ncg_frag_b = 0x927eu;  /* 逻辑 0,5 */
static volatile uint16_t ncg_frag_c = 0xf6a5u;  /* 逻辑 2,7 */
static volatile uint16_t ncg_frag_d = 0x4b0du;  /* 逻辑 3,6 */
```

意图（`:144`）写得很清楚：

```c
/* ⚠️ 碎片必须是「运行期才知道」的值，否则白拆。 */
```

**但实测这四个碎片整齐排在 `.data`：**

```
054560  31 c8 00 00  7e 92 00 00  a5 f6 00 00  0d 4b 00 00
```

顺序与源码声明完全一致，每个 `uint16_t` 后 2 字节零填充。`volatile` 只阻止编译器优化掉访问，**不加密初始值**。

按 `:141` 的规则（`i<4` 取低位，`i>=4` 取高位）重排 8 次即得完整 `XOR_KEY`：

| 逻辑字节 | 值 | 来源 |
|---|---|---|
| 0 | `7E` | frag_b 低位 |
| 1 | `31` | frag_a 低位 |
| 2 | `A5` | frag_c 低位 |
| 3 | `0D` | frag_d 低位 |
| 4 | `C8` | frag_a 高位 |
| 5 | `92` | frag_b 高位 |
| 6 | `4B` | frag_d 高位 |
| 7 | `F6` | frag_c 高位 |

**碎片化没有降低攻破成本**（都是一条 `od` + 8 次心算），只增加了约 30 秒理解重排规则的时间。从「降低可读性」变成了「降低了一点点可读性」。

**真正的修法**：碎片不能是 `.data` 里的初始值。应改为运行期从其他来源派生（如与 `.text` 的 crc32 混合、从证书派生），或干脆去掉这个中间层——因为它保护的 `k_so` 本身已改为证书派生，`XOR_KEY` 的实际价值已经很低。

---

## 6. 其他实测发现

### 6.1 契约注释自相矛盾

`nc_guard_probe.c` 同一段里写了两个值：

```c
/* 对拍契约：ncguard_probe(0) == ((0^0x5A)+0x0F)*3 & 0xFF == 59。
   取值刻意不取 42/0/1 这类哨兵值，避免 strings 一眼定位。 */   ← 说"刻意不取 42"
...
/* 对拍契约：ncguard_probe(0) 必须返回 0x2A（42）。 */            ← 紧接着说要 42
```

实测算式：**(0 ^ 0x5A) + 0x0F) * 3) & 0xFF = 59 = 0x3B**。前一句对，后一句是过期注释。

顺带一个讽刺点：注释说「刻意不取 42/0/1 哨兵值，避免 strings 一眼定位」，但写法是硬编码算术常量，编译后就是 `eor`/`add`/`mov` 三条立即数指令，`llvm-objdump` 一眼可见。**这个反定位意图没有实现。**

### 6.2 ~~`reserved8` 字段实际非零~~ 【已更正：本条为误判】

> **⚠️ 2026-10-19 更正**：本节原结论（`reserved8` 非零）是**误判**，已推翻。
>
> **错误原因**：把 `expect_mac` 的字段长度当成 16 字节，实际是 **32 字节**。
> 因此后续字段整体前移 8 字节——看到的 `10d2cadf...` 位于 `0x50`，是 `pkg_sha8`，
> 不是 `0x58` 的 `reserved8`。
>
> **实测复核**（按正确字段切分）：
>
> ```
> 0x00 magic        = 3072ee4891de04b50000000000000000   (16B)
> 0x10 wrapped_k_so = d6054d96f1e7128525a5b6cc9b496258   (16B)
> 0x20 wrapped_k_mac= df137044a989ac6284cb5c97e2b7e680   (16B)
> 0x30 expect_mac   = 4e4be1d5...9366737bf7fec1ef6fb7fa147d2dfb49  (32B)
> 0x50 pkg_sha8     = 10d2cadff1d5accf                   (8B)  ← 原误判为 reserved8
> 0x58 reserved8    = 0000000000000000                   (8B)  ← 全零，符合源码
> ```
>
> **`reserved8` 确实是全零。源码与产物一致。**
>
> 附带验证：`pkg_sha8` 的语义也正确——
> `SHA256("com.xixin.box")[:8] = 10d2cadff1d5accf`，与实测**完全一致**。
>
> **结论**：本节不构成任何缺陷。构建产物与源码版本一致。
> 原报告其它章节中凡引用本节结论的，均不受影响（该结论未被用于任何安全判断）。

### 6.3 magic 换形式但结构性冗余仍在

`so-section-lock.py:56-64`：

```python
SLOT_MAGIC_SEED = bytes([0x30, 0x72, 0xEE, 0x48, 0x91, 0xDE, 0x04, 0xB5])
STUB_MAGIC_SEED = bytes([0x30, 0x72, 0xF6, 0x59, 0x9D, 0xD0, 0x07, 0xBD])
XOR_KEY         = bytes([0x7E, 0x31, 0xA5, 0x0D, 0xC8, 0x92, 0x4B, 0xF6])
assert SLOT_MAGIC_SEED ^ XOR_KEY == b'NCKEYLOC'
assert STUB_MAGIC_SEED ^ XOR_KEY == b'NCSTUBLK'
```

**做对的**：`NCKEYLOCK` / `NCSTUBLK` 字面量确实已从二进制抹除。实测：

```
$ strings -a libnc.so | grep -iE 'NCKEYLOCK|NCSTUBLK'
(无输出)
```

**没做对的**：`SLOT_MAGIC_SEED[0:2] == STUB_MAGIC_SEED[0:2] == 0x30 0x72`。两个槽共享 2 字节前缀，加上「96 字节 + 相邻偏移」的特征，我靠这个匹配一眼认出两个槽。

**修法**：让两个槽的 magic 互不相关，或干脆不设 magic——用段头表 size 字段判「是否已锁」。

### 6.4 编译器常量明文

`NCG_XOR_KEY` 旧值仍在 `.rodata`：

```
013450  5a c3 11 9e f0 37 b2 6d b9 43 81 78 78 a7 57 e7
```

来自历史存档 `nc_guard_unlock.c:77`（该文件头已标注「历史存档，不要再参考」）。现行实现用碎片（见 §5），但旧常量仍被编进产物。

### 6.5 `master` 附近的其他明文

`.rodata 0x13400` 是表A，`0x13440` 区域还有：

```
013440  a2 69 00 00 a3 69 00 00 01 00 02 03 00 01 03 02
```

`0x69a2`、`0x69a3` 疑似紧邻的其他表的地址/偏移量。这些辅助常量也在明文。

---

## 7. 强度评分与理由

评分基准：**以实测破解难度为准**，不以设计意图为准。

### 7.1 星级总表

| 防御层 | 设计意图 | 实测结果 | 评分 |
|---|---|---|---|
| **签名校验逻辑** | 正确判定签名与否 | **检出了**（真机日志铁证），逻辑无懈可击 | ★★★★★ |
| `.nckey` 诱饵 | 误导攻击者 | **真实有效**，成功误导一轮 | ★★★★☆ |
| `.text` 代码块置换 | 让反汇编读不懂 | 唯一真挡住一轮的防御，但只增加理解成本 | ★★★☆☆ |
| v2 签名块直读 | 绕过 `PackageManager` hook | 设计正确、实现质量好，但位置暴露 | ★★★☆☆ |
| `.ncguard` 段加密 | 保护核心校验函数 | RC4 实现正确，但 `master` 占位符使密钥可静态派生 | ★★★☆☆ |
| 节名混淆 | 隐藏保护数据位置 | `.ncguard` 自解释；同 APK 其他 so 无自定义节 | ★☆☆☆☆ |
| **校验算法位置** | 藏在加密段 | **最大缺陷**：真正的判定 `0x238bc` 与两个表全在明文 | ★☆☆☆☆ |
| **`.text` 完整性校验** | 防篡改 | **基准不可信**，改 3 处 `.text` 仍报 `clean` | ★☆☆☆☆ |
| 证书绑定 | 防「只拿 so 就解」 | 设计意图正确，被 `master` 占位符架空 | ★★☆☆☆ |
| **kill 链** | 让篡改者无法运行 | 全走 `abort`/`_exit`/`raise` 三个 PLT 桩，改 4 字节全废 | ★☆☆☆☆ |
| 失败路径分散 | 防单点 patch | 13 分支 → 1 汇聚点 `0x23ae4` | ☆☆☆☆☆ |
| 符号隐藏 | 藏住 `ncVerify` | `nm -D` 直接列出 | ☆☆☆☆☆ |
| 字符串加密 | 藏住防御意图 | `.rodata` 全明文，架构泄底 | ☆☆☆☆☆ |
| 反调试/反注入 | 挡动态分析 | 真机实测全部 `clean`（无 frida/xposed 环境，未验证拦截能力） | — |

### 7.2 两个总分

```
┌────────────────────────────────────────────────┐
│  静态防御强度（只读逆向，不运行）                │
│                                                │
│     ★★☆☆☆                                     │
│     2.5 / 10                                   │
│                                                │
│  「找到要 4 分钟，看懂要 40 分钟」               │
└────────────────────────────────────────────────┘

┌────────────────────────────────────────────────┐
│  实战防御强度（真机 patch + 重打包 + 运行）      │
│                                                │
│     ★☆☆☆☆                                     │
│     1.5 / 10                                   │
│                                                │
│  「70 分钟产出可运行的绕过包，无崩溃」           │
└────────────────────────────────────────────────┘
```

### 7.3 为什么静态是 2.5 而不是 3.5（早期误判的修正）

本报告早期版本给过 **3.5 / 10**，依据是「`.ncguard` 加密有效，我 4 分钟没解开」。**这个评分是错的**，原因有两层：

**第一层：把「我没解开」误当成「解不开」**
4 分钟没解开，不是因为加密强，而是因为**我当时按时间预算停了**。给出 8 分钟算 HKDF，就解开了。评分应以「攻破所需时间」为准，不以「某次尝试是否成功」为准。

**第二层：更根本的——解开 `.ncguard` 本身没有价值**
即使不解开，也能攻破。因为真正判定的 `0x238bc` 从来不在加密段里。所以给 `.ncguard` 加密打 4 星，是把「一个对结果无影响的层」评高了。

`2.5` 这个分数的含义是：**这套防御能挡住「用 jadx 打开看看」的人，挡不住任何知道该看哪儿的人。**

### 7.4 为什么实战再降到 1.5

静态 2.5 测的是「能不能看懂」。实战测的是「能不能跑起来」。后者才是攻击者真正要的。

实测结果：**从零到能在真机前台稳定运行的绕过包，全程约 70 分钟，10 处 patch，每处不超过 8 字节。**

降分理由：

1. **签名校验虽然检出了，但杀不掉我**——因为杀进程的手段是 `abort`/`_exit`/`raise`，全走 PLT
2. **`.text` 完整性校验全程报 `clean`**——我改了 3 处 `.text` 字节，它没发现
3. **两段加密都解开了**——`.ncguard` 靠 `master` 占位符，`.ncguard_head` 靠拿 `.ncguard` 明文当参照

**1.5 分给的是什么**：签名校验那层逻辑真的写对了（这是 ★★★★★ 那一项）。问题不在逻辑，在「检出之后怎么办」。

### 7.5 各层在实战中的实际作用

按攻击者遇到它们的顺序：

```
攻击者动作                     防御反应                    攻击者应对
─────────────────────────────────────────────────────────────────────
① 反汇编 libnc.so                .ncguard 全 <unknown>        改从 .text 找
② 找签名校验                    ncVerify 符号明文导出        直接读 0x238bc
③ 想解密 .ncguard               master=0x11×32 占位符        HKDF 算出来
④ 想解密 .ncguard_head          16B XOR + CRC 自绑定         频率分析破 key
⑤ 重签名装包                     签名校验检出 → tgkill         改 abort/_exit PLT
⑥ 改 .text 字节                  .text 完整性校验 → clean     无需应对
```

**六步全部通过，每一步的防御都被绕过。**

唯一真正拦住过我的是第 ④ 步的**第一轮尝试**（`k_stub` 算错导致 SIGILL），但那是技术细节，不是设计强度——换个方法（频率分析）就破了。

---

## 8. 给 AI 的总结

> 本节写给后续接手的 AI。人读完上面就够了。

### 8.1 结构性问题：加密层装错了东西

**最该理解的一件事**：这套体系里，加密做对了、诱饵做对了、签名块解析做对了，但**加密的东西不对**。

```
现在：  .ncguard（密文）= ncVerify 转发壳
        .text    （明文）= 0x238bc 真正的判定算法 + 两张表

应该：  .ncguard（密文）= 0x238bc 判定算法 + 两张表
        .text    （明文）= ncVerify 转发壳
```

这是一个 `__attribute__((section(".ncguard")))` 的位置问题，不是加密算法问题。**改这一处，收益大于所有其他改动之和。**

### 8.2 五个容易踩的坑（我踩过）

1. **`.text` 不是明文**。`llvm-objdump` 输出看着正常，是因为有函数级置换 + libc++ 符号欺骗。判据：某函数中途出现 `paciasp`/`autiasp` 且前后风格不一致 = 置换点。

2. **`0x23ae4` 不是 return**。它是 `close` + `__android_log_print` + `b 0x23bdc` 的中间块。找失败出口不能只看 `ret` 前的块，要看谁被引用 13 次。

3. **符号名完全不可信**。`__emutls_get_address` 名下挂着校验逻辑。按符号做语义推断会把人带偏。

4. **`wrapped_k_so ^ XOR_KEY` 得到的是诱饵**。别拿它当真实密钥用，会解出乱码然后误判「加密很强」。

5. **历史存档文件不能当真**。`nc_guard_unlock.c` 头部已标注「不要再参考」，但里面的常量仍被编进产物。读源码前先看文件头的时效声明。

### 8.3 修优先级（按性价比排序，已按实战结果重排）

> **⚠️ 实战后修正**：原表把 `master` 列在 P0。实战证明**kill 链才是第一优先**——
> 因为即使 `master` 修好，攻击者仍可 patch `0x238bc` 让判定恒真，然后绕过 kill 链。
> 而 kill 链修好（改成走垃圾数据），攻击者重打包后 App 能启动但功能全废。

| 优先级 | 改动 | 成本 | 收益 | 依据 |
|---|---|---|---|---|
| **P0** | **kill 链去掉 `abort`/`_exit`，改走「静默垃圾数据」** | 中 | 重打包包能启动但功能全废 | 实战 §13.1 |
| **P0** | `.text` 完整性校验改用**构建期写死的基线** | 中 | 改字节能被检出 | 实战 §13.1 报 clean |
| **P1** | `master[32]` 改构建期随机生成 + 注入 | 低 | 断绝「拿 APK 就能离线解」 | 静态 §3.3 |
| **P1** | 把 `0x238bc` 判定函数 + 两张表移进 `.ncguard` | **极低** | 让加密层第一次真正生效 | 静态 §8.1 |
| **P1** | 失败路径分散（13 → N 个独立出口） | 中 | 消除单点 patch | 静态 §10 |
| **P2** | 不依赖 `abort`/`_exit` 做 fail-fast（直接写非法状态） | 低 | 消除 PLT 单点 | 实战 §12.1 |
| **P2** | `.dynsym` / `.dynstr` 抹除业务符号 | 中 | 消除 90% 定位成本 | 静态 §1 |
| **P3** | `.rodata` 字符串加密 | 中 | 隐藏防御架构 | 静态 §4 |
| **P3** | 节名改标准名或合并进 `.rodata` | 低 | 降低可发现性 | 静态 §0 |
| **P3** | 日志文本与实际行为对齐 | 低 | 减少误导排查 | 实战 §13.2 |
| **P3** | `XOR_KEY` 碎片改为运行期派生 | 低 | 碎片化真正生效 | 静态 §5 |


### 8.4 未验证项（静态阶段）

以下在静态阶段未验证，**部分已在第二部补上**：

- ~~重打包后签名校验是否真的会失败~~ → **已实测：会失败，且立即 tgkill SIGKILL**（§11.3）
- 反调试（`ptrace` 自检）是否真的生效 → 真机八项全 clean，但**未测有 frida 时能否检出**
- `0x24b20` 后台线程的实际行为 → 已实测：常驻复查线程，内含 `abort()`（§11.3）
- 13 个校验分支是否真的全部依赖 `0x23ae4` → 仍未逐条验证

静态分析回答的是「找到要多久」（4 分钟）和「看懂要多久」（40 分钟）。
实战验证回答的是「跑起来要多久」——**70 分钟**（见第二部）。

---

# 第二部：实战修改与真机验证

> 第一部是「只读逆向」——不运行、不修改。这一部是**真刀真枪**：
> patch、重打包、重签名、装到真机、抓崩溃、改到能跑。
>
> **区分标记**：以下所有内容都是**实际修改了二进制并运行验证**的，
> 与第一部的纯静态分析不是一回事。

## 10. 实战时间线与产物

### 10.1 时间线

| 时刻 | 事件 |
|---|---|
| `00:52:28` | T0，静态盲测开始 |
| `00:56:29` | 定位到签名校验核心（4 分 1 秒） |
| `~01:20` | 静态分析完成，`.ncguard` 离线解开 |
| `01:21` | 删除 02~07 号旧文档 |
| `01:32` | 第一个 patch 包 `bypass_signed.apk` |
| `01:36` | **真机闪退**，tombstone：`SIGILL @ 0x4f07c` |
| `01:47` | `bypass2`（两段全明文），仍闪退 |
| `01:48` | 拿到 `sigcheck_log.txt`，确认签名校验检出了 |
| `01:57` | adb 抓崩溃，发现真正死因是 `tgkill(SIGKILL)` |
| `01:59` | `bypass3`（patch kill 链），活 30 秒后 `SIGABRT` |
| `02:01` | `bypass4`（patch PLT 桩） |
| `02:03` | **真机稳定运行，无崩溃** |
| `02:06` | 实测完成 |

**从 T0 到可运行的绕过包：约 70 分钟。**

### 10.2 产物清单

```
~/jianhe_re_work/
├── target.apk              原包副本（未修改）
├── bypass_signed.apk       第 1 版：只 patch .text 判定 → SIGILL
├── bypass2_signed.apk      第 2 版：两段填明文 → 仍闪退
├── bypass3_signed.apk      第 3 版：patch kill 链 → 30s 后 SIGABRT
├── bypass4_signed.apk      第 4 版：patch PLT 桩 → 稳定运行 ✅
├── libnc_bypass4.so        最终修改后的 so
├── ncguard_dec.bin         .ncguard 解密结果（32,540 B）
├── head_final.bin          .ncguard_head 解密结果（2,600 B）
├── probe_ncguard.py        离线解密脚本
├── sigcheck_log.txt        真机日志（应用自己输出）
├── lc_start.txt / lc3.txt  adb logcat 抓取
└── tombstone_00001...      第 1 版的崩溃栈
```

---

## 11. 四次尝试：每一版为什么失败

### 11.1 第 1 版：只 patch 判定函数 → SIGILL

**做了什么**：
```python
so[0x238bc:0x238c4] = "mov w0,#1; ret"    # 判定恒真
```

**结果**：闪退。tombstone：

```
signal 4 (SIGILL), code 1 (ILL_ILLOPC), fault addr 0x7c2ff9307c (*pc=0x4fd1ee9e)
backtrace:
    #00 pc 0x0004f07c  libnc.so
    #01 pc 0x0002290c  libnc.so
    #02 pc 0x0006c914  linker64 (call_constructors)
```

**原因**：改 `.text` → `crc32(.text)` 变 → `k_stub` 错 → `.ncguard_head` 解出乱码 → 执行密文。

**这一版的教训**：**代码自绑定（CRC 混入密钥）真的有效**。我改一个字节，整个二级锁箱就废了。

但注意 `#01 pc 0x0002290c` 这个帧——它揭示了关键结构（见 11.2）。

### 11.2 第 2 版：两段都填明文 → 仍闪退

**做了什么**：
```python
so[0x46ac8:...] = ncguard_dec            # .ncguard 明文
so[0x4e9e4:...] = head_final             # .ncguard_head 明文
so[0x16634:0x1663c] = b'\x00'*8          # magic 置零
so[0x16694:0x1669c] = b'\x00'*8          # magic 置零
so[0x238bc:0x238c4] = "mov w0,#1; ret"
```

**结果**：仍闪退，但**没有 tombstone**（不是 native crash）。

**原因**：这次不是加密的问题了，是**签名校验检出后杀了进程**。

**这一版的教训**：加密不是唯一的门。绕过加密之后，还有一层运行时校验。

### 11.3 第 3 版：patch kill 链 → 活 30 秒

**拿到 `sigcheck_log.txt` 后**，确认了完整链条：

```
【成功】证书 DER 提取成功 (der_len=744)
nc: fp=a3b08bf6...                          ← 我的重签名
【数据】实际证书指纹 actual_fp (a3b08bf6...)
【E】nc: mm
【失败】指纹比对不一致 → 校验失败,延时退出已安排
【流程】延时退出线程启动:随机延时后 abort (delay=1~3s)
```

**注意日志说「延时 1~3 秒」，但实测只延了 19 毫秒**——日志和实际行为不符。

adb 抓到的真实死因：

```
01:57:55.713  【失败】指纹比对不一致
01:57:55.732  Zygote: Process 21726 exited due to signal 9 (Killed)
```

**19 毫秒。`signal 9` = SIGKILL，不是 `abort()`。**

**做了什么**：
```python
so[0x25474:0x25478] = "nop"              # 立即 kill 的调用点
so[0x25c14:0x25c18] = "ret"              # tgkill 函数
so[0x25c40:0x25c44] = "nop"              # tgkill 指令
so[0x25c00:0x25c04] = "ret"              # 延时线程
```

**结果**：进程活了 30 秒，然后 `SIGABRT`：

```
Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 25756
```

tombstone 栈：
```
#00 libc.so (abort+156)
#01 libnc.so pc 0x24c48        ← 另一条线程
#02 libc.so (__pthread_start)
```

`0x24c48` 是**常驻复查线程**（每 20 秒重检）里的 `abort()`。

**这一版的教训**：kill 手段不止一处。逐个 patch 会一直漏。

### 11.4 第 4 版：patch PLT 桩 → 稳定运行

**关键洞察**：搜出来 `bl abort@plt` 有 **30+ 处**。逐个改效率极低，而且永远可能漏。

**换思路**：直接改 PLT 表项本身。

```
abort@plt @0x4f6a0 : adrp→ldr→add→br  →  改成 ret
_exit@plt @0x4f8e0 : 同上              →  改成 ret
raise@plt @0x4f8f0 : 同上              →  改成 ret
```

**三个表项，各 4 字节，一共 12 字节，30+ 个调用点全部失效。**

**结果**：

```
t≈1s:  pid=25582
t≈2s:  pid=25582
t≈3s:  pid=25582
t≈5s:  pid=25582
t≈8s:  pid=25582
t≈12s: pid=25582
t≈20s: pid=25582
t≈30s: pid=25582
```

前台验证：

```
topResumedActivity=com.xixin.box/.MainActivity    ← App 在前台
Fatal signal / ANR / Force finishing: (空)         ← 无任何崩溃
```

**成功。**

---

## 12. 最终攻击清单（10 处 patch）

| # | 地址 | 原字节 | 改后 | 作用 | 大小 |
|---|---|---|---|---|---|
| 1 | `0x46ac8` + 32,540 B | RC4 密文 | 明文 | `.ncguard` 解密后写入 | 32.5 KB |
| 2 | `0x4e9e4` + 2,600 B | XOR 密文 | 明文 | `.ncguard_head` 解密后写入 | 2.6 KB |
| 3 | `0x16634` | `30 72 f6 59 …` | `00 × 8` | stub magic 置零 | 8 B |
| 4 | `0x16694` | `30 72 ee 48 …` | `00 × 8` | key magic 置零 | 8 B |
| 5 | `0x238bc` | `ff 03 01 d1` | `mov w0,#1; ret` | 判定恒真 | 8 B |
| 6 | `0x25474` | `bl 0x25c14` | `nop` | 断立即 kill | 4 B |
| 7 | `0x25c14` | `stp x29,x30…` | `ret` | kill 函数 | 4 B |
| 8 | `0x25c40` | `bl syscall` | `nop` | 断 tgkill | 4 B |
| 9 | `0x4f6a0` | `adrp x16…` | `ret` | **`abort@plt`** | 4 B |
| 10 | `0x4f8e0` | `adrp x16…` | `ret` | **`_exit@plt`** | 4 B |
| 11 | `0x4f8f0` | `adrp x16…` | `ret` | **`raise@plt`** | 4 B |

**共 11 处，其中 8 处是 4~8 字节的指令级 patch。真正的核心工作量是前两处的离线解密。**

### 12.1 三个 PLT 桩是最有价值的发现

```
改前：0x4f6a0: adrp x16, 0x55000 / ldr x17, [x16,#0x280] / add x16,x16,#0x280 / br x17
改后：0x4f6a0: ret
```

**一个 `ret`（4 字节）废掉 30+ 个 `abort()` 调用点。**

这是 Android so 的通用结构问题——所有 `abort` 调用都汇到同一个 PLT 表项。**任何依赖 `abort()` 做 fail-fast 的设计，都会被这一个点废掉。**

---

## 13. 真机实测暴露的三个新问题

这三个问题在纯静态分析里看不到，只有跑起来才发现。

### 13.1 `.text` 完整性校验从来没生效过

真机日志两次都报：

```
【数据】本 so .text 内存完整性校验结果 (clean)
```

而我改了 `.text` 里三处字节（`0x238bc`、`0x25474`、`0x25c40`）。

**原因**（从反汇编看出来的）：`0x4e4bc` / `0x4e4cc` 这一组：

```asm
4e4b4: add  x0, x20, x9        ; 缓冲区 A + 偏移
4e4b8: mov  x1, x19            ; 长度
4e4bc: bl   0x2226c            ; crc32(A+off, len) → w21

4e4c4: add  x0, x23, x24       ; 缓冲区 B + 偏移
4e4c8: mov  x1, x19            ; 同一长度
4e4cc: bl   0x2226c            ; crc32(B+off, len) → w19

4e4dc: cmp  w21, w19           ; 两个 CRC 比较
```

**两次 CRC 都是对着运行期内存算的，然后互相比对。** 这不是「内存 vs 构建期基线」，是「内存 vs 内存」。

如果两组都来自同一份被改过的 so，当然相等 → `clean`。

**对比签名校验**：它用的是构建期写进 `sig_hash.h` 的证书指纹，是可信基线，所以正确检出。

**`.text` 完整性校验缺的正是这个「可信基线」。**

### 13.2 日志描述与实际行为不符

日志说：

```
【流程】延时退出线程启动:随机延时后 abort (校验失败后的反应) (delay=1~3s)
```

实测：

```
01:57:55.713  【失败】指纹比对不一致
01:57:55.732  Process exited due to signal 9 (Killed)
```

**19 毫秒，`SIGKILL`，不是 `abort`。**

从反汇编看，`0x25474` 是 `bl 0x25c14`，而 `0x25c14` 里是 `tgkill(pid, tid, SIGKILL)` + `raise(SIGKILL)` + `_exit(127)`。

**「延时 1~3s 后 abort」和「立即 tgkill SIGKILL」是两套完全不同的行为。** 日志文本误导了排查方向——我一开始以为有 1~3 秒窗口可利用，实际没有。

### 13.3 反调试/反注入全部报 clean（未验证拦截能力）

```
【数据】frida 端口探测结果 (clean)
【数据】frida maps 特征探测结果 (clean)
【数据】frida tcp LISTEN 探测结果 (clean)
【数据】Xposed/LSPosed maps 特征探测结果 (clean)
【数据】Xposed/LSPosed 文件痕迹探测结果 (clean)
【数据】调试器 TracerPid 探测结果 (clean)
【数据】frida 线程名探测结果 (clean)
【数据】frida unix socket 探测结果 (clean)
```

**八项全部 `clean`。** 但这是在**没有 frida / xposed 的干净环境**下测的。

这只能证明「没有误报」，**不能证明「有 frida 时能检出」**。要验证拦截能力，需要在设备上真开 frida 再测。**本轮未做。**

---

## 14. 实战结论

### 14.1 这套防御在真实攻击者面前能撑多久

| 攻击者水平 | 预期耗时 | 依据 |
|---|---|---|
| 只会用 jadx 看 Java 层 | **挡住** | `.ncguard` 密文 + so 里没字符串 |
| 会 `nm` / `strings` / `readelf` | **10 分钟找到签名校验** | 符号明文导出 |
| 会反汇编 + 会算 HKDF | **40 分钟读懂全部逻辑** | `master` 占位符 |
| 会 patch + 重打包 + 会抓 tombstone | **70 分钟跑起来** | PLT 桩软目标 |

**AI 辅助的话，每个档位再快 3~5 倍。**

### 14.2 唯一真正有效的设计（一句话）

**签名校验的判定逻辑**。它确实算出了正确指纹、确实比对失败、确实打了日志——这部分代码质量没有问题。

**问题全部出在「检出来之后怎么办」**：杀进程的手段集中在 PLT 软目标上，一处 patch 全废。

### 14.3 如果只改一处

**不是改 `master`，是改 kill 链。**

理由：
- `master` 改了，`.ncguard` 打不开 → 但攻击者还是可以 patch `0x238bc` 让判定恒真，然后照着 11.2~11.4 的流程绕过 kill 链
- kill 链改了（不用 `abort`/`_exit`，改成「悄悄走垃圾数据路径」），攻击者重打包后 App 能启动但**功能全废**——这才叫真的防住

**`master` 是第二优先。** 它防的是「读懂逻辑」，kill 链防的是「跑起来」。对攻击者来说后者的价值更高。

### 14.4 未验证项（诚实清单）

- 反调试/反注入的**拦截能力**（本轮环境干净，八项全 clean，只证明无误报）
- 常驻复查线程的完整逻辑（只看到 `0x24c48` 这一处 `abort`）
- 13 个校验分支是否真的全部依赖 `0x23ae4`（静态推断，未逐条验证）
- `.ncguard_head` 的 key 是否能脱离 `.ncguard` 明文单独求出（本轮是靠参照破的）

---

## 15. 附录 A：静态分析关键地址速查

| 地址 | 内容 | 段 | 加密 |
|---|---|---|---|
| `0x20570` | `JNI_OnLoad` | `.text` | 否 |
| `0x22998` | `selftest` 起点 | `.text` | 否 |
| **`0x238bc`** | **真正的判定算法** | **`.text`** | **否** |
| `0x23ae4` | 失败汇聚点（13 处引用） | `.text` | 否 |
| `0x23bdc` | 后台线程创建块 | `.text` | 否 |
| `0x23ce4` | `APK Sig Block 42` memcmp | `.text` | 否 |
| `0x23d30` | v2 ID `0x7109871A` 装载 | `.text` | 否 |
| `0x24b20` | 后台校验线程入口 | `.text` | 否 |
| `0x42270` | 代码块置换点（伪 `__emutls_get_address`） | `.text` | 否 |
| `0x46ac8` | `.ncguard` 起点 | `.ncguard` | **是** |
| `0x4e8c4` | `ncVerify`（转发壳） | `.ncguard` | **是** |
| `0x4e95c` | `heartbeat`（转发壳） | `.ncguard` | **是** |
| `0x4e9e4` | `.ncguard_head` 起点 | `.ncguard_head` | **是** |
| `0x16634` | `.nckey_stub`（明文段表描述符） | `.nckey_stub` | 否 |
| `0x16694` | `.nckey`（含诱饵） | `.nckey` | 否 |

### `.rodata` 关键数据

| 地址 | 内容 |
|---|---|
| `0x13400` | 表A（16B，判定用） |
| `0x13fa4` | 表B（32B，判定用） |
| `0x13e80` | `master[32]` = `0x11` × 32 |
| `0x13450` | `NCG_XOR_KEY` 旧值（历史存档） |
| `0x149e0` | `"APK Sig Block 42"` |
| `0x11921` | `"exynos9810"` |
| `0x114bd` | `"ro.arch"` |
| `0x1317f` | `"/proc/self/task/%s/comm"` |

### `.data` 关键数据

| 地址 | 内容 |
|---|---|
| `0x54560` | `XOR_KEY` 四个碎片：`31c8 7e92 a5f6 0d4b` |

### `.nckey` 96 字节布局

| 偏移 | 字段 | 长度 |
|---|---|---|
| 0x00 | magic | 16 |
| 0x10 | wrapped_k_so（**诱饵**） | 16 |
| 0x20 | wrapped_k_mac（**诱饵**） | 16 |
| 0x30 | expect_mac | 32 |
| 0x50 | pkg_sha8 | 8 |
| 0x58 | reserved8（全零，已核实） | 8 |

---

## 16. 附录 B：实战 patch 地址速查

| 地址 | 原内容 | 改成 | 目的 | 大小 |
|---|---|---|---|---|
| `0x46ac8` | RC4 密文 32,540 B | 明文 | `.ncguard` 填充 | 32.5 KB |
| `0x4e9e4` | XOR 密文 2,600 B | 明文 | `.ncguard_head` 填充 | 2.6 KB |
| `0x16634` | `30 72 f6 59 9d d0 07 bd` | `00 × 8` | stub magic 置零 | 8 B |
| `0x16694` | `30 72 ee 48 91 de 04 b5` | `00 × 8` | key magic 置零 | 8 B |
| `0x238bc` | `ff 03 01 d1` | `20 00 80 52 c0 03 5f d6` | 判定恒真 | 8 B |
| `0x25474` | `bl 0x25c14` | `nop` (`1f 20 03 d5`) | 断立即 kill | 4 B |
| `0x25c14` | `stp x29,x30,[sp,#-0x20]!` | `ret` (`c0 03 5f d6`) | kill 函数 | 4 B |
| `0x25c40` | `bl syscall` | `nop` | 断 tgkill | 4 B |
| `0x4f6a0` | `adrp x16, 0x55000` | `ret` | `abort@plt` | 4 B |
| `0x4f8e0` | `adrp x16, 0x55000` | `ret` | `_exit@plt` | 4 B |
| `0x4f8f0` | `adrp x16, 0x55000` | `ret` | `raise@plt` | 4 B |

### 密钥材料（实测得出）

| 项 | 值 | 来源 |
|---|---|---|
| `master` | `0x11` × 32 | `.rodata 0x13e80`，`static const` 占位符 |
| `k_so` | `81830c13771b64b8de9a2d4642e19029` | `HKDF(master, SHA256(certDER), "nc-so-v1"+pkg)` |
| `.ncguard_head` XOR key | `346c9e9fadcfcff063956de65b8b8817` | 频率分析（以 `.ncguard` 明文为参照） |
| `XOR_KEY` | `7e31a50dc8924bf6` | `.data 0x54560` 四碎片重排 |
| 原证书指纹 | `d82e48dae7ce6268ebcefd61feb8128fdf1a55f574cbbbc788db7be4491b689e` | `apksigner verify --print-certs` |
| 重签名指纹 | `a3b08bf655337513d98b08b0bf8fdd1e9f7e639c9fefaf3bd8b301adebadbbf1` | debug.keystore |

### 定位 `.ncguard_head` XOR key 的方法（可复用）

1. 确认加密方式：对密文按 `mod 16` 分组统计字节熵。若各位置熵 < 8 且有主导字节 → 16 字节循环 XOR。
2. 取一段已知明文（本例是 `.ncguard`，因为它的密钥链全开放），按 `mod 16` 分组统计分布。
3. 对 head 密文的每个 `mod 16` 位置，枚举 256 个 key 候选，算解密后与该位置明文分布的**余弦相似度**。
4. 取相似度最高者。**验证方法**：如果解出的片段落在合法 AArch64 指令族（如 `i%4==3` 位置是 `a9/d1/91/f9`），说明对了。
5. 本例中 3 个已知 key 字节（`0x63`/`0x95`/`0xe6`）全部命中验证，方法可靠。

**关键前提**：需要一个「同源编译器产出的已知明文」做参照。攻击者能拿到它，是因为 `.ncguard` 的密钥链（`master`）是开放的。

---

## 17. 给 AI 的完整总结

> 本节写给后续接手的 AI。人读完 §1 结论速览和 §7 评分表就够了。

### 17.1 先读这三条

**1. 这套防御的加密算法没问题，装配有问题。**
RC4 实现正确、HMAC 前置校验设计对、v2 签名块解析质量好、诱饵机制真的骗过人。
所有失分都在「东西放错位置」和「失败后怎么办」。

**2. 唯一真正有效的层是签名校验的判定逻辑，但它被自己的杀进程方式废掉了。**
判定准确（真机日志铁证），但杀进程靠 `abort`/`_exit`/`raise`——三个 PLT 桩，改 4 字节全废。
**这不只影响这一个项目：任何依赖 `abort()` 做 fail-fast 的 Android so 都有这个问题。**

**3. 位置错位的模式是「加密了壳，没加密核」。**

```
现在：.ncguard（密文）= ncVerify 转发壳
      .text  （明文）= 0x238bc 真判定算法 + 两张表

应该：反过来，一行 __attribute__ 的事。
```

### 17.2 六个坑（我在这个项目里实际踩的）

| # | 坑 | 判据 |
|---|---|---|
| 1 | 把「我这次没解开」当成「解不开」 | 评分看攻破所需时间，不看某次尝试成败。我 4 分钟停手 ≠ 加密强 |
| 2 | `.text` 不是明文 | 某函数中途出现 `paciasp`/`autiasp` 且前后风格不一致 = 代码块置换点 |
| 3 | `0x23ae4` 不是 return | 它是 `close` + `log` + `b 0x23bdc` 的中间块。找失败出口看谁被引用 13 次 |
| 4 | 符号名完全不可信 | `__emutls_get_address` 名下挂着校验逻辑 |
| 5 | `wrapped_k_so ^ XOR_KEY` 得到的是诱饵 | 解出来是乱码 → 别据此判断「加密很强」 |
| 6 | **日志文本会骗人** | 日志说「延时 1~3s 后 abort」，实测 19ms `tgkill SIGKILL`。**以抓包/反汇编为准** |

### 17.3 实战中三个反直觉的发现

**① 杀进程的方式决定了防御成败，不是加密强度。**
我的四版包：v1 撞 CRC 死、v2 撞签名校验死、v3 撞复查线程死、v4 改 PLT 活。
**前三版的死因全是「怎么被杀」，没有一次是「被加密挡住」。**

**② `.text` 完整性校验报 clean 是因为基准不可信。**
`0x4e4bc` / `0x4e4cc` 是「crc32(内存A) vs crc32(内存B)」，不是「内存 vs 构建期基线」。
两组都来自同一份改过的 so → 永远相等。
**对比签名校验：它用 `sig_hash.h` 构建期写死的指纹，所以能检出。**

**③ 三个 PLT 桩废掉 30+ 个调用点。**
`abort@plt` 有 30+ 个调用者。逐个 patch 会一直漏（我漏了 `0x24c48` 一次）。
直接改 PLT 表项是正确解法。
**攻击者会优先找这个模式。**

### 17.4 修优先级（含依据）

```
P0-1  kill 链去掉 abort/_exit，改走「静默垃圾数据」
      → 重打包能启动但功能全废，这才是真防住
      → 依据：实战 §11、§12.1

P0-2  .text 完整性校验改构建期基线
      → 现在改 3 处字节仍报 clean
      → 依据：实战 §13.1

P1-1  master 改构建期随机
      → 断绝离线解密 .ncguard
      → 依据：静态 §3.3

P1-2  0x238bc 判定函数 + 两张表移进 .ncguard
      → 一行 __attribute__ 的事，收益大于其余所有
      → 依据：静态 §8.1

P2    不依赖 abort/_exit 做 fail-fast
P3    符号抹除、字符串加密、节名、日志对齐、XOR 碎片
```

**为什么 kill 链排在 `master` 前面**：
`master` 修好只防「读懂」；kill 链修好才防「跑起来」。
对攻击者来说，「拿到代码」的价值低于「做出可用的破解包」。
而且即使 `master` 修好，攻击者仍可 patch `0x238bc` 让判定恒真 + 绕 kill 链。

### 17.5 这套防御的真实水平

| 对手 | 结果 |
|---|---|
| 用 jadx 看 Java 层 | **挡住**（`.ncguard` 密文，so 内无明文字符串） |
| 会 `nm`/`strings`/`readelf` | 10 分钟找到签名校验 |
| 会反汇编 + 算 HKDF | 40 分钟读懂全部逻辑 |
| 会 patch + 重打包 + 抓 tombstone | **70 分钟跑起来** |
| AI 辅助 | **每档再快 3~5 倍** |

**一句话**：能挡住「随便看看」的人，挡不住任何认真的逆向者。

### 17.6 未验证项（诚实清单）

- 反调试/反注入的**拦截能力**：真机八项全 clean，但环境本身干净，只证明无误报
- 常驻复查线程完整逻辑：只看到 `0x24c48` 一处 `abort`
- 13 个校验分支是否全部依赖 `0x23ae4`：静态推断，未逐条验证
- `.ncguard_head` key 能否脱离 `.ncguard` 明文单独求出：本轮靠参照破的
