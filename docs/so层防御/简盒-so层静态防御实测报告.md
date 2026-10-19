# 简盒 SO 层防御实测报告（第一版 + 第二版合并定稿）

> **本文是 so 层防御的唯一定稿。** 由两份独立实测记录合并而成：
> - 第一版（`简盒-so层静态防御实测报告.md`）：基线样本，完整破解 + 真机绕过成功
> - 第二版（`简盒-加固后复测报告.md`）：加固后样本，三次 patch 全失败
>
> **本文的判断基准**：二进制实测 + 真机实测。**源码/提交记录仅作对照参考**，
> 用来区分「设计意图」与「实际效果」。凡是源码声称做了、但实测没生效的，
> 一律以实测为准并标注。**实测与源码冲突时，在对应章节给出源码口径核对结论。**
>
> 合并原则：**不删结论、不改判据**。两份原报告的所有结论、评分、自我更正
> 全部保留；只做三件事——统一编号、补两版对比框架、在源码口径与实测
> 冲突处标注核对结果。原文的自我更正标注（误判、已推翻）一律保留原样，
> 那是这套文档最该看的部分。
>
> 已删除的配套文档（2026-10-19 清理）：
> - `简盒-复核清单.md`（复核方法，其优先级与脚本已并入本文附录 C）
> - 四份 `2026-10-19-*-改动说明.md`（实现侧改动说明，结论已并入
>   `docs/变更历史.md`，不重复保留）
> - `2026-10-19-对复测报告P0质疑的核查.md`（其结论已完整并入本文 §2.10.1，
>   是第二版 P0 被推翻的直接依据）

---

## 0. 合并说明

### 0.1 两份样本

| 项 | 第一版（基线） | 第二版（加固后） |
|---|---|---|
| 样本 | `简盒_signed_23_59_49_sign.apk` | `简盒_signed_09_09_37_sign.apk` |
| SHA-256 | `9a82f0e209f96eb2878f17f22d1b9331d12e7686995e1908df299f8a7897745f` | `6a1365be0d4f777ba005059d1efb689a90e20d057840f167223c4a5dcf995f28` |
| `libnc.so` | 348,128 B | 358,064 B（+9,936 B） |
| 工作目录 | `~/jianhe_re_work/` | `~/nb2/`（与第一版完全隔离） |
| 真机 | Redmi 2602BRT18C / Android 16 (API 36) / arm64-v8a | 同左 |
| 结果 | 完整破解 + 真机稳定运行 | 三次 patch 全失败 |

### 0.2 评分对比（速览）

```
第一版：静态 ★★☆☆☆ 2.5 / 10   实战 ★☆☆☆☆ 1.5 / 10
第二版：静态 ★★★★☆ 6.5 / 10   破解 ★★★☆☆ 5.5 / 10

两版对比：+4.0 分，实质性加固
```

### 0.3 两版差异的本质

第一版的核心指控是「**加密做对了，加密的东西不对**」——判定算法和密钥
都躺在明文。第二版把这两样都搬进了密文，并意外获得了「kill 链与解密
流程耦合」的收益。

**但外围没动**：JNI 符号、`.rodata` 字符串、节表名三项与第一版完全一致。
第二版的结论「核心机密保住了，外围地图还在」即由此而来。

---

# 第一部分 第一版：基线实测（完整破解）

> 本部分为第一版报告的完整内容，编号已改为 `1.x` 以便与第二部分区分。
> 结论与自我更正全部按原文保留。

## 1.0 结论速览

| 项 | 结果 |
|---|---|
| 盲测定位签名校验核心 | **4 分 1 秒** |
| 完整离线破解（解密两段 + 反推算法） | **约 40 分钟** |
| 从零到产出可在真机运行的绕过包 | **约 70 分钟** |
| **静态防御综合评分** | **★★☆☆☆ 2.5 / 10** |
| **实战（真机验证）评分** | **★☆☆☆☆ 1.5 / 10** |
| 最致命缺陷 | ① `master[32]` 全是 `0x11`；② 真正判定算法不在加密段；③ kill 链全走 PLT 软目标 |

**一句话结论**：签名校验逻辑本身写对了、也真的检出了，但**杀掉进程的手段
全部集中在 `abort` / `_exit` / `raise` 三个 PLT 表项上**——改 4 个字节，
30+ 个调用点全废。最终产物在同签名校验全开的情况下，**稳定运行在前台，
无崩溃、无 ANR**。

**本部分分两块**：
- **§1.1–§1.8 静态分析**：只读逆向，全程不运行，不修改 APK
- **§1.9–§1.14 实战修改**：真机 patch + 重打包 + 重签名 + 运行验证

### 1.0.1 操作边界与可复现路径

工作目录集中在 `~/jianhe_re_work/`：

```
jianhe_re_work/
├── target.apk              # 原 APK 副本（原文件未被修改）
├── T0_start.txt            # 计时起点 2026-10-19 00:52:28
├── probe_ncguard.py        # 离线解密验证脚本
├── ncguard_dec.bin         # 解密后的 .ncguard（32,540 B）
├── libnc_unlocked.so       # .ncguard 已被明文替换的 so（用于反汇编）
└── ex/                     # 解包工作区
    ├── classes.dex                     7,083,500 B
    ├── lib/arm64-v8a/libnc.so            348,128 B
    └── lib/armeabi-v7a/libnc.so          214,644 B
```

原 APK 仅做过一次 `cp` 读取，未被改动。

### 1.0.2 时间线

| 阶段 | 起止 | 耗时 | 产出 |
|---|---|---|---|
| 盲测定位（不知源码） | 00:52:28 → 00:56:29 | **4 分 1 秒** | 找到签名校验核心逻辑 |
| 源码核对 | — | ~25 分钟 | 确认 `master` 占位符、诱饵机制 |
| 离线解密 `.ncguard` | — | ~8 分钟 | 32,540 B 明文 |
| 反推校验算法 | — | ~5 分钟 | 通过校验所需的 32 字节输入 |
| **合计** | | **约 40 分钟** | 完整攻破 |

「4 分 1 秒」这个数字的含义要说清楚：它只统计到**找到关键逻辑**。
完整攻破是 40 分钟。两者都重要——前者衡量防御能否拖住「快速试探」，
后者衡量能否拖住「认真破解」。

---

## 1.1 防御逐条实测

按实际发现顺序编号，与当次汇报一一对应。

### 1.1.1 #0 自定义节布局实名暴露

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
                                .text .plt .data.rel.ro .fini_array
                                .dynamic .got.plt .bss .comment .shstrtab
```

**同 APK 其他 so 一个自定义节都没有**，全是 NDK 标准节。`libnc.so`
独有 4 个非标准节，名字全是自解释英文。

源码注释（`so-section-lock.py:46`）写：

```python
SECTION_NAME = '.ncguard'   # 加密代码段（Xop 用 .bitcode，改名避开指纹）
```

**「改名避开指纹」这个目的没有达到。** 换个角度想：Xop 用 `.bitcode`
能躲，是因为 `.bitcode` 是 LLVM 的标准节名，混在正常产物里不显眼；
`.ncguard` 恰好相反——任何见过 Android so 的人都知道 `.ncguard`
不是标准节。改了一个「明显不像标准」的名字，比不改更容易被注意到。

**正确做法**：让节名混入标准集合（`.rodata`、`.data.rel.ro`），
或 `objcopy --rename-section .ncguard=.rodata` 合并进只读段，
运行时靠 `mprotect` 补执行权限（`mprotect` 本来就已导入）。

> **源码口径核对（合并时补）**：第一版样本的节名 `.ncguard` / `.nckey` /
> `.nckey_stub` 在当前源码中已全部更名为 `.ncx` / `.nck` / `.ncks`
> （`scripts/lib/so-section-lock.py:47-48`、`nc_guard_boot.c:64-72`）。
> 更名本身没有隐藏存在性——节表仍可 `readelf -SW` 一条命令列出。

### 1.1.2 #1 导入符号表完整暴露防御清单

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

### 1.1.3 #2 `.comment` 泄漏编译器指纹

```
Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4
Linker: LLD 18.0.4
```

`.note.gnu.build-id`：`b6aa57b4a65f9f712adc9e12ae573b5f975d7ea4`

build-id 是原始构建的稳定指纹。改了字节但 build-id 对不上，
就能判定被 patch 过。

> **源码口径核对（合并时补）**：当前源码 `lib-ndk.sh:56` 的
> `LOCAL_LDFLAGS` 已含 `-Wl,--build-id=none`，`.note.gnu.build-id`
> 已不再生成。

### 1.1.4 #3 `.ncguard` 段确实加密（但见 §1.3 的破解）

```
000000000004e8c4 <Java_com_nc_link_NcLink_ncVerify>:
    4e8c4: 702da388     	adr	x8, 0xa9d37
    4e8c8: 7b561c36     	<unknown>
    4e8cc: 595d0820     	<unknown>
    4e8d0: 0d564a85     	<unknown>
    ...
```

仅首条指令合法，后续全部 `<unknown>`。**加密本身有效**，
静态反汇编直接失败。

**但注意**：这只说明「我没有立刻读出明文」，不说明「读不出来」。见 §1.3。

### 1.1.5 #4 错误日志字符串把防御架构完整泄底

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

第 6 条设计正确——直接读 v2 签名块使 hook `PackageManager` 失效。
但 `APK Sig Block 42` 明文字符串躺在 `.rodata`，等于告诉了攻击者从哪儿下手。

> **源码口径核对（合并时补）**：LSGS 密文机制（`make-sig-log.py`）现已
> 覆盖 `sig_check.c` / `env_check.c` / `sig_guard2.c` 的 `/*LSG:...*/`
> 标记，构建期扫描加密，so 里只有密文。上表中的 `/proc/self/maps` 等
> 路径字面量确实已密文化（`env_check.c` 通过 `lsg_s(LSGS_PATH_MAPS, ...)`
> 取用）。第二版实测（§2.2）仍能看到这些字符串，说明**该样本未包含
> 本轮 LSGS 修复**——两版样本的时间点不同，属预期差异，非机制失效。

### 1.1.6 #5 `.nckey` 存在明文段表描述符

`.nckey_stub`（0x16634，96B）第 28 字节起是一段小端 32 位整数：

```
01664c  34 66 01 00  → 0x00016634 = 91700    ← .nckey_stub 自身偏移
016650  e4 e9 04 00  → 0x0004e9e4 = 321508   ← .ncguard_head 偏移
016654  28 0a 00 00  → 0x00000a28 = 2600     ← .ncguard_head size
016658  e0 ff 01 00  → 0x0001ffe0 = 131040   ← .text 偏移
01665c  e8 6a 02 00  → 0x00026ae8 = 158440   ← .text size
```

**明文段表描述符**：`{self_offset, guard_head_offset, guard_head_size, text_offset, text_size}`。
加密器的元数据原封不动写进了二进制。

两个槽都以固定魔数 `30 72` 开头（见 §1.6.3），固定 96 字节，相邻偏移。
**定位成本 = 0。**

### 1.1.7 #6 加密覆盖错位——判定分支留在明文段

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

**失败逻辑一目了然**：`cmp w0, #0` / `b.ne` / `mov w0, #-100`。
返回值 `0` 成功、`-100` 失败。

**架构错位**：`.text` 明文装调度逻辑、返回值判定；`.ncguard`
加密只装被调用的函数体。逆向者不需解开 `.ncguard`，读明文就能画出流程。

> **源码口径核对（合并时补）**：这是第一版最致命的缺陷，也是第二轮
> 加固的主攻点。当前源码 `nc_link.c:37-85` 已把判定函数 `nc_verify_t1`
> 标进 `.ncx`、两张表 `SIG_SALT` / `SIG_HASH_STORED` 标进 `.ncxr`
> （`protect.sh:473-483` 同步把两个段都交给锁箱器）。**该缺陷在
> 第二版样本中已修复**（见 §2.3.1）。

### 1.1.8 #7 `.text` 存在函数级代码块置换（唯一真挡住一轮的防御）

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

这是**函数级代码块置换**：校验逻辑塞进 libc++ 静态链接函数中间，
符号表标成 `__emutls_get_address` / `__cxa_guard_acquire`，属于**符号欺骗**。

相关 `.rodata` 内容：

```
0114bd  ro.arch
0114cd  getULEB128
0114d7  fp
0114da  d7
011921  exynos9810
011931  unsupported arm64 reg
```

`exynos9810` 是三星 Exynos 9810，ARM64 已知的 UMO
（Unpredictable Memory Ordering）芯片，常用于真机/模拟器判定。
`getULEB128` 说明有 DWARF unwind 解析。

**这是本样本唯一有效的静态防御层**——我第一次读 `0x42270` 时确实
误判成「明文业务逻辑」，看到 `paciasp` 突兀出现才纠正。

**判据**（给后来者）：如果某函数中途出现 `paciasp`/`autiasp`
且前后风格不一致，就是置换点。

### 1.1.9 #8~#9 签名校验函数全貌（明文 `.text` 内）

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

这是一段**逐字节手工实现的 APK Signing Block v2/v3 解析器**。
实现质量不错：有下溢保护（`csel x21, xzr, x8, lo`）、有边界检查、
有标签精确匹配。**绕过 `PackageManager` 的常规 hook 确实无效**。

**但定位成本近乎为零**，三个原因：

1. **符号表直接点名**：整个校验是 `selftest` 的内联体，跨约 5.7KB
2. **魔数全在明文立即数里**：`0x06054B50`、`0x7109871A`，`grep` 即中
3. **失败汇聚点可见**：`23cf4: cbnz w0, 0x23ae4`

### 1.1.10 #10 单一失败出口 = 单点绕过

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

**13 个校验分支 → 1 个汇聚点。** 处理一处，13 个全失效。
典型 patch：在 `0x23ae4` 写 `b 0x23bdc`。

**设计缺陷**：校验分散、失败路径集中。良好的反篡改设计应使失败路径
分散且各不相同。

> **源码口径核对（合并时补）**：当前源码已改为三个独立函数体
> `delayed_kill_0/1/2`（`sig_check.c:833/865/889`），按 variant
> 分派，且三个都标进 `.ncx` 加密段（`sig_check.c:744`）。
> 「三份独立函数体」的纪律写在注释里：共用函数 = 一处 patch 全废，
> 参数化只改变量不改控制流。**第二版实测证实静态不可见**（§2.2.4），
> 但报告统计出的「13 次引用」是把 `heartbeat` 的地址当成了失败路径——
> 该统计方法本身是错的（见 §2.10.1）。

### 1.1.11 #11 第二层：后台 detached 校验线程

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

`0x24b20` 是后台校验线程入口——反调试 + maps 扫描 + `/proc/net/tcp`
实际跑的地方。这解释了 `.bss` 的 146KB。

线程为 **detached**，patch 返回值时它可能已在运行。这是设计上的一个
真实优势。

---

## 1.2 完整破解过程（第一版的核心）

### 1.2.1 破解链总览

```
APK 签名块（明文）
  └─ certDER ──SHA256──┐
                        ├─→ HKDF-SHA256(ikm=master, salt, info="nc-so-v1"+pkg, 16)
master[32]（.rodata）  │        └─→ k_so
包名（Manifest）───────┘             └─→ RC4 解 .ncguard（32,540 B）→ 明文
                                                               └─→ 读出 ncVerify
```

### 1.2.2 密钥派生参数（源码静态阅读 + 二进制验证）

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

### 1.2.3 `master[32]` 是占位符（最致命缺陷）

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

`master` 全项目只出现在 `nc_guard_boot.c:423` 一处，`static const`
硬编码，**没有任何构建期替换机制**。

> **源码口径核对（合并时补）**：当前源码已彻底改为
> `so-section-lock.py:574` 的 `master = os.urandom(32)`，且 master
> 落进 `.ncxhr` 段后由二级锁箱用 `k_stub` 加密（`nc_guard_boot.c:249-250`
> 的 `ncg_master[32]` 标在 `NCG_HEAD_RO`）。第一版「`od` 一条命令读出」
> 的路径**在当前源码中已不存在**，第二版实测零命中（§2.4.1）。

### 1.2.4 实测解密成功

`probe_ncguard.py` 执行结果：

```
signing block id = 0x7109871A
certDER len = 666
certDER sha256 = d82e48dae7ce6268ebcefd61feb8128fdf1a55f574cbbbc788db7be4491b689e
k_so = 81830c13771b64b8de9a2d4642e19029
.ncguard addr=0x46ac8 off=0x46ac8 size=0x7f1c
decrypted head: c0035fd6fd7bbaa9fc6f01a9fd030091fa6702a9f85f03a9f65704a9f44f05a9
```

解密首字节 `c0 03 5f d6` = `ret`；接 `fd 7b ba a9` =
`stp x29,x30,[sp,#-0x60]!`——**标准函数序言**。

32,540 字节全部解开。

### 1.2.5 `ncVerify` 解密后：只是个转发壳

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

### 1.2.6 真正的判定算法在明文 `.text 0x238bc`

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

反推得到的 32 字节通过值**不在本文记录**（避免给出可直接使用的绕过凭据）。
正向自检 `True`，算法正确。

> **源码口径核对（合并时补）**：当前源码 `nc_link.c:158-179` 的
> `nc_verify_t1` 与上表算法逐字节同源，两张表 `SIG_SALT` /
> `SIG_HASH_STORED` 由 `make-sig-hash.sh:85-92` 生成
> （`stored = t1[i] ^ salt[i%16] ^ ((i*0x9E)&0xFF)`）。算法未变，
> 变的是位置——现已标进 `.ncx` / `.ncxr` 两个加密段。

### 1.2.7 破解结论

**两条路通向同一结论：**

- **不解密 `.ncguard`**：`ncVerify` 的符号名已暴露，读 `0x4e8c4`
  附近的明文 xref 就知道它转调 `0x238bc`，直接看明文判定函数
- **解密 `.ncguard`**：确认 `ncVerify` 确实是转发壳

**`.ncguard` 加密对这次破解的贡献是零。** 8 分钟的解密只换来一个
「原来里面是转发器」的确认。

---

## 1.3 `.nckey` 诱饵机制（真实有效的防御）

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

我在分析中段曾用 `wrapped_k_so ^ XOR_KEY` 算出过一个「k_so」，
并据此断言能解开——那个值是**诱饵**，解出来是乱码。
这是真实有效的防御。

**但诱饵的强度止步于此**：它只挡住「不懂源码结构的人」。
一旦知道真实派生公式（公式就在 `.rodata` 字符串和明文代码里可推），
诱饵就失效了。

> **源码口径核对（合并时补）**：当前源码 `so-section-lock.py:658-662`
> 已把诱饵改为 `os.urandom(16)` 真随机（`_decoy_seed` / `_decoy_mac`）。
> 修的是第二版 §2.7.1 的识破手法——两版样本的 `wrapped_k_so`
> 一字不差，攻击者 diff 两个 so 就能认出诱饵，不需要懂任何密码学。
> 现有 T17 回归断言「两次构建的 `wrapped_k_so` 必须不同」。

---

## 1.4 `XOR_KEY` 碎片化：实测未生效

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

顺序与源码声明完全一致，每个 `uint16_t` 后 2 字节零填充。
`volatile` 只阻止编译器优化掉访问，**不加密初始值**。

按 `:141` 的规则（`i<4` 取低位，`i>=4` 取高位）重排 8 次
即得完整 `XOR_KEY`：

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

**碎片化没有降低攻破成本**（都是一条 `od` + 8 次心算），
只增加了约 30 秒理解重排规则的时间。从「降低可读性」
变成了「降低了一点点可读性」。

**真正的修法**：碎片不能是 `.data` 里的初始值。应改为运行期从其他
来源派生（如与 `.text` 的 crc32 混合、从证书派生），或干脆去掉这个
中间层——因为它保护的 `k_so` 本身已改为证书派生，`XOR_KEY`
的实际价值已经很低。

> **源码口径核对（合并时补）**：当前源码的碎片机制已演进两层：
> ① 四个碎片从「4 个 noinline 函数的立即数」改为「4 个独立 volatile
> 变量」（`.data` 而非 `.rodata`），修的是 LLVM 函数间常量传播把
> 完整 8 字节密钥折回 `.rodata`（源码注释记录了实测：
> `boot.o 0x5b0/0x5b8` 各一份连续 8 字节，HEX 一搜即中）；
> ② `k_stub` 进一步改为 `HKDF(master, slot_seed, crc32(自身代码区间))`
> 的前 16 字节（`nc_guard_boot.c:703-756`），改任何一处 stub 代码 →
> CRC 变 → `k_stub` 变 → head 段解出乱码。第一版「碎片整齐排在
> `.data`、一条 `od` 重排即得」的静态读取路径，**在当前源码中
> 已被 CRC 自绑定挡了一层**——但 `.data` 里的四个 `uint16` 初始值
> 本身仍可静态读出，读者需自行判断剩余价值。

---

## 1.5 其他实测发现

### 1.5.1 契约注释自相矛盾

`nc_guard_probe.c` 同一段里写了两个值：

```c
/* 对拍契约：ncguard_probe(0) == ((0^0x5A)+0x0F)*3 & 0xFF == 59。
    取值刻意不取 42/0/1 这类哨兵值，避免 strings 一眼定位。 */   ← 说"刻意不取 42"
...
/* 对拍契约：ncguard_probe(0) 必须返回 0x2A（42）。 */            ← 紧接着说要 42
```

实测算式：**(0 ^ 0x5A) + 0x0F) * 3) & 0xFF = 59 = 0x3B**。
前一句对，后一句是过期注释。

顺带一个讽刺点：注释说「刻意不取 42/0/1 哨兵值，避免 strings 一眼定位」，
但写法是硬编码算术常量，编译后就是 `eor`/`add`/`mov` 三条立即数指令，
`llvm-objdump` 一眼可见。**这个反定位意图没有实现。**

> **源码口径核对（合并时补）**：核对当前源码，`nc_guard_probe.c:49-56`
> **两处矛盾注释依然存在**（一处写 59，一处写 42），本轮未清理。
> 函数体算出的确定是 59。这是文档债，不影响功能，但会持续误导
> 读代码的人（包括 AI）。建议后续清理时把 `0x2A（42）` 那句删掉。

### 1.5.2 ~~`reserved8` 字段实际非零~~ 【已更正：本条为误判】

> **⚠️ 2026-10-19 更正**：本节原结论（`reserved8` 非零）是**误判**，已推翻。
>
> **错误原因**：把 `expect_mac` 的字段长度当成 16 字节，实际是 **32 字节**。
> 因此后续字段整体前移 8 字节——看到的 `10d2cadf...` 位于 `0x50`，
> 是 `pkg_sha8`，不是 `0x58` 的 `reserved8`。
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
> 原报告其它章节中凡引用本节结论的，均不受影响
> （该结论未被用于任何安全判断）。

### 1.5.3 magic 换形式但结构性冗余仍在

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

**没做对的**：`SLOT_MAGIC_SEED[0:2] == STUB_MAGIC_SEED[0:2] == 0x30 0x72`。
两个槽共享 2 字节前缀，加上「96 字节 + 相邻偏移」的特征，
我靠这个匹配一眼认出两个槽。

**修法**：让两个槽的 magic 互不相关，或干脆不设 magic——
用段头表 size 字段判「是否已锁」。

### 1.5.4 编译器常量明文

`NCG_XOR_KEY` 旧值仍在 `.rodata`：

```
013450  5a c3 11 9e f0 37 b2 6d b9 43 81 78 78 a7 57 e7
```

来自历史存档 `nc_guard_unlock.c:77`（该文件头已标注「历史存档，
不要再参考」）。现行实现用碎片（见 §1.4），但旧常量仍被编进产物。

### 1.5.5 `master` 附近的其他明文

`.rodata 0x13400` 是表A，`0x13440` 区域还有：

```
013440  a2 69 00 00 a3 69 00 00 01 00 02 03 00 01 03 02
```

`0x69a2`、`0x69a3` 疑似紧邻的其他表的地址/偏移量。这些辅助常量也在明文。

---

## 1.6 强度评分与理由

评分基准：**以实测破解难度为准**，不以设计意图为准。

### 1.6.1 星级总表

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

### 1.6.2 两个总分

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

### 1.6.3 为什么静态是 2.5 而不是 3.5（早期误判的修正）

本报告早期版本给过 **3.5 / 10**，依据是「`.ncguard` 加密有效，
我 4 分钟没解开」。**这个评分是错的**，原因有两层：

**第一层：把「我没解开」误当成「解不开」**
4 分钟没解开，不是因为加密强，而是因为**我当时按时间预算停了**。
给出 8 分钟算 HKDF，就解开了。评分应以「攻破所需时间」为准，
不以「某次尝试是否成功」为准。

**第二层：更根本的——解开 `.ncguard` 本身没有价值**
即使不解开，也能攻破。因为真正判定的 `0x238bc` 从来不在加密段里。
所以给 `.ncguard` 加密打 4 星，是把「一个对结果无影响的层」评高了。

`2.5` 这个分数的含义是：**这套防御能挡住「用 jadx 打开看看」的人，
挡不住任何知道该看哪儿的人。**

### 1.6.4 为什么实战再降到 1.5

静态 2.5 测的是「能不能看懂」。实战测的是「能不能跑起来」。
后者才是攻击者真正要的。

实测结果：**从零到能在真机前台稳定运行的绕过包，全程约 70 分钟，
10 处 patch，每处不超过 8 字节。**

降分理由：

1. **签名校验虽然检出了，但杀不掉我**——因为杀进程的手段是
   `abort`/`_exit`/`raise`，全走 PLT
2. **`.text` 完整性校验全程报 `clean`**——我改了 3 处 `.text` 字节，它没发现
3. **两段加密都解开了**——`.ncguard` 靠 `master` 占位符，
   `.ncguard_head` 靠拿 `.ncguard` 明文当参照

**1.5 分给的是什么**：签名校验那层逻辑真的写对了（这是 ★★★★★ 那一项）。
问题不在逻辑，在「检出之后怎么办」。

### 1.6.5 各层在实战中的实际作用

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

唯一真正拦住过我的是第 ④ 步的**第一轮尝试**（`k_stub` 算错导致 SIGILL），
但那是技术细节，不是设计强度——换个方法（频率分析）就破了。

---

## 1.7 给 AI 的总结（第一版）

> 本节写给后续接手的 AI。人读完 §0 结论速览和 §1.6 评分表就够了。

### 1.7.1 结构性问题：加密层装错了东西

**最该理解的一件事**：这套体系里，加密做对了、诱饵做对了、
签名块解析做对了，但**加密的东西不对**。

```
现在：  .ncguard（密文）= ncVerify 转发壳
        .text    （明文）= 0x238bc 真正的判定算法 + 两张表

应该：  .ncguard（密文）= 0x238bc 判定算法 + 两张表
        .text    （明文）= ncVerify 转发壳
```

这是一个 `__attribute__((section(".ncguard")))` 的位置问题，
不是加密算法问题。**改这一处，收益大于所有其他改动之和。**

### 1.7.2 五个容易踩的坑（第一版作者踩过）

1. **`.text` 不是明文**。`llvm-objdump` 输出看着正常，是因为有函数级
   置换 + libc++ 符号欺骗。判据：某函数中途出现 `paciasp`/`autiasp`
   且前后风格不一致 = 置换点。
2. **`0x23ae4` 不是 return**。它是 `close` + `__android_log_print` +
   `b 0x23bdc` 的中间块。找失败出口不能只看 `ret` 前的块，
   要看谁被引用 13 次。
3. **符号名完全不可信**。`__emutls_get_address` 名下挂着校验逻辑。
   按符号做语义推断会把人带偏。
4. **`wrapped_k_so ^ XOR_KEY` 得到的是诱饵**。别拿它当真实密钥用，
   会解出乱码然后误判「加密很强」。
5. **历史存档文件不能当真**。`nc_guard_unlock.c` 头部已标注
   「不要再参考」，但里面的常量仍被编进产物。读源码前先看文件头的
   时效声明。

---

# 第一部分（续）第一版实战：真机 patch 与验证

> **区分标记**：以下所有内容都是**实际修改了二进制并运行验证**的，
> 与上面的纯静态分析不是一回事。

## 1.8 实战时间线与产物

### 1.8.1 时间线

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

### 1.8.2 产物清单

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

## 1.9 四次尝试：每一版为什么失败

### 1.9.1 第 1 版：只 patch 判定函数 → SIGILL

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

**原因**：改 `.text` → `crc32(.text)` 变 → `k_stub` 错 →
`.ncguard_head` 解出乱码 → 执行密文。

**这一版的教训**：**代码自绑定（CRC 混入密钥）真的有效**。
我改一个字节，整个二级锁箱就废了。

但注意 `#01 pc 0x0002290c` 这个帧——它揭示了关键结构（见 §1.9.2）。

### 1.9.2 第 2 版：两段都填明文 → 仍闪退

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

### 1.9.3 第 3 版：patch kill 链 → 活 30 秒

**拿到 `sigcheck_log.txt` 后**，确认了完整链条：

```
【成功】证书 DER 提取成功 (der_len=744)
nc: fp=a3b08bf6...                          ← 我的重签名
【数据】实际证书指纹 actual_fp (a3b08bf6...)
【E】nc: mm
【失败】指纹比对不一致 → 校验失败,延时退出已安排
【流程】延时退出线程启动:随机延时后 abort (delay=1~3s)
```

**注意日志说「延时 1~3 秒」，但实测只延了 19 毫秒**——
日志和实际行为不符。

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

### 1.9.4 第 4 版：patch PLT 桩 → 稳定运行

**关键洞察**：搜出来 `bl abort@plt` 有 **30+ 处**。
逐个改效率极低，而且永远可能漏。

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

## 1.10 最终攻击清单（10 处 patch）

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

**共 11 处，其中 8 处是 4~8 字节的指令级 patch。
真正的核心工作量是前两处的离线解密。**

### 1.10.1 三个 PLT 桩是最有价值的发现

```
改前：0x4f6a0: adrp x16, 0x55000 / ldr x17, [x16,#0x280] / add x16,x16,#0x280 / br x17
改后：0x4f6a0: ret
```

**一个 `ret`（4 字节）废掉 30+ 个 `abort()` 调用点。**

这是 Android so 的通用结构问题——所有 `abort` 调用都汇到同一个
PLT 表项。**任何依赖 `abort()` 做 fail-fast 的设计，
都会被这一个点废掉。**

## 1.11 真机实测暴露的三个新问题

这三个问题在纯静态分析里看不到，只有跑起来才发现。

### 1.11.1 `.text` 完整性校验从来没生效过

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

**两次 CRC 都是对着运行期内存算的，然后互相比对。**
这不是「内存 vs 构建期基线」，是「内存 vs 内存」。

如果两组都来自同一份被改过的 so，当然相等 → `clean`。

**对比签名校验**：它用的是构建期写进 `sig_hash.h` 的证书指纹，
是可信基线，所以正确检出。

**`.text` 完整性校验缺的正是这个「可信基线」。**

> **源码口径核对（合并时补，重要）**：本节原判断「基准不可信、
> 内存 vs 内存」**是错的**，已被推翻。当前源码
> `env_check.c:1095` 的 `self_text_crc_probe` 明确是
> **磁盘 vs 内存**：
> - 磁盘侧：`safe_syscall(__NR_openat)` + `pread64` 把 so 文件
>   的 `.text` 读进 `fb`，算 `cf = env_crc32(fb, ...)`
> - 内存侧：`env_crc32(mem, ...)` 算 `cm`
> - 比对 `cf != cm`
>
> 而且磁盘侧走 syscall 直调（防 `fopen` hook 喂假内容）。
> 第一版看到的现象（改 3 处仍报 clean）的**真正根因不是基准问题**，
> 而是 `env_mem_readable()` 要求区间完整落在单条 maps 记录里，
> `.text` 与 `.eh_frame` 同页必跨两条 → 函数返回 0 → 探针直接
> `return 0` 放弃校验。「读不到」被当成了「没问题」。
> 该缺陷已修为游标推进式扫描（`env_check.c:858`），
> 并有 `test-mem-readable.sh` 6 个正负向用例钉死。
>
> **但「能读到」不等于「能发现被改」**——修复后的真机行为
> （改一个字节日志是否从 `clean` 变 `hit`）**仍未验证**，
> 需真机 patch 对照实验。这是本文已知的最大未验证项之一。

### 1.11.2 日志描述与实际行为不符

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

从反汇编看，`0x25474` 是 `bl 0x25c14`，而 `0x25c14` 里是
`tgkill(pid, tid, SIGKILL)` + `raise(SIGKILL)` + `_exit(127)`。

**「延时 1~3s 后 abort」和「立即 tgkill SIGKILL」是两套完全不同的
行为。** 日志文本误导了排查方向——我一开始以为有 1~3 秒窗口可利用，
实际没有。

> **源码口径核对（合并时补）**：该日志文案本身是 LSGS 标记
> `/*LSG:KILL|【流程】延时退出线程启动:随机延时后 abort(校验失败后的反应)*/`
> （`sig_check.c:836` 附近），源码里确实同时存在「延时」与「立即
> tgkill」两条路径。日志与实测的落差源于**路径选择与文案不匹配**，
> 是真实缺陷，非记录错误。

### 1.11.3 反调试/反注入全部报 clean（未验证拦截能力）

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

这只能证明「没有误报」，**不能证明「有 frida 时能检出」**。
要验证拦截能力，需要在设备上真开 frida 再测。**本轮未做。**

> **源码口径核对（合并时补）**：`libc_hook_probe` 现已从 4 个函数
> 扩到 8 个（新增 `mprotect` / `mmap` / `dlopen` /
> `process_vm_readv`），专门覆盖第二版 §2.13.3 指出的
> 「hook mprotect 拿明文段」这条动态路径。符号名走 LSGS 密文。
> 实测 8 函数 13.85 μs、p99 44 μs，每 20 秒一次，CPU 占比 0.00007%。
> **但「hook 后能被发现」与「hook 被阻止」是两件事**——
> 解密后明文必然在内存里，这是自解密机制的物理上限。

## 1.12 实战结论（第一版）

### 1.12.1 这套防御在真实攻击者面前能撑多久

| 攻击者水平 | 预期耗时 | 依据 |
|---|---|---|
| 只会用 jadx 看 Java 层 | **挡住** | `.ncguard` 密文 + so 里没字符串 |
| 会 `nm` / `strings` / `readelf` | **10 分钟找到签名校验** | 符号明文导出 |
| 会反汇编 + 会算 HKDF | **40 分钟读懂全部逻辑** | `master` 占位符 |
| 会 patch + 重打包 + 会抓 tombstone | **70 分钟跑起来** | PLT 桩软目标 |

**AI 辅助的话，每个档位再快 3~5 倍。**

### 1.12.2 唯一真正有效的设计（一句话）

**签名校验的判定逻辑**。它确实算出了正确指纹、确实比对失败、
确实打了日志——这部分代码质量没有问题。

**问题全部出在「检出来之后怎么办」**：杀进程的手段集中在 PLT 软目标上，
一处 patch 全废。

### 1.12.3 如果只改一处

**不是改 `master`，是改 kill 链。**

理由：
- `master` 改了，`.ncguard` 打不开 → 但攻击者还是可以 patch
  `0x238bc` 让判定恒真，然后绕过 kill 链
- kill 链改了（不用 `abort`/`_exit`，改成「悄悄走垃圾数据路径」），
  攻击者重打包后 App 能启动但**功能全废**——这才叫真的防住

**`master` 是第二优先。** 它防的是「读懂逻辑」，kill 链防的是
「跑起来」。对攻击者来说后者的价值更高。

### 1.12.4 未验证项（诚实清单）

- 反调试/反注入的**拦截能力**（本轮环境干净，八项全 clean，只证明无误报）
- 常驻复查线程的完整逻辑（只看到 `0x24c48` 这一处 `abort`）
- 13 个校验分支是否真的全部依赖 `0x23ae4`（静态推断，未逐条验证）
- `.ncguard_head` 的 key 是否能脱离 `.ncguard` 明文单独求出
  （本轮是靠参照破的）

---

## 1.13 附录 A：第一版静态分析关键地址速查

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

## 1.14 附录 B：第一版实战 patch 地址速查

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

1. 确认加密方式：对密文按 `mod 16` 分组统计字节熵。
   若各位置熵 < 8 且有主导字节 → 16 字节循环 XOR。
2. 取一段已知明文（本例是 `.ncguard`，因为它的密钥链全开放），
   按 `mod 16` 分组统计分布。
3. 对 head 密文的每个 `mod 16` 位置，枚举 256 个 key 候选，
   算解密后与该位置明文分布的**余弦相似度**。
4. 取相似度最高者。**验证方法**：如果解出的片段落在合法 AArch64
   指令族（如 `i%4==3` 位置是 `a9/d1/91/f9`），说明对了。
5. 本例中 3 个已知 key 字节（`0x63`/`0x95`/`0xe6`）全部命中验证，
   方法可靠。

**关键前提**：需要一个「同源编译器产出的已知明文」做参照。
攻击者能拿到它，是因为 `.ncguard` 的密钥链（`master`）是开放的。

## 1.15 给 AI 的完整总结（第一版）

### 1.15.1 先读这三条

**1. 这套防御的加密算法没问题，装配有问题。**
RC4 实现正确、HMAC 前置校验设计对、v2 签名块解析质量好、
诱饵机制真的骗过人。所有失分都在「东西放错位置」和「失败后怎么办」。

**2. 唯一真正有效的层是签名校验的判定逻辑，但它被自己的杀进程方式
废掉了。** 判定准确（真机日志铁证），但杀进程靠
`abort`/`_exit`/`raise`——三个 PLT 桩，改 4 字节全废。
**这不只影响这一个项目：任何依赖 `abort()` 做 fail-fast 的
Android so 都有这个问题。**

**3. 位置错位的模式是「加密了壳，没加密核」。**

```
现在：.ncguard（密文）= ncVerify 转发壳
      .text  （明文）= 0x238bc 真判定算法 + 两张表

应该：反过来，一行 __attribute__ 的事。
```

### 1.15.2 六个坑（第一版作者在这个项目里实际踩的）

| # | 坑 | 判据 |
|---|---|---|
| 1 | 把「我这次没解开」当成「解不开」 | 评分看攻破所需时间，不看某次尝试成败。我 4 分钟停手 ≠ 加密强 |
| 2 | `.text` 不是明文 | 某函数中途出现 `paciasp`/`autiasp` 且前后风格不一致 = 代码块置换点 |
| 3 | `0x23ae4` 不是 return | 它是 `close` + `log` + `b 0x23bdc` 的中间块。找失败出口看谁被引用 13 次 |
| 4 | 符号名完全不可信 | `__emutls_get_address` 名下挂着校验逻辑 |
| 5 | `wrapped_k_so ^ XOR_KEY` 得到的是诱饵 | 解出来是乱码 → 别据此判断「加密很强」 |
| 6 | **日志文本会骗人** | 日志说「延时 1~3s 后 abort」，实测 19ms `tgkill SIGKILL`。**以抓包/反汇编为准** |

### 1.15.3 实战中三个反直觉的发现

**① 杀进程的方式决定了防御成败，不是加密强度。**
我的四版包：v1 撞 CRC 死、v2 撞签名校验死、v3 撞复查线程死、
v4 改 PLT 活。**前三版的死因全是「怎么被杀」，
没有一次是「被加密挡住」。**

**② `.text` 完整性校验报 clean 是因为基准不可信。**
`0x4e4bc` / `0x4e4cc` 是「crc32(内存A) vs crc32(内存B)」，
不是「内存 vs 构建期基线」。两组都来自同一份改过的 so → 永远相等。
**对比签名校验：它用 `sig_hash.h` 构建期写死的指纹，所以能检出。**

> **本条已被源码推翻**，见 §1.11.1 的核对结论。

**③ 三个 PLT 桩废掉 30+ 个调用点。**
`abort@plt` 有 30+ 个调用者。逐个 patch 会一直漏
（我漏了 `0x24c48` 一次）。直接改 PLT 表项是正确解法。
**攻击者会优先找这个模式。**

### 1.15.4 修优先级（第一版给出，第二轮已逐项回应）

```
P0-1  kill 链去掉 abort/_exit，改走「静默垃圾数据」
      → 重打包能启动但功能全废，这才是真防住
      → 依据：实战 §1.9、§1.10.1

P0-2  .text 完整性校验改构建期基线
      → 现在改 3 处字节仍报 clean
      → 依据：实战 §1.11.1

P1-1  master 改构建期随机
      → 断绝离线解密 .ncguard
      → 依据：静态 §1.2.3

P1-2  0x238bc 判定函数 + 两张表移进 .ncguard
      → 一行 __attribute__ 的事，收益大于其余所有
      → 依据：静态 §1.7.1

P2    不依赖 abort/_exit 做 fail-fast
P3    符号抹除、字符串加密、节名、日志对齐、XOR 碎片
```

**为什么 kill 链排在 `master` 前面**：
`master` 修好只防「读懂」；kill 链修好才防「跑起来」。
对攻击者来说，「拿到代码」的价值低于「做出可用的破解包」。
而且即使 `master` 修好，攻击者仍可 patch `0x238bc`
让判定恒真 + 绕 kill 链。

### 1.15.5 这套防御的真实水平（第一版样本）

| 对手 | 结果 |
|---|---|
| 用 jadx 看 Java 层 | **挡住**（`.ncguard` 密文，so 内无明文字符串） |
| 会 `nm`/`strings`/`readelf` | 10 分钟找到签名校验 |
| 会反汇编 + 算 HKDF | 40 分钟读懂全部逻辑 |
| 会 patch + 重打包 + 抓 tombstone | **70 分钟跑起来** |
| AI 辅助 | **每档再快 3~5 倍** |

**一句话**：能挡住「随便看看」的人，挡不住任何认真的逆向者。

---

---

# 第二部分 第二版：加固后复测

> 本部分为第二版报告的完整内容，编号已改为 `2.x`。
> 结论与自我更正全部按原文保留。
>
> - 被测样本：`简盒_signed_09_09_37_sign.apk`
> - SHA-256：`6a1365be0d4f777ba005059d1efb689a90e20d057840f167223c4a5dcf995f28`
> - `libnc.so`：358,064 B（第一版 348,128 B，+9,936 B）
> - 分析环境：Termux aarch64 / LLVM 18.0.4
> - 真机环境：Redmi 2602BRT18C / Android 16 (API 36) / arm64-v8a
> - 计时：`2026-10-19 09:12:31` 起
> - 工作目录 `~/nb2/`，与第一版 `~/jianhe_re_work/` 完全隔离

## 2.0 结论速览

```
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     静态分析强度   ★★★★☆   6.5 / 10   （第一版 2.5）       ║
║     静态破解强度   ★★★☆☆   5.5 / 10   （第一版 1.5）       ║
║                                                           ║
║     两版对比：+4.0 分，实质性加固                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
```

**耗时对比**

| 阶段 | 第一版 | 第二版 |
|---|---|---|
| 定位签名校验核心 | **4 分钟** | 约 6 分钟 |
| 取得 `master` | **10 分钟**（`od` 命中 `0x11×32`） | **>26 分钟，未取得** |
| 解密加密段 | **20 分钟，成功** | **死锁，无路径** |
| 读懂判定逻辑 | 明文直读 | **看不到** |
| 产出可运行绕过包 | **70 分钟，成功** | **3 次尝试，全失败** |

**攻防结果**

| 维度 | 第一版 | 第二版 | 评价 |
|---|---|---|---|
| `master` 位置 | `.rodata 0x13e80` 明文 | **不在明文，零命中** | ✅ 根本性修复 |
| 判定函数 | `0x238bc` 明文 `.text` | `0x504a0` **`.ncx` 密文** | ✅ 修复 |
| SHA256/HKDF 实现 | 明文 `.text` | **`.ncx` 密文** | ✅ 修复 |
| kill 链 | 独立，改 PLT 即废 | **与解密流程耦合** | ✅ 意外加固 |
| JNI 符号 | 303 个暴露 | **303 个暴露** | ❌ 未变（提交已回退） |
| `.rodata` 字符串 | 全明文 | **全明文** | ❌ 未变 |
| 失败汇聚点 | 13→1 | **13→1** | ❌ 未变 |

**一句话**：这一版把**答案**藏住了（`master` + 判定逻辑都进密文），
但**地图**还摊在门口（JNI 符号、签名流程、防御字符串全明文）。
我三次 patch 全失败，根因是 **kill 链与解密流程耦合**——
这是第一版没有的结构，也是本次最有价值的发现。

### 2.0.1 操作边界

```
~/nb2/
├── t.apk                 原包副本（未修改）
├── p.py                  离线解密脚本（尝试用）
├── ex/                   解包工作区
│   └── lib/arm64-v8a/libnc.so
├── libnc_n2.so           尝试 1：PLT + pthread + selftest
├── libnc_n3.so           尝试 2：仅 PLT×3
├── n2_signed.apk         产物 1（SEGV）
├── n3_signed.apk         产物 2（SIGILL）
├── lc.txt / lc3.txt      logcat 抓取
└── ncx.bin               解密尝试输出（乱码）
```

原 APK 仅做一次 `cp` 读取。

## 2.1 节表变化

### 2.1.1 第一版 vs 第二版

| 第一版 | 第二版 | 大小变化 | 说明 |
|---|---|---|---|
| `.nckey_stub` (96B) | **`.ncks`** (104B) | +8 | 末尾新增 8 字节（`.ncxhr` 地址+长度） |
| `.nckey` (96B) | **`.nck`** (96B) | 0 | 布局不变 |
| — | **`.ncxr`** (96B) | **全新** | 高熵，第三把密钥槽 |
| `.ncguard` (32,540B) | **`.ncx`** (33,684B) | +1,144 | 加密代码段，变大 |
| `.ncguard_head` (2,600B) | **`.ncxh`** (2,880B) | +280 | 二级锁箱，变大 |
| — | **`.ncxhr`** (32B) | **全新** | 在 `.data` 区，`WAR` 属性 |

### 2.1.2 节名改动评价

从 `.ncguard` / `.nckey` 改到 `.ncx` / `.nck` / `.ncxr`。

**效果：有限。** 节名仍然出现在节表里，`readelf -SW` 一条命令全部列出。
缩短名字只降低了「一眼看出用途」的便利性，没有隐藏存在性。

**但 `.ncxhr` 有意思**：给它 `WAR`（可写+可读）属性、放在 `.data` 区、
32 字节——这个大小正好是 `master` 的长度。
**这是一个强诱饵或真钥槽**（见 §2.4）。

> **源码口径核对（合并时补）**：`.ncxhr` 是**真钥槽**，不是诱饵。
> `nc_guard_boot.c:249-250` 的 `ncg_master[32]` 就标在
> `NCG_HEAD_RO = ".ncxhr"`，锁箱器 `so-section-lock.py:566-577`
> 往里写 `os.urandom(32)` 的明文 master，随后由二级锁箱
> （`--lock-head`）用 `k_stub` XOR 成密文。`.ncxr` 才是
> 签名表段（`SIG_SALT` + `SIG_HASH_STORED` + `wrapped` 字段），
> master 不在那里。报告 §2.4.4「`.ncxr` 暴力找 master」
> 这条攻击方向**找错了地方**——该段里根本没有 master。

## 2.2 仍然暴露的部分

### 2.2.1 JNI 符号全在（与第一版完全一致）

```
$ nm -D --defined-only libnc.so | grep Java_
0000000000021ce0 T JNI_OnLoad
00000000000484e8 T Java_amimo_dcc_DccApplication_init__
0000000000025388 T Java_com_nc_link_NcLink_heartbeat
00000000000252f0 T Java_com_nc_link_NcLink_ncVerify
0000000000024204 T Java_com_nc_link_NcLink_selftest
00000000000484ec T Java_com_xixin_box_MainActivity_k__Landroid_os_Bundle_2
000000000004d9a8 T Java_com_xixin_box_MainActivity_onConfigurationChanged__...
000000000004dde4 T Java_com_xixin_box_MainActivity_onCreate__...
```

导出符号总数 **303**——**与第一版一字不差**。

> **⚠️ 与源码提交记录不符**
>
> 提交 `863a688 feat(so-harden): P2 三项——JNI 符号面` 声称：
> 「修复前 `.dynsym` 导出 303 个符号……修复后：`.dynsym` 只剩 `JNI_OnLoad`」
>
> **实测：仍是 303 个，7 个 JNI 全在。**
>
> 后续提交链显示原因：
> `863a688` → `8c2987c`（段标记误伤 JNI 入口）→ `33da24f`（改 constructor 注册）
> → `0258058` → `2d064d7` → `1bcc660` → `a7d9cbc **回退动态注册——真机启动崩溃，改回短名绑定**`
>
> **P2-1（JNI 符号隐藏）被完整回退了。** 这是实测与设计意图差异最大的一处。

### 2.2.2 防御字符串仍全明文

```
118ed  /proc/self/maps
118e4  base.apk
11a2f  APK Sig Block 42
11e3b  maps has no base.apk!/...so line, try lib-path fallback
11e73  /proc/self/root%s/base.apk
1268b  unsigned __int128
12b80  data/app scan exhausted: no <pkg>*/base.apk accessible
136c5  .nck
13abe  .ncxr
13b3e  /proc/self/task/%s/comm
15f25  APK Sig Block 42
```

与第一版完全相同的泄底清单。
**提交 `863a688` 提到的 P2-2「.rodata 路径」同样未生效或已回退。**

> **源码口径核对（合并时补）**：LSGS 密文机制已覆盖
> `sig_check.c` / `env_check.c` / `sig_guard2.c`，路径字面量确实
> 走密文（见 §1.1.5 的核对）。第二版样本仍见明文，属样本时间点
> 早于该修复，非机制缺失。`docs/变更历史.md` 有
> `0595b90 fix(lsgs): sig_guard2.c 漏出密文化` 一条记录。

### 2.2.3 签名校验主干仍明文

`0x25388–0x26a50`（`heartbeat` 符号名下，1,458 条指令），关键指令：

```asm
25aac: adr  x1, 0x15f25          ; "APK Sig Block 42"
25ab8: bl   memcmp@plt
25af8: mov  w27, #0x871a
25b00: movk w27, #0x7109, lsl 16  ; 0x7109871A = APK Signature v2 ID
```

找 EOCD、解析 v2 块、比对魔数——**全流程明文可读**。

### 2.2.4 失败汇聚点：原统计错误，已推翻

```
跳向 0x258b8 的次数：13
区间指令数：1,458
```

> **⚠️ 本节原结论为误判，已推翻**
>
> 原文写「`0x258b8` 仍被引用 13 次，仍是唯一汇聚点，改动未进构建」。
>
> **错误原因**：`0x258b8` 落在 `<Java_com_nc_link_NcLink_heartbeat>`
> 符号范围内（`heartbeat` 起始 `0x25388`）。我用 `0x25388–0x26a50`
> 圈定「签名校验主干」，但该区间实际跨了多个函数，`heartbeat` 就在里面。
>
> **正确结论**：`delayed_kill_0/1/2` 与 `sig_raw_die` 都标进了
> `.ncx` 加密段，静态反汇编看不到（是密文）。
> **「看不到」不等于「不存在」。**
>
> **教训**：统计引用次数前，必须先确认地址落在哪个符号范围内。

## 2.3 真正的加固：判定逻辑进了密文

### 2.3.1 `ncVerify` 变成纯转发壳

```asm
00000000000252f0 <Java_com_nc_link_NcLink_ncVerify>:
    252f0: stp  x29, x30, [sp, #-0x30]!
    25300: cbz  x2, 0x25370              ; jstring == NULL → 返回 0
    25314: ldr  x8, [x8, #0x558]         ; GetStringUTFLength
    2531c: cmp  w0, #0x20                 ; 长度必须 32
    25320: b.ne 0x25370
    25334: ldr  x8, [x8, #0x5c0]         ; GetStringUTFChars
    25348: bl   0x504a0                   ; ★ 真正的判定函数
    25370: mov  w22, wzr
    25374: mov  w0, w22
    25384: ret
```

**`0x504a0` 在 `.ncx`[0x484e8, 0x5087c) 密文段内。**

对比第一版：真正的判定 `0x238bc` 在明文 `.text`，`ncVerify` 只是转发。
第二版把判定搬进了密文。

**这是本版最有价值的两处修复之一。**

### 2.3.2 `selftest` 也变成跳板

```asm
0000000000024204 <Java_com_nc_link_NcLink_selftest>:
    2421c: bl   0x43c90
    24220: cmp  w0, #0
    24228: bl   0x23dc0
    24234: b    0x50488                   ; ★ 跳进 .ncx
    24238: mov  w0, #-0x64                ; 失败 -100
    24240: ret
```

明文中只剩跳板与失败码，主体在 `0x50488`（密文）。

## 2.4 最核心的加固：`master` 消失了

### 2.4.1 第一版 vs 第二版

**第一版**（一击命中）：

```bash
$ od -A x -t x1 -j 0x13e80 -N 32 libnc.so
013e80 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
013e90 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11
```

**第二版**（零命中）：

```bash
$ od -A x -t x1 -v libnc.so | grep -E '11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11'
（无输出）
```

> 提交 `dcd65ae feat(so-harden): master 随机化 + 藏进密文段` 与此一致。

### 2.4.2 关键：SHA256 实现也进了密文

```bash
$ od -A x -t x4 -v libnc.so | grep -iE '6a09e667'
013de0 6a09e667 bb67ae85 3c6ef372 a54ff53a    ← SHA256 初始常量，明文
$ od -A x -t x4 -v libnc.so | grep -iE '5be0cd19'
013dd0 510e527f 9b05688c 1f83d9ab 5be0cd19    ← SHA256 末常量，明文

$ llvm-objdump -d libnc.so | grep -E '0x13dd0|0x13de0'
（无输出）                                     ← 但没有代码引用这两张表
```

**SHA256 常量表在明文，但引用它们的代码在 `.ncx` 密文里。**

这意味着：即使知道 SHA256 怎么实现，也看不到 `master` 是怎么被送给它的。

> **源码口径核对（合并时补）**：核对当前源码，`nc_guard_key.c`
> （SHA256/HMAC/HKDF 实现）**没有任何 `section()` 属性**
> （全文件 grep 无命中），即全部落在 `.text` 明文。
> 也就是说第二版样本观察到的「SHA256 常量表在明文、无代码引用」，
> 在当前源码中**已不复现**——`ksha256`/`khmac_sha256`/`khkdf_sha256`
> 是明文可见的。这削弱了本条的强度，但不改变主结论：
> `master` 本身在 `.ncxhr` 密文里，链路仍是
> 「要解 `.ncx` → 要 `k_so` → 要 `master` → master 在密文里」。
> 攻击者现在能读到 HKDF 实现，但仍缺 `master` 这个输入。

### 2.4.3 死锁形成

```
要解 .ncx    →  需要 k_so
要得 k_so    →  需要 master
要得 master  →  恢复代码在 .ncx 内（SHA256/HKDF 实现）
                    ↑ 回到起点
```

**这是本版真正的防线。** 第一版的死锁不存在，因为 `master` 躺在明文。

> **源码口径核对（合并时补）**：按当前源码，第三条边应改为
> 「要得 `master` → 需先解 `.ncxhr`，而解它要 `k_stub`；
> `k_stub = HKDF(master, slot_seed, crc32(stub 代码))`，
> 又要 `master`」。死锁结构更紧：`master` 同时是 `.ncxhr`
> 的解密原料和自己的派生输入，单向链路见
> `nc_guard_boot.c:227-247` 的注释
> （`碎片 → XOR_KEY → k_stub → {解 head, 解 head_ro → master} → k_so`）。
> 设计上刻意避免了「用 `k_so` 解 master」的循环依赖。

### 2.4.4 我试过的破解路径（全部失败）

| 尝试 | 对象 | 结果 |
|---|---|---|
| 直接把 `.ncxhr`(32B) 当 `master` | `k_so` 派生 | 解出乱码 `a1fdf9e1...` |
| 搜 32 字节高熵块 | `.ncxr`(96B) | 96 字节无结构特征，无法确定哪 32 字节 |
| 追 `JNI_OnLoad` 初始化链 | `0x22b80` | 是 JNI 方法注册表，非密钥初始化 |
| 搜 `nc-so-v1` 字符串 | HKDF info | **字符串不存在**（已碎片化/加密） |
| 引用 SHA256 常量表 | 定位 HKDF | 无明文引用 |

**26 分钟（09:13 → 09:39）内未取得 `master`。**

## 2.5 三次 patch 尝试（全部失败）

### 2.5.1 尝试 1：多目标 patch → SIGSEGV

**改动**：

| 地址 | 原 | 改 | 意图 |
|---|---|---|---|
| `0x2594c` | `bl pthread_create` | `nop` | 不启监控线程 |
| `0x25950` | `cbnz w0, ...` | `nop` | 走正常路径 |
| `0x24238` | `mov w0, #-100` | `mov w0, #0` | selftest 失败变成功 |
| `0x51890` | `adrp x16` | `ret` | `_exit@plt` |
| `0x518a0` | `adrp x16` | `ret` | `raise@plt` |
| `0x51950` | `adrp x16` | `ret` | `abort@plt` |

**结果**：`SIGSEGV (SEGV_ACCERR)`，进程活约 3 秒。

tombstone：

```
signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x7c37cf256c
Cause: trying to execute non-executable memory.

#00 pc 0x6f256c  <anonymous:7c37600000>
#01 pc 0x24104   libnc.so
#02 pc call_constructors
```

**根因**：`0x24104` 调用 `0x50f24`（在 `.ncxh` 密文段）。
该段未解密，执行密文 → SEGV。

### 2.5.2 尝试 2：只改 3 个 PLT → SIGILL

**改动**：`_exit@plt` / `raise@plt` / `abort@plt` 三个桩 → `ret`，
**其他一律不动**。

**结果**：连 1 秒都没撑住。

```
Fatal signal 4 (SIGILL), code 1 (ILL_ILLOPC)

#00 pc 0x4f474   libnc.so     ← .ncx[0x484e8,0x5087c) 内，仍是密文
#01 pc 0x22dc8   libnc.so     ← .text 构造函数
#02 pc call_constructors
```

日志只输出了一行就死：

```
nc : 【流程】so 已加载,进入环境检测 env_check_run
```

**根因**：`0x22dc8` 位于构造函数里，前序是 `ptrace`(0x22d90) +
`prctl`(0x22da8)，它直接调用 `.ncx` 里的 `0x4f474`。
此时 `.ncx` 未解密。

### 2.5.3 尝试 3（推断，未实施）：精确单点

理论上应找那个「被改成 `ret` 后破坏解密流程」的 `abort` 调用点，
单点修改。

**但我没做**——因为需要先知道 `.ncx` 的解密走哪条路，
而这又回到死锁。

## 2.6 最有价值的发现：kill 链与解密流程耦合

### 2.6.1 构造函数的解密结构

```asm
0000000000021ce0 <JNI_OnLoad>:
    ...
    23ff8: cbnz  w8, 0x24104           ; w8 != 0 → 跳到调用点
    23ffc: bl    getpagesize@plt
    24014: mov   w2, #0x7              ; ★ RWX
    24028: bl    mprotect@plt
    24030: 循环解密：
    2403c:   ldrb  w10, [x20, x19]     ; 密文
    24040:   ldrb  w9,  [x8, x9]       ; key[i & 0xF]
    24044:   eor   w9, w10, w9         ; XOR
    24048:   strb  w9, [x20, x19]      ; 写回
    24054: adr   x22, 0x17bfc
    24104: bl    0x50f24               ; ★ 调 .ncxh 里的函数
```

### 2.6.2 第二段解密用 RW 而非 RWX

```asm
    240a8: bl    mprotect(..., 3)      ; ★ PROT_READ|PROT_WRITE，无 X
    240bc: 循环 XOR 解密
    240ec: bl    mprotect(..., 3)      ; 恢复 RW，仍无 X
    24104: bl    0x50f24               ; 执行刚解密的代码
```

**注意**：`0x240a8` 和 `0x240ec` 用的是 `3`（RW），不是 `7`（RWX）。
如果这段解密后的代码要执行，必须有 X。
**所以这段大概率不是可执行代码，而是数据/密钥区**——
或者原始包在别处补了 X 权限。

### 2.6.3 耦合的证据

尝试 2 只改 3 个 PLT 桩（不改任何逻辑分支），就导致 `.ncx` 不解密。

**唯一解释**：解密流程里有一次 `abort()` 调用，且那次调用
**必须是生效的**（即程序在某条路径上故意靠 `abort` 终止）。
把 `abort` 改成 `ret` 后，控制流继续往下走，跳过了后续的解密步骤。

**这个结构第一版没有。** 第一版改 PLT 桩后进程能跑 30 秒以上，
说明第一版的 `abort` 都是「终结路径」，不参与控制流。

**第二版把 `abort` 变成了控制流的一部分**——
不管这是有意设计还是副作用，它让「改 PLT 桩」这个通用手法失效了。

> **源码口径核对（合并时补）**：这条结论**在本轮源码核对中
> 未获支持**。当前源码里 kill 链已完全不走 libc：
> `env_check.c:358-426` 的 `env_raw_die` / `sig_check.c:798-807`
> 的 `sig_raw_die` 都是 GNU 内联汇编 `svc #0` 直投
> `tgkill(SIGABRT)`，信号被拦时 `__builtin_trap()`（生成 `brk #1`），
> 全程不经 libc，二进制里**没有 `abort@plt` 调用者**。
> 验收判据 `nm -D -u libnc.so | grep -wE "abort\|syscall\|_exit\|raise"`
> 应为空。
>
> 因此第二版样本观察到的「解密流程里有 `abort()` 参与控制流」，
> 在当前源码中对应的应是 **libc++ 静态运行时**的
> `std::terminate` / `__cxa_get_globals_fast` 路径，
> 而非业务 kill 链（这一点第二版 §2.10.1 的核查自己也已经查明，
> 379 个 `abort@plt` 调用者全属 libc++）。
> **结论：该「耦合」是 libc++ 异常路径与解密流程的偶合，
> 不是有意设计的防御。** 报告作者自己也说「不管是有意还是副作用」。
> 保留此记录，但后人不应把它当成可依赖的机制去「优化」或「加强」——
> 它随时可能因 STL 版本变化而消失。

## 2.7 两版对比总表

| 维度 | 第一版 | 第二版 | 评价 |
|---|---|---|---|
| **`master` 位置** | `.rodata 0x13e80`，`0x11×32` | **不在明文** | ✅ 根本性修复 |
| **SHA256/HKDF 实现** | 明文 `.text` | **`.ncx` 密文** | ✅ 修复 |
| **判定函数** | `0x238bc` 明文 | `0x504a0` **密文** | ✅ 修复 |
| **`.ncx` 可解密** | 是（10 分钟） | **否（死锁）** | ✅ 修复 |
| kill 链 | 独立，改 PLT 即废 | **内联 svc + 与解密耦合** | ✅ 双重加固（`svc`×10） |
| `.text` 完整性校验 | 从未生效 | **实测仍报 clean** | ⚠️ 提交声称已修（`38df518`），本样本未见 |
| JNI 符号隐藏 | 303 个全暴露 | **303 个全暴露** | ❌ 提交已回退（`a7d9cbc`） |
| 失败汇聚点 | 13→1（`0x23ae4`） | **多出口，但在 `.ncx` 密文里** | ✅ 已改（原判据统计错了函数） |
| **PLT 软目标** | 3 个（我漏数了 `syscall@plt`） | **kill 链已无 PLT 调用者**，走内联 `svc` | ✅ 已修（379 个 `abort` 全属 libc++） |
| `.rodata` 字符串 | 全明文 | **全明文** | ❌ 未变 |
| 节名 | `.ncguard` 等 | `.ncx` 等 | ⚠️ 仅缩短 |
| `.text` 代码块置换 | 有（挡住一轮） | 有 | ➖ 保留 |
| `.nck` 诱饵 | `wrapped_k_so` | `wrapped_k_so` **完全相同** | ➖ 保留 |

### 2.7.1 一处值得注意的细节

两版的 `.nck` 里 `wrapped_k_so` **完全相同**：

```
第一版：d6054d96f1e7128525a5b6cc9b496258
第二版：d6054d96f1e7128525a5b6cc9b496258
```

`master` 变了、证书没变、包名没变——`wrapped_k_so` 却一字不差。

这印证了第一版的结论：**它是诱饵死字段，不参与真实派生**。
本版原样保留，说明诱饵是有意为之。

> **源码口径核对（合并时补）**：这条「diff 识破手法」已被修掉。
> 当前源码 `so-section-lock.py:658-662`：
> `_decoy_seed = os.urandom(16)`（原来是
> `sha256('nc-decoy-v1' + package)` 的确定性派生）。
> 同一个包名永远产出同一串字节 → 攻击者 diff 两个 so 就能认出诱饵。
> 改后三次独立构建的 `wrapped_k_so` 全不同，并有 T17 回归
> 断言「两次构建必须不同」。**本条攻击面在当前源码中已关闭。**

## 2.8 评分

### 2.8.1 星级总表（第二版）

| 防御层 | 实测结果 | 评分 |
|---|---|---|
| **`master` 隐藏** | 26 分钟未取得，`0x11` 零命中 | ★★★★★ |
| **判定逻辑加密** | `0x504a0` 在 `.ncx`，解不开 | ★★★★★ |
| **kill 链内联 `svc`** | 10 条 `svc #0`，无 PLT 调用者 | ★★★★★ |
| **kill 链耦合** | 改 PLT 破坏启动，通用手法失效 | ★★★★☆ |
| `.nck` 诱饵 | `wrapped_k_so` 与上版相同，成功误导 | ★★★★☆ |
| `.text` 代码块置换 | 仍然有效 | ★★★☆☆ |
| v2 签名块解析 | 实现质量好 | ★★★☆☆ |
| 节名中性化 | 仅缩短，仍可列举 | ★★☆☆☆ |
| `.ncxh` 二级锁箱 | 有效（但诱发了 SEGV，算双刃） | ★★☆☆☆ |
| `.text` 完整性校验 | 从未生效 | **实测仍报 clean** | ⚠️ 提交声称已修（`38df518`），本样本未见 |
| 失败路径分散 | 13→1 | **13→1** | ❌ 提交声称已改（`c664797`），本样本未见 |
| **PLT 软目标** | 3 个（我漏数了 `syscall@plt`） | **kill 链已无 PLT 调用者**，走内联 `svc` | ✅ 已修（379 个 `abort` 全属 libc++） |
| JNI 符号隐藏 | 303 个全暴露 | **303 个全暴露** | ❌ 提交已回退（`a7d9cbc`） |
| `.rodata` 字符串 | 全明文 | ☆☆☆☆☆ |

### 2.8.2 两个总分

```
╔════════════════════════════════════════════════════════╗
║  ①  静态分析强度（能否读懂逻辑）                     ║
╠════════════════════════════════════════════════════════╣
║                                                    ║
║       ★★★★☆                                       ║
║       6.5 / 10                                     ║
║                                                    ║
║      第一版 2.5  ──>  第二版 6.5  （ +4.0 ）        ║
╚════════════════════════════════════════════════════════╝

╔════════════════════════════════════════════════════════╗
║  ②  静态破解强度（能否做出能跑的包）                 ║
╠════════════════════════════════════════════════════════╣
║                                                    ║
║       ★★★☆☆                                       ║
║       5.5 / 10                                     ║
║                                                    ║
║      第一版 1.5  ──>  第二版 5.5  （ +4.0 ）        ║
╚════════════════════════════════════════════════════════╝
```

**一句话**：核心机密（`master` + 判定逻辑）藏住了，**但地图还摊在门口**。

### 2.8.3 分数是怎么算出来的

**评分口径**：以实测「攻击者拿到答案所需的成本」为准，不以设计意图为准。

#### ① 静态分析强度 = 6.5

按「读懂签名校验逻辑」分四步算：

| 步骤 | 第一版成本 | 第二版成本 | 本步得分 |
|---|---|---|---|
| 定位入口 | 4 分钟 | 6 分钟 | 1.0 / 2.0 |
| 取得密钥 `master` | **10 分钟**（`od` 命中） | **>26 分钟未拿到** | 2.0 / 2.5 |
| 解密加密段 | **20 分钟** | **死锁，无路径** | 1.0 / 2.5 |
| 读懂判定逻辑 | 明文直读 | **看不到** | 1.5 / 3.0 |

四项相加：**6.5**

#### ② 静态破解强度 = 5.5

按「做出能在真机运行的绕过包」算：

| 尝试 | 第一版 | 第二版 | 得分 |
|---|---|---|---|
| 改判定逻辑 | 直接 patch `0x238bc` 成功 | **`0x504a0` 在密文，无处下手** | 2.0 / 3.0 |
| 绕 kill 链 | 改 PLT 桩成功 | **PLT 耦合，改了起不来** | 2.0 / 3.0 |
| 产出可运行包 | 成功（30 秒稳定） | **3 次全失败** | 0.5 / 4.0 |

四项相加：**5.5**

### 2.8.4 为什么 ① 是 6.5 而不是 8+

**短板全在外围，不在核心。**

核心四项（`master` 隐藏、判定加密、解密死锁、kill 耦合）拿了满分权重，
但下面这些「零成本情报泄漏」把分数拉下来：

| 外围失守项 | 攻击成本 | 扣分原因 |
|---|---|---|
| **JNI 符号 303 个** | `nm -D` 一条命令 | 直接定位 8 个入口 + 精确大小，知道业务重心在哪 |
| **签名流程明文** | `strings` 一条命令 | `APK Sig Block 42` + `0x7109871A`，知道它在解析什么 |
| **`.rodata` 全泄底** | `strings` 一条命令 | `/proc/self/maps` 等整套防御决策树 |
| ~~失败汇聚点 13→1~~ | — | **原判错误**，多出口已进 `.ncx`，静态不可见 |
| **节表可列举** | `readelf` 一条命令 | `.ncx`/`.ncxr` 明写，直接告诉去哪找 |

**如果只把外围修好、核心不动**，① 能到 8。
**如果核心没修、只修外围**，① 还是 2.5。

**现在的情况是核心修好了，外围没修**，所以是 6.5。

### 2.8.5 为什么 ② 是 5.5 而不是更高

**我三次尝试全失败，但失败原因是「手法失效」，
不是「找到了路径却走不通」。**

| 尝试 | 结果 | 性质 |
|---|---|---|
| 多目标 patch | `SEGV` 执行密文 | patch 太多，互相干扰 |
| 只改 PLT | `SIGILL` @ `.ncx` | **`abort()` 参与控制流**，通用手法失效 |
| 精确单点 | 未做 | 需要先知道解密路径，回到死锁 |

**5.5 分给的是「当前静态手段下我做不到」，不是「不可能做到」。**

三条尚未验证的路径（见 §2.13.3）：

1. **frida hook `mprotect`**：`0x24014` 那次带 `PROT_EXEC`，
   之后内存就是明文 `.ncx`
2. **hook `0x24104`**：此时 `.ncxh` 应已解密
3. **`.ncxr` 暴力**：96 字节里找 32 字节 `master`

**这三条都属于动态，已超出静态测试范围。**

### 2.8.6 评分结论（给 AI 看）

```
┌──────────────────────────────────────────────────────────────┐
│  静态分析强度  ★★★★☆ 6.5 / 10                                 │
│                                                              │
│  含义：攻击者要读懂签名校验逻辑，成本从「10 分钟」变成「      │
│        >26 分钟且未成功」。核心机密（master + 判定）已藏住。   │
│                                                              │
│  扣分项全在外围：JNI 符号 303 个、签名流程明文、.rodata 泄底、 │
│  节表可列举。这些不需要解密就能拿到。（失败汇聚那条已推翻）    │
├──────────────────────────────────────────────────────────────┤
│  静态破解强度  ★★★☆☆ 5.5 / 10                                 │
│                                                              │
│  含义：攻击者要做出能跑的破解包，第一版 70 分钟成功，          │
│        第二版 3 次全失败。                                    │
│                                                              │
│  但这是「当前静态手段失效」，不是「不可能」。未验证的动态路径   │
│  有三条（§2.13.3），任何一条成功都能拿到明文。                 │
├──────────────────────────────────────────────────────────────┤
│  最关键的单点发现                                             │
│                                                              │
│  kill 链与解密流程耦合。                                      │
│  改 abort@plt / _exit@plt / raise@plt（第一版的有效手法）      │
│  会让 .ncx 无法解密 → SIGILL 起不来。                         │
│  这个结构第一版没有，是本版最有价值的加固（可能是有意设计）。   │
│  ⚠️ 建议保留，避免后人「优化」掉。                             │
├──────────────────────────────────────────────────────────────┤
│  最紧迫的一项（不是安全问题，是流程问题）                      │
│                                                              │
│  样本构建 09:09，晚于所有提交（最后 07:52），但实测：          │
│    · .dynsym 仍 303 个（P2-1 已回退，合理）                   │
│    · kill 链已用内联 svc，PLT 无 kill 调用者（原判据错）       │
│    · 多出口 kill 在 .ncx 密文内，静态不可见（原统计错了函数） │
│  → 需确认本样本是否真的是最新代码构建的产物。                  │
└──────────────────────────────────────────────────────────────┘
```

> **该「最紧迫的一项」已被核查推翻**，见 §2.10。

## 2.9 这一版到底防住了什么

### 2.9.1 明确防住的

| 攻击者层级 | 第一版结果 | 第二版结果 |
|---|---|---|
| `od` 搜常量 | **10 秒拿到 `master`** | 零命中 |
| 反汇编找判定 | **直接看到 `0x238bc`** | 看到的是转发壳 |
| 离线解密 | **20 分钟解开全部** | 死锁 |
| 改 PLT 桩 | **成功绕过 kill** | **破坏启动** |
| 产出可运行包 | **70 分钟成功** | 3 次失败 |

### 2.9.2 未防住的

| 仍暴露 | 影响 |
|---|---|
| JNI 符号 303 个 | 一眼定位入口与业务重心 |
| 签名流程明文 | 知道它在干什么，只是不知道判据 |
| `.rodata` 防御字符串 | 反调试架构全泄底 |
| 节表 | `.ncx`/`.ncxr` 明写，知道去哪找 |
| `.text` 校验 | 真机报 clean，但**未证实**是否真能检出改动 |

### 2.9.3 攻防成本对比

| 阶段 | 第一版 | 第二版 | 倍数 |
|---|---|---|---|
| 定位入口 | 4 分 | 6 分 | 1.5× |
| 拿到密钥 | 10 分 | **>26 分（未成功）** | >2.6× |
| 解密内容 | 20 分 | **未成功** | ∞ |
| 做出能跑的包 | 70 分 | **未成功** | ∞ |

**对 AI 逆向的拦截效率提升了至少 3 倍，且在当前静态手段下是「∞」。**

## 2.10 建议（按优先级）与 P0 质疑的核查

> 基于实测，不基于源码设计意图。

### 2.10.1 P0：~~构建一致性核对~~ 【已推翻：本节全部结论为误判】

> **⚠️ 2026-10-19 第二次更正**
>
> 本节原结论「三处改动未生效、产物非最新代码」**全部是误判，已推翻**。
>
> **三条错误的性质**：
>
> | 原结论 | 实际情况 | 错误性质 |
> |---|---|---|
> | 内联 `svc` 0 条，改动未生效 | **10 条 `svc #0`**（`d4000001`） | **正则写错**：我搜 `svc #0x0`，llvm 输出 `svc #0`，未匹配 |
> | 379 个 `abort` 调用者是 kill 链 | 全在 `0x27d30–0x48388`，libc++ 静态运行时 | **判据缺陷**：没确认符号归属 |
> | `0x258b8` 仍 13→1 | 该地址在 `heartbeat` 符号内，不是签名校验失败路径 | **判据缺陷**：没确认地址归属 |
>
> **共同根因（对方说得对）**：没有先确认「这些符号/地址属于谁」就直接统计。
> 第一版漏 `syscall@plt`、第二版把 libc++ 的 `abort` 当 kill 链，是同一个毛病。
>
> **修正后的实测**：
>
> ```bash
> $ llvm-objdump -d libnc.so | grep -cE '\bsvc\b'
> 10
> $ llvm-objdump -d libnc.so | grep -E '\bsvc\b'
>   22d4c: d4000001  svc #0
>   231e8: d4000001  svc #0
>   23544: d4000001  svc #0
>   235b8: d4000001  svc #0
>   235d4: d4000001  svc #0
>   235e8: d4000001  svc #0
>   235f8: d4000001  svc #0
>   23608: d4000001  svc #0
>   2572c: d4000001  svc #0
>   25754: d4000001  svc #0
> ```
>
> **kill 链确实已进加密段**：`env_raw_die` / `sig_raw_die` 走内联 `svc`，
> 二进制里没有对应 PLT 调用者。379 个 `abort@plt` 调用者全属 libc++，
> 与业务 kill 链无关。
>
> **本节原建议（重构建对比 sha256）作废。**

**核查结论（原独立核查文档，已并入本节）**：

| 报告质疑 | 核查结果 | 证据 |
|---|---|---|
| 四个 PLT 软目标（`abort`/`_exit`/`raise`/`syscall`）仍在 | ❌ **误判**。这 379 个调用点全来自 libc++ 静态运行时，不是 kill 链 | §2.2 |
| `syscall@plt` 未消除 | ❌ **误判**，同上 | §2.2 |
| 失败汇聚点仍 13→1 | ❌ **误判**。报告统计的 `0x258b8` 落在 `heartbeat` 函数内，不是 `sig_verify` 的失败路径 | §2.3 |
| `.text` 完整性校验仍报 clean | ⚠️ **未能证伪**。本地产物逻辑正确，但真机日志无法在本地复现 | §2.4 |
| JNI 符号 303 个未变 | ✅ **属实**。`a7d9cbc` 主动回退动态注册（真机崩溃），这是已知取舍 | §2.5 |

**核查方法**：下载 CI 那次成功运行的产物（run `39183064777`，
commit `a7d9cbc`），与本地最新代码构建的产物逐项对比。
**不看源码声称，只看产物。**

**先确认「产物是否来自最新代码」**：

| 项 | 值 |
|---|---|
| 报告样本构建时间 | 09:09 |
| CI 最后一次成功运行 | `39183064777`，commit `a7d9cbc`，`2026-10-19T00:57:01Z` = **北京 08:57** |
| 代码最后提交 | `a7d9cbc`，`2026-10-19 07:52:47 +0800` |

时间线吻合：**样本确实由最新代码构建**。质疑前提成立，可以继续查。

**四个 PLT 软目标：全来自 libc++，不是 kill 链**

CI 产物（arm64）的未定义符号：

```
$ nm -D -u libnc.so | grep -wE "abort|_exit|raise|syscall"
              U _exit@LIBC
              U abort@LIBC
              U raise@LIBC
              U syscall@LIBC
```

与报告观察一致。看起来「软目标没消除」。

**但这些调用点是谁的**：

```
27d28: bl syslog@plt
27d2c: bl closelog@plt
27d30: bl abort@plt              ← syslog/closelog/abort 三连
282e8: bl abort@plt              ← 前一条是 __cxa_get_globals_fast
28e7c: bl _ZSt9terminatev@plt    ← C++ std::terminate
28e80: bl abort@plt
```

`_ZSt9terminatev`、`__cxa_get_globals_fast`、`syslog/closelog` 三连——
**全是 libc++ 静态运行时的符号**（`Application.mk` 里 `APP_STL := c++_static`）。

统计：`bl abort/_exit/raise@plt` 共 **379 处**，全部属于 C++ 运行时
（异常路径、`std::terminate`、静态对象析构失败等）。

**我的 kill 链实际状态**：

```bash
$ objdump -d libnc.so | grep -c svc
10                          # CI 产物

$ objdump -d <本地构建> | grep -c svc
10                          # 本地产物
```

**两处完全一致。** `env_raw_die` / `sig_raw_die` 走的是内联 `svc #0`，
二进制里没有对应的 PLT 表项。

**为什么会被误判**：

报告作者（以及第一版的我）都默认：

> 「看到 `abort@plt` 就说明 kill 链有软目标」

这个推论在**纯 C 工程**里成立。但本工程 `APP_STL := c++_static`，
libc++ 静态链接会带入自己的 `abort` 依赖（异常/terminate 路径），
与业务代码的 kill 链无关。

**正确的判据应该是**：

```bash
# 数内联 svc —— 这才是 kill 链的真实形态
objdump -d libnc.so | grep -c svc
# 期望：10（我们的 env_raw_die + sig_raw_die + gettid 等）

# 而不是数 abort@plt —— 那个数被 libc++ 污染
```

**失败汇聚点 13→1：统计的是另一个函数**

反汇编该地址：

```
258b4: b.ge 0x259fc <Java_com_nc_link_NcLink_heartbeat+0x674>
```

**`0x258b8` 落在 `Java_com_nc_link_NcLink_heartbeat` 符号范围内**，
不在 `sig_verify` 里。报告把 `heartbeat` 附近的引用计数当成了
`sig_verify` 的失败路径统计。

`delayed_kill_0/1/2` 与 `sig_raw_die` 都标进了 `.ncx` 加密段：

```bash
$ nm libnc.so | grep delayed_kill
（无输出）          ← 在加密段内，nm 看不到，符合预期
```

`objdump` 也反汇编不出（是密文）。所以**从静态统计里看不到它们**，
但这不等于不存在——本地未锁箱产物可见三个独立函数体
（`0xb698` / `0xb7d8` / `0xb8c8`，地址互不相同）。

**教训**：**符号名会骗人，地址归属要自己算。**
统计引用次数前，必须先确认地址落在哪个符号范围内。

**`.text` 完整性校验报 clean：未能证伪**

报告观察：真机日志仍报
`【数据】本 so .text 内存完整性校验结果 (clean)`。

修的是 `env_mem_readable` 的跨映射误判（`.text` 与 `.eh_frame`
同页导致探针放弃校验）。本地验证：修后跨两条映射能正确判定为可读。

但**"能读到"不等于"能发现被改"**——报告观察到的 `clean` 是真机行为，
本地无法复现（需要真实设备 + patch 后的 so）。

**这条保持「未证实」状态**，不下结论。要坐实需要：
1. 用最新代码构建产物
2. 改 `.text` 一个字节
3. 真机跑，看日志是否从 `clean` 变 `hit`

报告作者有能力做这个实验（它有真机），但我不能替它下结论。

**JNI 符号 303 个：属实，是已知取舍**

这条报告说得对，且原因已查明：

`863a688` 实现了动态注册（`.dynsym` 只剩 `JNI_OnLoad`），
但真机启动崩溃，被 `a7d9cbc` 回退为短名绑定。

**根因**：`constructor` 里 `FindClass("com/nc/link/NcLink")` 不安全——
so 由 `Application.onCreate` 触发加载，此刻 Application 类正在初始化。

**这是真实的取舍，不是疏漏**：
- 想隐藏 `Java_*` → 必须动态注册
- 动态注册 → so 加载时机遇崩
- 选「能跑起来」，放弃「符号隐藏」

报告 §10 P1 建议用 `objcopy --strip-symbol` 或 `--dynamic-list` 精确控制，
这条路**不需要动态注册**，是更可行的方向，值得后续尝试。

> **源码口径核对（合并时补）**：这条建议已落地。
> 当前源码 `lib-ndk.sh:99-109` 生成 `nc_hide.map`
> （`global: JNI_OnLoad; Java_com_nc_*; local: *;`）并以
> `--version-script` 传入链接器，只保留手写入口、隐藏 dex2c
> 业务符号。提交 `e0e6bb2` 实测验证：`Java_com_x_MainActivity_k`
> 被隐藏、`Java_com_nc_link_NcLink_selftest` 保留，各得其所。
> 报告说的「`objcopy --strip-symbol` 路线不可行」也已被实测确认
> ——JNI 短名绑定去掉符号名 = 必然 `UnsatisfiedLinkError`。
> 真正的出路正是「区分哪些走短名绑定、哪些走动态注册」。

**这次核查暴露的真问题**

不是「改动没生效」，而是**「判据本身有缺陷」**：

| 现象 | 错误判据 | 正确判据 |
|---|---|---|
| 以为软目标没消除 | 数 `abort@plt` 调用点 | 数 `svc` 指令（10 处） |
| 以为失败汇聚没改 | 在 `0x25388–0x26a50` 区间统计引用 | 先确认地址落在哪个符号内 |
| 以为 `.text` 校验没修 | 看日志报 clean | 需真机 patch 对照实验 |

**两个报告（第一版、第二版）都在同一个地方犯错**：第一版漏了
`syscall@plt`（把 3 个软目标当成全部），第二版把 libc++ 的 `abort`
当成 kill 链的。共同点是**没有先确认「这些符号属于谁」**。

**给后续逆向核验的检查清单**

下次再核验这套加固，按这个顺序：

```bash
SO=libnc.so

# ① kill 链是否用内联 svc（期望 10）
objdump -d $SO | grep -c svc

# ② 软目标是否属于 libc++（先看调用方，别只看符号在不在）
objdump -d $SO | grep -B3 "abort@plt>" | grep -cE "terminate|__cxa|syslog"
#   若占比高 → 那些是 C++ 运行时的，与 kill 链无关

# ③ 多出口 kill 是否存在（在加密段内，需未锁箱产物验证）
nm $SO | grep -E "delayed_kill_[012]"     # 期望 3 个独立地址

# ④ master 是否随机化（期望 0 0）
python3 -c "d=open('$SO','rb').read(); print(d.count(b'\x11'*32), d.count(b'\x11'*16))"

# ⑤ 判定函数是否在加密段
nm $SO | grep nc_verify_t1                 # 地址应落在 .ncx 范围内

# ⑥ JNI 符号面（已知取舍：必须导出）
nm -D --defined-only $SO | grep -c Java_   # 期望 4~7（短名绑定必需）
```

**最重要的一条**：`objdump` 看到 `<unknown>` 或看不到符号，
**不等于没生效**——加密段内的代码本来就反汇编不出。
区分「不存在」与「在密文里」需要对比未锁箱产物。

### 2.10.2 P0-附加：验证 `syscall@plt` 是否真的该消失

`2026-10-19-kill链加固-改动说明.md` §3 说得对：

> 此前代码已经「syscall 直调绕过 libc」——但那是调用 libc 的 `syscall()`，
> 它本身也是一个 PLT 表项（`syscall@plt`）。所以当时的真实绕过成本只是
> 「改 4 个桩而不是 3 个」。

**这句话完全正确，也是我第一版报告的疏漏。**
第一版我只列了 3 个桩（`abort`/`_exit`/`raise`），
没注意到 `syscall@plt` 也是软目标。

**更正**：我原写「`syscall@plt` 仍在 → 内联 svc 未生效」，**这是错的**。
实测有 10 条内联 `svc #0`，kill 链已不用 PLT。
`syscall@plt` 存在是因为 libc++ 自己要用它，与业务 kill 链无关。

### 2.10.3 P1：修 JNI 符号面

`863a688` 的思路正确（`nm -D` 一条命令拿到 7 个入口 + 精确大小），
但后续回退了（`a7d9cbc`）。

**建议改方向**：不要用动态注册（会导致启动崩溃），
改用 `objcopy --strip-symbol` 或链接期 `--dynamic-list` 精确控制导出表，
保留功能的同时隐藏名字。

> **源码口径核对（合并时补）**：已按 `--version-script` 落地，
> 见 §2.10.1 末尾的核对。

### 2.10.4 P1：`.rodata` 字符串

`/proc/self/maps`、`APK Sig Block 42`、`data/app scan exhausted` 等
仍全部明文。第一版就列过这条，本版未动。

> **源码口径核对（合并时补）**：LSGS 机制已覆盖上述字符串，
> 见 §1.1.5 / §2.2.2 的核对。

### 2.10.5 P2：失败汇聚点

实测仍是 13→1。如果 `c664797` 确实已实现但未进本次构建，构建后应复核。

> **源码口径核对（合并时补）**：三个独立 `delayed_kill_0/1/2`
> 已存在且标进 `.ncx`（`sig_check.c:833/865/889`、`:744`）。
> 原「13→1」统计本身就是误判（§2.2.4）。**本条建议已闭环。**

### 2.10.6 P2：节名

`.ncx` / `.ncxr` 仍在节表里明文列出。真正的隐藏要么合并进 `.rodata`，
要么去掉节表（`--strip-section-headers`，但需要改运行期定位方式）。

> **源码口径核对（合并时补）**：当前源码仍以 `readelf` 可列举
> 全部自定义节。`--strip-section-headers` 会同时破坏运行期定位
> （`ncg_find_section` 依赖节表），代价大于收益，**本条维持未修**。

### 2.10.7 关于 kill 链耦合

**这可能是本版最有价值的不经意设计**（也可能是有意的）。

把 `abort()` 变成控制流的一部分，让「改 PLT 桩」这个通用手法失效。
虽然它让调试变难（日志只剩一行），但**防御收益显著**。

**建议保留，并在文档里明确记录这个设计**，避免后人「优化」掉它。

> **源码口径核对（合并时补）**：**本条建议不采纳。**
> 按当前源码，业务 kill 链已完全不经 libc（内联 `svc`），
> 不存在「`abort()` 参与控制流」的设计。第二版观察到的现象
> 来自 libc++ 静态运行时的异常/terminate 路径，
> 属偶合而非设计。把它当成机制保留，会在 STL 升级时
> 造成虚假的安全感。详见 §2.6.3 的核对。

## 2.11 未完成项（诚实清单）

| # | 项 | 原因 |
|---|---|---|
| 1 | 取得 `master` | 26 分钟未成功 |
| 2 | 解密 `.ncx` / `.ncxh` | 死锁，无参照物 |
| 3 | 看到 `0x504a0` 判定逻辑 | 同上 |
| 4 | 产出可运行绕过包 | 3 次尝试全失败 |
| 5 | 精确单点 patch | 需先知道解密路径 |
| 6 | 动态验证（frida dump） | 未实施 |
| 7 | 验证 `0x258b8` 是否真的仍是唯一出口 | 静态统计，未动态验证 |
| 8 | 验证 `.text` 校验在本样本是否真的跑起来了 | 只看到日志报 clean |

## 2.12 附录：第二版地址速查

### 本版关键地址

| 地址 | 内容 | 段 | 状态 |
|---|---|---|---|
| `0x21ce0` | `JNI_OnLoad` | `.text` | 明文 |
| `0x24204` | `selftest`（跳板） | `.text` | 明文 |
| `0x252f0` | `ncVerify`（转发壳） | `.text` | 明文 |
| `0x25388` | 签名校验主干（1458 指令） | `.text` | 明文 |
| `0x258b8` | 失败汇聚点（13 引用） | `.text` | 明文 |
| `0x2594c` | `bl pthread_create` | `.text` | 明文 |
| `0x25aac` | `adr x1, "APK Sig Block 42"` | `.text` | 明文 |
| `0x25af8` | v2 ID `0x7109871A` 装载 | `.text` | 明文 |
| `0x23ff8` | 构造函数解密分支 | `.text` | 明文 |
| `0x24014` | `mprotect(..., 7)` 解密块 | `.text` | 明文 |
| `0x24104` | `bl 0x50f24`（进 `.ncxh`） | `.text` | 明文 |
| **`0x504a0`** | **真正的判定函数** | **`.ncx`** | **密文** |
| `0x50488` | `selftest` 主体 | `.ncx` | 密文 |
| `0x50568` | 成功路径线程入口 | `.ncx` | 密文 |
| `0x506ac` | 失败路径线程入口 | `.ncx` | 密文 |
| `0x50f24` | `.ncxh` 调用入口 | `.ncxh` | 密文 |

### 节表

| 节 | 地址 | 大小 | 属性 |
|---|---|---|---|
| `.ncks` | `0x17b9c` | 104 (0x68) | `AR` |
| `.nck` | `0x17c04` | 96 (0x60) | `AR` |
| `.ncxr` | `0x17c64` | 96 (0x60) | `AR` |
| `.text` | `0x21750` | 159,128 (0x26d98) | `AX` |
| `.ncx` | `0x484e8` | 33,684 (0x8394) | `AXR` |
| `.ncxh` | `0x5087c` | 2,880 (0xb40) | `AXR` |
| `.ncxhr` | `0x58c60` | 32 (0x20) | `WAR` |

### PLT 桩（与第一版不同）

| 名称 | 第二版 | 第一版 | 备注 |
|---|---|---|---|
| `syscall@plt` | `0x51880` | （第一版未记录） | **我在第一版漏了这一个** |
| `_exit@plt` | `0x51890` | `0x4f8e0` | |
| `raise@plt` | `0x518a0` | `0x4f8f0` | |
| `abort@plt` | `0x51950` | `0x4f6a0` | |

**自我更正（关于 `syscall@plt`）**

第一版报告 §12 我写了「三个 PLT 桩废掉 380 个 abort 调用点」，
并把 `abort`/`_exit`/`raise` 列为全部软目标。**这是不完整的。**

`ncg` 的 kill 链里用 `syscall(SYS_tgkill, ...)` 直接系统调用，
但那是调用 **libc 的 `syscall()`**——它本身也是一个 PLT 表项。
所以真实软目标是 **4 个**，不是 3 个。

第一版我 patch 了 3 个桩就成功了，是因为 `syscall@plt` 那条路径
在第一版里没有成为致命路径（`tgkill` 在 `0x25c14`，
我另外单独 patch 了 `0x25c40`）。

**但「3 个桩够了」这个结论是运气，不是规律。** 正确的表述应是 4 个。

### `.nck` 96 字节布局（与第一版同构）

| 偏移 | 字段 | 本版值 |
|---|---|---|
| 0x00 | magic | `3072ee4891de04b50000000000000000` |
| 0x10 | wrapped_k_so（诱饵） | `d6054d96f1e7128525a5b6cc9b496258` |
| 0x20 | wrapped_k_mac（诱饵） | `df137044a989ac6284cb5c97e2b7e680` |
| 0x30 | expect_mac | `87167211c9f248e0...` |
| 0x50 | pkg_sha8 | `10d2cadff1d5accf` |
| 0x58 | reserved8 | `0000000000000000` |

### `.ncks` 104 字节（比第一版多 8 字节）

| 偏移 | 内容 | 值 |
|---|---|---|
| 0x00 | magic | `3072f6599dd007bd` |
| 0x08 | wrapped_k_stub | `454dbc536a4d03c712b44f2a9c094420` |
| 0x18 | `.ncks` 自身地址 | `0x00017b9c` |
| 0x1c | `.ncxh` 起始 | `0x0005087c` |
| 0x20 | `.ncxh` 大小 | `0x00000b40` |
| 0x24 | `.text` 起始 | `0x00021750` |
| 0x28 | `.text` 大小 | `0x00026d98` |
| 0x2c | reserved | `0x00000000` |
| 0x30 | wrapped_k_mac_head | `ef7b7705b37114305389c11a67abc5a7` |
| 0x40 | expect_mac_head | `...` |
| **0x60** | **`.ncxhr` 地址**（新增） | `0x00058c60` |
| **0x64** | **`.ncxhr` 大小**（新增） | `0x00000020` |

## 2.13 给 AI 的总结（第二版）

### 2.13.1 如果你接手这份报告

**先读 §0 结论速览和 §2.9「这一版到底防住了什么」。** 其余是过程。

### 2.13.2 三个必须知道的坑

**① 不要先改 PLT 桩。**
第一版这招有效（改 3 个桩，30+ 调用点全废）。
**第二版这招会让 App 起不来**——因为 `abort()` 参与了正常控制流。
出现了 `SIGILL` 在 `.ncx` 里，看栈帧 `#01` 是构造函数就说明踩了这个坑。

> **源码口径核对（合并时补）**：现象属实（三次尝试的 tombstone
> 都在），但归因需修正——不是「业务 `abort()` 参与控制流」，
> 而是 libc++ 的 terminate 路径撞上解密流程（§2.6.3）。
> **给后人的可操作结论不变**：改 PLT 桩前先确认调用方归属。

**② `wrapped_k_so` 是诱饵。**
两版值完全相同（`d6054d96...`），`master` 却变了。
用它算 `k_so` 解出来一定是乱码。
**不要据此判断「加密很强」或「算错了」。**

> **源码口径核对（合并时补）**：诱饵现已改真随机（§2.7.1），
> 「两版值完全相同」这个判据**在当前源码中已失效**。
> 但「`wrapped_k_so` 是诱饵」这个结论不变。

**③ 「看不到」不等于「不存在」——本次最贵的教训。**

本报告曾断言「三处改动未生效」（§2.10.1），被核查全部推翻。三条错误：

| 我的错误 | 实际情况 | 性质 |
|---|---|---|
| 搜 `svc #0x0` 得 0 条 → 改动未生效 | **10 条 `svc #0`** | 正则没匹配 llvm 输出格式 |
| 379 个 `abort@plt` 调用者 = kill 链 | 全属 libc++ 静态运行时 | 没确认符号归属 |
| `0x258b8` 被引用 13 次 = 唯一汇聚点 | 该地址在 `heartbeat` 符号内 | 没确认地址归属 |

**第一版和第二版犯了同一个错**：没有先确认「这些符号/地址属于谁」
就直接统计。

**正确判据（已验证）：**

```bash
# kill 链的真实形态是内联 svc，不是 PLT 调用
llvm-objdump -d libnc.so | grep -cE '\bsvc\b'        # 期望 10

# 软目标归属要先看调用方，别只看符号在不在
llvm-objdump -d libnc.so | grep -B3 'abort@plt>' | grep -cE 'terminate|__cxa|syslog'

# 统计引用次数前，先确认地址落在哪个符号范围内
nm -D --defined-only libnc.so | sort
```

**④ 加密段内反汇编不出，不等于没生效。**
`delayed_kill_0/1/2` 在 `.ncx` 里，`objdump` 看到的是密文。
**区分「不存在」与「在密文里」需要对比未锁箱产物。**

### 2.13.3 如果你要继续攻

**静态路径已经堵死了。** 建议：

1. **frida hook `mprotect`**：`0x24014` 那次调用带 `PROT_EXEC`，
   之后的内存就是解密后的 `.ncx`，直接 dump
2. **hook `0x50f24` 的调用点**（`0x24104`）：此时 `.ncxh` 应该已解密
3. **`.ncxr` 暴力**：96 字节里找 32 字节 `master`，配合证书试 HKDF

**不要走的路：**
- 改 PLT 桩（会破坏启动）
- 改 `pthread_create`（`0x2594c`，会破坏初始化）
- 猜 `master`（32 字节，2^256 空间）

> **源码口径核对（合并时补，两条方向性修正）**：
>
> - 第 1 条（hook `mprotect`）方向正确且**已被针对性防御**：
>   `libc_hook_probe` 已从 4 函数扩到 8 函数，新增的正是
>   `mprotect` / `mmap` / `dlopen` / `process_vm_readv`。
>   但要如实说明：这让它**可被发现**，不是**不可能**——
>   解密后明文必然在内存里，这是自解密机制的物理上限。
>   真正杜绝需要服务端取密钥 / 白盒密码学 / 真 VM 解释执行。
> - 第 3 条（`.ncxr` 暴力）**找错了段**：master 在 `.ncxhr`
>   （32B），不在 `.ncxr`（96B，装签名表）。见 §2.1.2 的核对。
>   报告放弃的理由「96 字节无结构特征」也因此不成立——
> 它找的地方根本没有 master。

### 2.13.4 这一版的真实定位

**核心机密保住了，外围地图还在。**

- `master` ✅ 藏住
- 判定逻辑 ✅ 藏住
- 解密链 ✅ 死锁
- kill 链 ✅ 意外耦合

- JNI 符号 ❌ 暴露
- 签名流程 ❌ 明文
- `.rodata` ❌ 泄底
- 失败汇聚 ❌ 单点

**如果只再做一件事：修 JNI 符号面。**
因为 `nm -D` 一条命令就定位全部入口，这是当前最大的「零成本情报泄漏」。

> **源码口径核对（合并时补）**：这件事已经做了（`nc_hide.map`，
> `e0e6bb2`），只保留手写入口、隐藏 dex2c 业务符号。
> 剩下的 `Java_com_nc_link_NcLink_*` 三个符号是 JNI 短名绑定的
> 硬要求，除非找到安全的动态注册时机，否则无法消除。

---

---

# 第三部分 两版对比与演进评价

> 本部分是合并时新增的框架，用来把两份独立记录放到同一张表上。
> 不含新的实测数据，只做归并与交叉引用。

## 3.1 防住了什么：从第一版到第二版

第一版的核心指控「加密做对了，加密的东西不对」在第二轮被逐项回应。
下表左列是第一版给出的修优先级（§1.15.4），右列是源码核对后的现状。

| 第一版优先级 | 改动 | 源码现状（合并时核对） | 闭环 |
|---|---|---|---|
| **P0-1** | kill 链去掉 `abort`/`_exit`，改走内联 `svc` | `env_check.c:358-426` / `sig_check.c:798-807` 全部内联 `svc #0`，被拦时 `__builtin_trap()`；`delayed_kill_0/1/2` 三个独立函数体 | ✅ |
| **P0-2** | `.text` 完整性校验改用构建期基线 | 机制确为「磁盘 vs 内存」（`env_check.c:1095` syscall 直读文件）；跨映射缺陷已修（报错五十四） | ⚠️ 机制对，真机行为未验证 |
| **P1-1** | `master` 改构建期随机 | `so-section-lock.py:574` `os.urandom(32)`，落 `.ncxhr` 后由二级锁箱加密 | ✅ |
| **P1-2** | 判定函数 + 两张表移进加密段 | `nc_link.c:67/82` 标进 `.ncx` / `.ncxr`，`protect.sh:473-483` 同步锁箱 | ✅ |
| **P2** | 失败路径分散 | `delayed_kill_0/1/2` 三独立体，均标进 `.ncx` | ✅ |
| **P3** | 符号抹除 | `nc_hide.map` version-script，隐藏 dex2c 业务符号 | ✅（手写入口因短名绑定必须保留） |
| **P3** | 字符串加密 | LSGS 覆盖 `sig_check.c` / `env_check.c` / `sig_guard2.c` | ✅ |
| **P3** | 节名中性化 | `.ncguard` → `.ncx` 等 | ⚠️ 仅缩短，仍可列举 |
| **P3** | 日志文本与实际行为对齐 | 未改（`sig_check.c` 的 LSG:KILL 文案与立即 tgkill 仍并存） | ❌ |
| **P3** | `XOR_KEY` 碎片改运行期派生 | 碎片改 volatile `.data`；`k_stub` 进一步改为 HKDF(master, seed, crc32(stub)) | ✅（部分） |

**两条未闭环的值得单独说**：

1. **`.text` 完整性校验**：机制已修正为磁盘 vs 内存，但「改一个字节
   真机是否从 `clean` 变 `hit`」始终没有真机对照实验。
   第一版、第二版都只观察到 `clean`。这是本文最大的未验证项。
2. **日志文案对齐**：第一版 §1.11.2 记录「日志说延时 1~3s，
   实测 19ms SIGKILL」，源码里两条路径与文案至今并存。
   它不影响安全，但会持续误导排查方向。

## 3.2 第二版新暴露的问题（已由源码核对定性）

| 报告观察 | 源码核对结论 |
|---|---|
| kill 链与解密流程耦合（§2.6） | 业务 kill 链已不走 libc；观察到的是 libc++ terminate 路径偶合，**非设计**，不可依赖 |
| SHA256/HKDF 实现在 `.ncx` 密文（§2.4.2） | `nc_guard_key.c` 无段属性，实为明文。死锁结构仍成立但链条不同（见 §2.4.3） |
| `.ncxr` 里找 `master`（§2.13.3） | 找错段，master 在 `.ncxhr` |
| `wrapped_k_so` 两版相同 → 诱饵（§2.7.1） | 结论对，但该判据已失效：诱饵改 `os.urandom(16)` |
| JNI 符号 303 个（§2.2.1） | 属实且已修：`nc_hide.map` 隐藏 dex2c 符号，手写入口因短名绑定保留 |
| 失败汇聚 13→1（§2.2.4） | 统计方法错误，实际是多出口且在密文里 |

## 3.3 当前状态总结（合并时）

**已经站住的**：
- `master` 随机化 + 藏入 `.ncxhr` 密文（第一版最致命缺陷）
- 判定函数与两张表进 `.ncx` / `.ncxr` 密文（第一版「加密了壳没加密核」）
- kill 链内联 `svc`，无 PLT 软目标（第一版 30 秒绕过的手法）
- 二级锁箱 + `k_stub` CRC 自绑定（改 `.text` 一个字节即废）
- 诱饵真随机，diff 识破手法失效
- dex2c 业务符号隐藏
- LSGS 字符串密文（含 `sig_guard2.c`）
- hook 探针扩到 8 函数，覆盖解密链关键点

**仍未站住 / 未验证**：
- `.text` 完整性校验的真机检出行为（无对照实验）
- 反调试/反注入的**拦截能力**（两版都只测了干净环境无误报）
- 解密后明文在内存里可被 dump（自解密机制的物理上限，只能「可发现」不能「不可能」）
- 节表可列举（`--strip-section-headers` 会破坏运行期定位，代价大于收益）
- 日志文案与实际行为不对齐

**结构性上限（要如实写在这里）**：自解密机制决定了
「密钥+密文+解锁代码」三者必须在同一台设备上齐备，
因此动态 hook（frida hook `mprotect` 后 dump）**在原理上
无法被静态防御挡住**。当前做到的是让它可被发现
（8 函数 hook 探针），不是让它不可能。真正杜绝需要
服务端取密钥 / 白盒密码学 / 真 VM 解释执行，这三项都不在
「高性能 + 小改动」的约束内。

---

# 附录 C：复核方法（懒人版）

> 以下内容原为 `简盒-复核清单.md`，随本次文档清理并入本文。
> 它服务的是**第一版**样本的复核；第二版样本的复核清单见 §2.10.1 末。

## C.1 复核优先级

**时间有限就只做这两条：**

| 优先级 | 项目 | 耗时 | 能验证什么 |
|---|---|---|---|
| **★★★ 必做** | A. 装一次 APK | 2 分钟 | 整条攻击链是否真通（连带证实 B、C、D） |
| **★★★ 必做** | B. 验一次 `k_so` | 1 分钟 | 密钥派生公式是否成立（连带证实 E） |

**这两条过了，其余都是推论，错也错不到哪去。
任何一条不过，主报告该重写。**

### A. 装一次 APK（验证整条链）

```bash
adb devices                              # 确认设备在线
adb uninstall com.xixin.box              # 清掉旧版
adb install -r ~/jianhe_re_work/bypass4_signed.apk
adb logcat -c
adb shell am start -n com.xixin.box/.MainActivity
sleep 10
adb shell pidof com.xixin.box            # 期望：有 pid 输出
adb shell dumpsys activity activities | grep topResumedActivity
adb logcat -d | grep -iE 'Fatal signal|ANR in com.xixin|Force finishing'
```

| 项 | 预期 |
|---|---|
| `adb install` | `Success` |
| `pidof` | 输出一串数字（不是空） |
| `topResumedActivity` | `com.xixin.box/.MainActivity` |
| `Fatal signal` 等 | **空** |

预期的日志（应用自己输出）：

```
nc : 【数据】实际证书指纹 actual_fp (a3b08bf6...)
nc : 【E】nc: mm
nc : 【失败】指纹比对不一致 → 校验失败,延时退出已安排
nc : 【流程】延时退出线程启动:随机延迟后 abort
```

**关键**：日志说"失败"，但进程**没死**。这就是绕过成功的证据。

产物校验值：

```
bypass4_signed.apk
  sha256 = e83f4d9f4b9d05a0c04e2c5ca3e4f2bc359ad441d5366c53e632fcf4f05e2165
  大小   = 4,938,198 B
```

**如果 sha256 对不上，说明产物被改过，不要用这个结果。**

这条不过说明什么：如果装上去仍闪退，说明还有没找到的 kill 路径。
取新 tombstone：

```bash
adb shell "ls -t /data/tombstones/ | head -1"
adb shell "cat /data/tombstones/tombstone_00" | head -30
```

看 `#01 pc` 落在 `libnc.so` 的哪个地址，那就是漏掉的点。

### B. 验一次 `k_so`（验证密钥派生）

主报告声称：

```
k_so = HKDF-SHA256(ikm = master, salt = SHA256(certDER),
                   info = "nc-so-v1" + 包名, length = 16)
master = 0x11 × 32
```

如果这个公式对，应该算出 `k_so = 81830c13771b64b8de9a2d4642e19029`。

```bash
cd ~/jianhe_re_work
python3 probe_ncguard.py target.apk ex/lib/arm64-v8a/libnc.so
```

预期输出：

```
signing block id = 0x7109871A
certDER len = 666
certDER sha256 = d82e48dae7ce6268ebcefd61feb8128fdf1a55f574cbbbc788db7be4491b689e
k_so = 81830c13771b64b8de9a2d4642e19029
.ncguard addr=0x46ac8 off=0x46ac8 size=0x7f1c
decrypted head: c0035fd6fd7bbaa9fc6f01a9fd030091...
```

**关键判据**：解密后首字节必须是 `c0 03 5f d6`（`ret`），
接下来是 `fd 7b ba a9`（`stp x29,x30,[sp,#-0x60]!`）。
**这是合法 AArch64 函数序言。** 如果 `master` 是错的，
RC4 解出来必然是乱码，不可能出现这种结构。

这条不过说明什么：
- `k_so` 不对 → `master` 不是 `0x11×32`，或派生公式记错
  → 第一版 §1.2 核心论断作废
- `certDER len` 不是 666 → 证书提取逻辑有问题

### C~F. 其余复核项（第一版样本）

| 项 | 验什么 | 现状 |
|---|---|---|
| C | 三个 PLT 桩已改成 `ret`（`0x4f6a0`/`0x4f8e0`/`0x4f8f0`） | 第一版 §1.9.4 |
| D | 判定函数已 patch（`0x238bc` = `20 00 80 52 c0 03 5f d6`） | 第一版 §1.9.1 |
| E | `master` 是 `0x11×32`（`od 0x13e80`） | **不必单独验**，跟 B 一起验即可 |
| F | `.ncguard_head` XOR key 正确（统计推断得出，最不可靠） | 第一版 §1.14；不影响 A/C/D 结论 |
| G | `.text` 完整性校验机制 | **原判断已推翻**，见 §1.11.1 核对 |

## C.2 快速复核脚本

把下面整段存成 `review.sh` 跑一遍：

```bash
#!/data/data/com.termux/files/usr/bin/bash
cd ~/jianhe_re_work || exit 1
echo "=== 1. 产物完整性 ==="
sha256sum bypass4_signed.apk
echo "期望 e83f4d9f4b9d05a0c04e2c5ca3e4f2bc359ad441d5366c53e632fcf4f05e2165"

echo "=== 2. master (应为 32 个 11) ==="
od -A x -t x1 -j 0x13e80 -N 32 ex/lib/arm64-v8a/libnc.so

echo "=== 3. 判定 patch (应 20 00 80 52 c0 03 5f d6) ==="
od -A x -t x1 -j 0x238bc -N 8 libnc_bypass4.so

echo "=== 4. PLT 桩 (应 c0 03 5f d6) ==="
for a in 4f6a0 4f8e0 4f8f0; do
  echo -n "0x$a: "; od -A n -t x1 -j 0x$a -N 4 libnc_bypass4.so
done

echo "=== 5. abort 调用点数量 ==="
llvm-objdump -d libnc_bypass4.so | grep -c 'bl\s+0x4f6a0'

echo "=== 6. k_so 派生 ==="
python3 probe_ncguard.py target.apk ex/lib/arm64-v8a/libnc.so

echo "=== 7. 真机安装测试 ==="
adb uninstall com.xixin.box >/dev/null 2>&1
adb install -r bypass4_signed.apk
adb logcat -c
adb shell am start -n com.xixin.box/.MainActivity >/dev/null 2>&1
sleep 8
echo -n "pid: "; adb shell pidof com.xixin.box
adb shell dumpsys activity activities | grep topResumedActivity | head -1
adb logcat -d | grep -iE 'Fatal signal|ANR in com.xixin|Force finishing' | head -3
echo "(上面若无输出 = 无崩溃)"
```

## C.3 第一版关键结论的可信度分级

| 结论 | 证据等级 | 复核项 |
|---|---|---|
| 签名校验逻辑正确检出 | **A 级**（真机日志 + 反汇编双重） | A |
| `master = 0x11×32` 且真的在用 | **A 级**（B 项验算闭环） | B、E |
| `.ncguard` 可离线解开 | **A 级**（解出合法 AArch64） | B |
| 三个 PLT 桩废掉 30+ 个 abort 调用点 | **A 级**（字节 + 反汇编 + 运行验证） | C、A |
| 判定函数在明文 `.text` | **A 级**（反汇编直读） | D |
| 最终包能跑 | **A 级**（真机 30 秒 + 前台确认） | A |
| `.ncguard_head` key 是 `346c...` | **C 级**（统计推断，3/16 字节验证） | F |
| `.text` 校验机制 | **D 级**（原判断已推翻，见 §1.11.1） | G |
| 反调试能挡住 frida | **未验证**（只测了干净环境） | — |

**A 级可信，C 级需复核，D 级不要采信，未验证项不要当成结论。**

## C.4 已知的报告缺陷（第一版作者自述）

复核者不必再花时间找这些，作者已经知道：

| # | 缺陷 | 影响 |
|---|---|---|
| 1 | 结论改过三次（3.5 → 2.5 → 1.5） | 早期判断不可靠，看最终版 |
| 2 | 曾说「`.ncguard_head` 防住了」，下一轮自己推翻 | §1.2.7 有记录 |
| 3 | `master` 那条能成立，**依赖 B 项验证** | 单看字节不算证据 |
| 4 | `.ncguard_head` key 是统计推断，非代码读取 | F 项最不可靠 |
| 5 | `.text` 完整性校验的机制判断**错了** | 已在 §1.11.1 更正 |
| 6 | 4 分钟/70 分钟这两个数字含「作者已看过源码」的成分 | 纯盲测应再加 20~30 分钟 |
| 7 | 反调试/反注入的**拦截能力未验证**（只测了干净环境无误报） | §1.11.3 已标注 |
| 8 | 只测了 30 秒运行，未覆盖 20 秒周期的常驻复查线程完整周期 | 长时间运行可能仍有问题 |
| 9 | **§1.5.2 `reserved8` 非零 —— 误判**（字段长度算错） | 已更正，不影响任何安全判断 |

## C.5 已由外部复核确认的错误

| 出处 | 原结论 | 实际情况 | 处理 |
|---|---|---|---|
| 第一版 §1.5.2 | `reserved8` 非零，产物与源码不一致 | **误判**。`expect_mac` 是 32 字节不是 16 字节，字段整体前移 8 字节。看到的 `10d2cadff1d5accf` 位于 `0x50`，是 `pkg_sha8`；`0x58` 的 `reserved8` **确实全零** | 已在 §1.5.2 标注推翻，并附正确字段切分 |

**复核者的纠正方法**（供后续参考）：

```bash
python3 - <<'PYEOF'
so = open('ex/lib/arm64-v8a/libnc.so','rb').read()
slot = so[0x16694:0x16694+96]
fields = [('magic',0,16),('wrapped_k_so',16,16),('wrapped_k_mac',32,16),
           ('expect_mac',48,32),('pkg_sha8',80,8),('reserved8',88,8)]
for name,off,ln in fields:
    print(f"0x{off:02x} {name:14s} = {slot[off:off+ln].hex()}")
PYEOF
```

输出应为：

```
0x00 magic          = 3072ee4891de04b50000000000000000
0x10 wrapped_k_so   = d6054d96f1e7128525a5b6cc9b496258
0x20 wrapped_k_mac  = df137044a989ac6284cb5c97e2b7e680
0x30 expect_mac     = 4e4be1d5...9366737bf7fec1ef6fb7fa147d2dfb49
0x50 pkg_sha8       = 10d2cadff1d5accf
0x58 reserved8      = 0000000000000000    ← 全零
```

**顺带验证**：`SHA256("com.xixin.box")[:8] = 10d2cadff1d5accf`，
与 `pkg_sha8` 完全一致，说明该字段语义正确、功能正常。

**这条错误的影响范围**：仅限 §1.5.2 本身。该结论**未被用于任何
安全判断或评分**，因此第一版的强度和结论不受影响。

---

## 附：本文与两份原始报告的差异说明

| 项 | 第一版原报告 | 第二版原报告 | 本文 |
|---|---|---|---|
| 文档 | `简盒-so层静态防御实测报告.md` | `简盒-加固后复测报告.md` | 两者合并 |
| 编号 | §0–§17 | §0–§13 | §0 + 第一版 §1.x + 第二版 §2.x + §3 + 附录 |
| 自我更正 | 保留 | 保留 | 全部保留，未删任何结论 |
| 源码核对 | 无 | 无（仅有提交记录对照） | 合并时补入，均以 `>` 引用块标注 |
| 复核方法 | 独立文档 | — | 并入附录 C |

**两份报告不冲突，是同一防御体系的两个时间点。**
本文的 §3 把两者放到同一张表上，供后续接手者一次性看清演进。
