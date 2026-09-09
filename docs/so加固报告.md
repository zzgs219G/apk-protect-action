# so 加固报告(2026-10)

> **本文是什么**:本次 so 加固改动的完整记录——做了什么、为什么、怎么验证、
> 如果出问题怎么修。写给三类读者:仓库主人(复盘决策)、下一任 AI(修复上下文)、
> 审查者(核对红线)。
>
> 配套文档:`docs/流程文档.md` §9 已同步追加本次变更记录;本次改动背景
> (防御评估全文)见当次会话,要点已浓缩进 §2。

---

## 1. 背景与目标

防御评估结论(2026-10):本项目全部防线(签名校验 `sig_check.c`、环境检测
`env_check.c`、延时 abort)寄居在**明文编译**的 `libnc.so` 里。PC 端攻击者:

1. `strings libnc.so` 直接看到 `"signature verify ok"`、`"env check triggered"`
   等路标词 → **秒级定位**校验函数
2. Ghidra 反编译 → `sig_verify`/`env_check_run` 各 patch 一条 RET → 防线全灭
3. 自有 keystore 重签 → 完事

本次加固目标:**消灭"自动定位"手段,提高人工逆向成本,但不把清晰源码变天书**
(用户明确约束:不引入字符串加密宏之类牺牲可读性的方案)。

## 2. 改动清单(3 个文件 + 1 个附带修复)

### 2.1 `scripts/lib/lib-ndk.sh`(非冻结,mk 模板唯一来源)

| 追加项 | 值 | 作用 |
|---|---|---|
| `APP_CPPFLAGS`/`APP_CFLAGS` | `-fno-ident` | so 里去掉编译器版本指纹字符串 |
| 同上 | `-Oz` | 极限尺寸优化,小函数内联,模糊函数边界 |
| 同上 | `-ffunction-sections -fdata-sections` | 每函数/数据独立段,供链接期裁剪 |
| `Android.mk` 新增 `LOCAL_LDFLAGS` | `-Wl,--gc-sections -Wl,--build-id=none` | 丢弃未引用段;去掉构建指纹 ID |

**特性:全局自动生效**。未来新增任何 `.c/.cpp` 只要过这道编译,自动加固,
无需逐文件维护(回答"以后新增源码要不要再升级一次"——不要)。

### 2.2 `sigcheck/src/sig_check.c`(冻结,用户当次点名)

**(a) 日志路标词中性化**(3 处,替换式改动):

| 原文(so 内明文) | 改后 | 语义保留 |
|---|---|---|
| `sig hash slot empty, skip verify` | `nc: slot empty` | 全零槽位跳过分支,行数/位置不变 |
| `signature verify ok` | `nc: ok` | 校验通过 |
| `signature mismatch (actual vs expected...)` | `nc: mm` | 校验失败(mm=mismatch) |
| `cert fp actual=%s` | `nc: fp=%s` | **排障保留**:fp 后是完整实际指纹十六进制 |

**刻意保留的日志**(排障生命线,报错十四定位链路依赖):
`apk not found (maps+data/app both failed)`、`open apk failed: errno=%d`、
`so-dir candidate not accessible` 等。理由:这些只在报错场景出现,而报错场景
攻击者本来就在调试自己的补丁;删掉它们会重演"签名一致仍闪退无法定位"的历史。

**(b) 延时堆破坏**(纯追加,`delayed_kill` 内、`sleep` 之前):

```c
/* 随机 8~23 轮:malloc 64~4KB → 1~4ms×50~250 次抖动 → free */
```

原理:校验失败后,除延时 abort 外,后台线程先持续 malloc/free 不同尺寸块。
攻击者即便 hook 掉 `abort()`/`sleep()` 让延时线程失效,**进程堆布局已被碎片化**,
后续任意时点崩溃难以归因。纯 malloc/free:不写入、不触碰业务内存、宿主测试安全。

### 2.3 `sigcheck/src/env_check.c`(冻结,用户当次点名)

1 处:`env check triggered` → `nc: t`。其余探测函数的特征串
(`frida-agent`、`lspd` 等)是**检测逻辑本身**,不可动。

### 2.4 附带修复:`sigcheck/src/sig_hash.h` 模板(非冻结)

**缺陷**:仓库模板仍是 2026-10 之前的旧形态——只有明文 `SIG_HASH` 数组,
没有 `SIG_SALT`/`SIG_HASH_STORED`。线上没炸只因流水线 `make-sig-hash.sh`
每次覆写生成新头;但**任何直接用模板编译 sig_check.c 的场景(宿主测试/
新 AI 复现)必然编译失败**(`use of undeclared identifier 'SIG_SALT'`)。
本次宿主验证时暴露,已同步为派生形态全零占位(全零 = 调试模式语义不变)。

## 3. 明确放弃的方案(决策记录)

| 方案 | 放弃原因 |
|---|---|
| 字符串加密宏(OBF_STR) | 纯 C 编译期加密需常量表达式折叠技巧,源码可读性骤降——违背用户"不搞复杂源码"约束;删路标词达到同等"strings 盲区"效果 |
| patch 自污染(污染 dcc 方法缓存表) | 需修改 dcc 生成的 `Dex2C.cpp` 模板(dcc/ 是冻结禁区)或生成后 patch,复杂度高;且与 dcc 升级耦合。留作二期候选 |
| OLLVM 换工具链 | workflow 要换 setup-ndk 配置,回归成本大;当前三项已覆盖 P0 |
| binary rewriting(对成品 so 后处理) | ELF 解析+重定位回填,静默出错风险高(报错七/十一同型),且源码在手无此必要 |

## 4. 验证记录(全部通过)

宿主端 clang 21.1.8(Termux,`android/log.h` 用 stub 替代):

| 场景 | 操作 | 结果 |
|---|---|---|
| 编译 | 两个源文件 `-c` 编译 | 均通过,无警告级问题 |
| 运行时①调试模式 | 全零槽位(真实模板头)跑 sig_verify | 干净返回,exit 0 |
| 运行时②失败路径 | 非零槽位+无 APK | 主线程存活 → 延时线程堆破坏后 abort,exit 134(预期) |
| 运行时③env_check | 被 ptrace 附着的 Termux shell | 正确命中 tracer_probe(TracerPid=20946,真实命中非误报,与 2026-10 首次验证一致) |
| 语法 | `bash -n` lib-ndk.sh / protect.sh | 全过 |
| diff | `git diff` 全量复核 | 仅预期改动,冻结区无越界 |

冻结红线复核:`dcc/`、`extract-cert-fp.py`、`inject-loadlib.py`、
`mark-native.py`、`apktool.jar` **零改动**。

## 5. ⚠️ 下一任 AI 修复指南(如果改炸了)

**先看这里再动手。**

### 5.1 症状 → 根因 → 修法对照

| 症状 | 最可能根因 | 修法 |
|---|---|---|
| 云端 ndk-build 报 `unrecognized command line option` | runner NDK 版本过老不认 `-Oz`/`-fno-ident`(NDK r26d 都支持,理论上不会) | 查 workflow `setup-ndk` 版本;确系过老则从 `lib-ndk.sh` mk 模板里删掉对应 flag(逐个删,二分定位),**不要回滚整个文件** |
| so 体积异常膨胀/异常缩小 | `-ffunction-sections`+`--gc-sections` 与某个源文件交互异常 | 对比改动前后 `libs/*/libnc.so` 大小;`nm --size-sort` 看符号;必要时仅撤 `LOCAL_LDFLAGS` 的 gc-sections |
| 真机"签名一致仍闪退"且日志只有 `nc: mm` | 正常校验失败!先看同时间戳的 `nc: fp=` 行,比对实际指纹与开发者重签 keystore 是否一致——**多半是用户换了 keystore,不是代码 bug**(设计约定,见 §2 步骤 2 审查点) | 不是 bug,引导用户确认 keystore |
| 真机随机崩溃、时间点飘忽 | 可能是延时堆破坏与某机型低内存设备交互(极小概率,8~23 轮×4KB 上限很温和) | 应急:注释 `delayed_kill` 中 `[so加固 2026-10 追加]` 标注的 `{...}` 块(有明确标注,好找);长期:把轮数上限调低 |
| sig_check.c 编译报 `SIG_SALT undeclared` | 有人把 `sig_hash.h` 模板又改回了旧形态 | 对照本文 §2.4 恢复模板(必须含 SIG_SALT_LEN/SIG_SALT/SIG_HASH_STORED);真正的头由 `make-sig-hash.sh` 生成,勿手改其生成逻辑 |
| 日志里找不到 `nc: ok` | 全零槽位(调试模式)or 日志开关没开(sdcard 哨兵文件),先查这两个再怀疑代码 | 见 §5.2 排障入口 |

### 5.2 排障入口(按序)

1. `docs/流程文档.md` §5 报错对照表 → §9 变更历史(本次条目在最末)
2. 真机文件日志:sdcard 建 `/storage/emulated/0/sigcheck_debug` 哨兵 →
   重启 App → 看 `/storage/emulated/0/Android/data/<包名>/files/sigcheck_log.txt`
   (`nc: fp=` 行给出实际指纹;`apk not found` 行给出定位分支)
3. 宿主端复现:参照 §4 验证表,clang + android/log stub
   (stub 内容:`__android_log_print` 空实现 + 三个 prio 宏) +
   流水线生成的 sig_hash.h 即可,无需 NDK

### 5.3 改动红线(修复时同样适用)

- `sig_check.c`/`env_check.c` 是冻结模块:修复需用户当次点名;只允许追加,
  不改写已有逻辑行
- `nc: ok`/`nc: mm`/`nc: fp=`/`nc: t` 这些中性日志**不要再改回长描述**——
  那是把路标词还给攻击者;排障语义已由 `nc: fp=`(指纹)+ 报错行(定位)承担
- `lib-ndk.sh` 的 mk 模板是唯一模板来源(报错十一红线),改动前先读
  流程文档 §0.1 和 §9 报错十三
- **不要**为了"更安全"自行加回字符串加密/OLLVM——那是本次明确放弃的方案
  (见 §3),除非用户重新拍板

### 5.4 本次改动的完整范围(git 视角)

```
scripts/lib/lib-ndk.sh    +9 -1   编译/链接参数(非冻结)
sigcheck/src/sig_check.c  +22 -4  日志中性化3处 + 堆破坏追加(冻结,用户点名)
sigcheck/src/env_check.c  +1 -1   日志中性化1处(冻结,用户点名)
sigcheck/src/sig_hash.h   +11 -5  模板同步派生形态(附带修复,非冻结)
docs/流程文档.md                  §9 追加本条目(另有报错十五死链清理,与本任务无关)
docs/报错文档.md          删除    (用户要求,报错十五日志已并入流程文档)
```

## 6. 效果与性价比(回答"值不值")

**效果**:攻击者自动定位手段(strings 搜路标词、搜编译器指纹)全部失效;
函数边界因 `-Oz` 内联变模糊;hook abort 后还有堆碎片化兜底。PC 端破解成本
从"1~2 小时"提升到"逐函数人工逆向 + 不确定能否归因崩溃"。

**性价比高的三个理由**:
1. 总改动 43 行,其中 30 行是编译参数(零维护、永不过期)
2. 源码可读性几乎无损(注释完整记录了每处原文,还原成本低)
3. 攻击成本提升是不对称的:攻击者面对的是不确定性和归因困难,防御者面对
   的只是多写了几行注释

**局限(诚实声明)**:熟练逆向者仍可逐函数逆向定位 sig_verify(Ghidra
里"读 APK 文件 + SHA256"的模式依然可认)。本次目标不是"不可破解",
而是让破解成本 > 大多数攻击者的收益阈值。要更硬的保护(VMP/OLLVM)
是另一个量级的工程,见 §3 放弃项。
