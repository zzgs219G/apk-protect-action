# AGENTS.md — AI 改动本仓库前的必读契约

Agent 编程任务执行规范（架构师增强版）

---

本指南适用于Agent编程任务：

1. 角色定位：你不仅是编码员，更是该任务的技术负责人。你的核心职责是交付正确且可靠的方案，而非仅仅交付代码。若需求本身存在问题（业务逻辑矛盾、技术不可行、隐患未处理），你有权质疑并拒绝执行，但需给出明确理由和替代建议。
2. 工具调用原则：
   · 优先并行调用（同一轮同时发起多个工具），其次批量合并（多个bash命令用 && 或分号连接）。
   · 禁止无依赖关系的串行多轮；仅当后续工具输入依赖前面输出，才允许拆分为多轮。
   · 单轮工具调用数量上限为20个，超出时拆分为多轮。
3. 资源消耗通用约束（无论后端计费模式，必须遵守，不得降低推理思考质量）：
   · 禁止无差别读取全部完整源码；未变更文件只读取结构摘要（函数名、接口），仅改动目标文件读取完整内容。
   · 工具返回自动裁剪冗余噪声：过滤无关日志、stderr垃圾输出、无关元信息，仅保留决策必需内容。
   · 输出优先使用diff/片段补丁，禁止输出完整大文件，除非用户明确要求完整文件。
   · 上下文膨胀时，允许压缩执行过程描述（如"已读A文件"），但绝对禁止压缩三类核心信息：用户原始需求原文、所有显式约束条件、已确认的技术结论。这三类必须原样保留。
   · 严禁截断、删减模型内部思考推理链，不得为节约资源降低解决问题能力。
4. 核心工作法（拿到需求后的强制思维路径）：
   · 第一步——挑战需求：先推演该需求的真实业务场景。如果需求本身缺乏合理性（如"将所有日志改成Debug级别"），必须质疑并追问原因，拒绝盲目执行。
   · 第二步——多路径对比：至少构想两种实现方案，对比其复杂度、维护成本、风险差异，选定最优方案并说明理由。禁止只给一种方案就开写。
   · 第三步——逆向审查：分析你的方案在以下4个压力场景下的表现——① 变更后能否快速回滚？② 新增外部依赖如果超时/下线，系统如何降级？③ 多步写入操作中途失败，是否会留下脏数据？④ API或数据库Schema变更，老版本客户端能否无感兼容？
   · 第四步——交付代码：代码只是上述思考过程的落地产物。确认前3步无阻塞问题后，再输出diff/补丁。

---

无需构建编译

> 给 AI(以及人类)的硬约束。**改任何代码前先读完本文。**
> 违反下列任何一条,改动视为无效,必须回滚。
> 配套强制手段:冻结模块的回归测试(若 `tests/` 目录存在则执行,冻结模块被改红即失败)。

---

## 1. 冻结模块清单(⛔ 禁止修改,除非用户在当次对话中明确点名)

以下模块经过真机/宿主端反复验证,是**已收敛的稳定资产**。
AI 不得"顺手优化"、"重构"、"重命名"、"整理格式"。它们的正确性靠
回归测试钉死(若 `tests/` 目录存在)——**测试红了 = 你改坏了,立即回滚**。

| 冻结模块 | 职责 | 钉死的回归测试 |
|---|---|---|
| `scripts/sigcheck/src/sig_check.c` | 签名校验 native 实现(maps 定位截断、Signing Block 解析、SHA-256) | `scripts/sigcheck/javalink/tests/test-javacheck.sh`(11 大项,host 编译+对拍) + `scripts/sigcheck/tests/test-lsgs-strings.sh`(密文零泄漏) |
| `scripts/sigcheck/src/env_check.c` | 环境检测(10 探针/反调试抢占/so 自校验/心跳检查端) | 同上两套 + `scripts/sigcheck/tests/test-lsgs-strings.sh`。**2026-10-19**:`env_delayed_kill` 进 `.ncguard`;`safe_syscall` 改内联 `svc`(arm64 `x8`/armv7 `r7`)、新增 `env_raw_die`——**`syscall()` 本身也是 PLT 表项**,验收必查 `nm -D -u \| grep -wE "abort\|syscall\|_exit\|raise"` 为空。**kill 函数标段、调用方(`env_fail`)不标段**(后者是 unlock 使用者,标了即死锁) |
| `scripts/sigcheck/src/nc_link.c` | Java↔Native 桥接(ncVerify/heartbeat + 心跳武装) | test-javacheck.sh(判决对拍) + 心跳语义对拍(变更历史 10-16 条) |
| `scripts/inject/inject-loadlib.py` | loadLibrary 插桩(幂等、多 dex、AXMLPrinter) | `tests/test_inject_loadlib.py`(冒烟,若存在) |
| `scripts/sigcheck/hash/extract-cert-fp.py` | 证书指纹提取(纯 stdlib 解析 Signing Block) | `tests/test_cert_fp.py`(伪造 APK 双场景,若存在) |
| `scripts/repack/mark-native.py` | native 壳替换 + 插桩 | 冒烟: 回归测试内嵌 |
| `tools/dcc/`(解压产物;真源 `tools/dcc.zip`) | dcc 工具(**引擎已下架**,现仅为 apktool.jar + 内置 androguard 载体) | 严禁任何改动(历史: 报错三/九);真源包 `tools/dcc.zip` 严禁改包/换版/**删除** |
| `tools/dcc/tools/apktool.jar` | 解包/重打包工具(apktool 3.0.3,随 dcc.zip 解压) | 严禁替换版本(历史: 报错四/五);dcc 引擎下架后这是该 zip 的唯一存在理由 |
| `scripts/sigcheck/src/nc_guard_unlock.c` | `.ncguard` 段运行期自解密(**2026-10-18 起已退出 NDK 工程**,保留为历史存档;现行入口是 `nc_guard_boot.c`) | 真机已验证: 4012/2750B 密文、selftest=59、冷启动无可测劣化;改动前必读 `docs/流程文档.md` §3.12 的 8 条审查点 |
| `scripts/sigcheck/src/nc_guard_boot.c` | 自解谜设施:明文 stub(`.text`)+ unlock 本体(`.ncguard_head` 密文) | 真机链路已验证: 两级锁箱后 dlopen → add/mul/selftest 全对;**绝不可把 `ncg_head_unlock` 标进 `.ncguard`**(它得先被 stub 解出来);stub 用简单 XOR 而非 RC4,`lock_head()` 必须同算法 |
| `scripts/sigcheck/src/nc_guard_key.c` | HKDF-SHA256 + 证书 DER 提取(`k_so = HKDF(master, SHA256(certDER), info)` ) | 无调用方,是"HKDF 契约的可执行证明";sha256/hmac/hkdf 三组测试向量对拍过,勿重写密码学原语 |
| `scripts/sigcheck/src/nc_link.c` | Java↔Native 判决核心 `nc_verify_t1` + 心跳记录侧 | `test-javacheck.sh` 11 大项(判决对拍/心跳语义)。**2026-10-19**:`nc_verify_t1` 进 `.ncguard` 段,两张签名表进 `.ncguard_ro`——**`ncVerify`/`heartbeat` 两个 JNI 入口绝不能标段**(它们是 unlock 调用方,标了即死锁);段标记必须条件化 `NC_GUARD_SECTIONED && !NCLINK_HOST_TEST`(否则宿主测试读到密文假红) |
| `scripts/sigcheck/src/nc_guard_probe.c` | `.ncguard`/`.nckey` 两段的**唯一定义处**(`ncg_key_slot[96]` 就是 `.nckey` 段全部内容) | 改数组长度必须同步 `so-section-lock.py` 的 `assert len(blob)==96` 与 `nc_guard_boot.c` 的 `NCG_SLOT_SIZE`——不一致在构建期即 AssertionError。**2026-10-19 P1-a 从 80 扩到 96**：新增 `pkg_sha8`(包名指纹)+reserved |
| `scripts/lib/so_section_mark.py` | 通用段标记器(第2层设施):规则=函数头正则,零模块逻辑 | 新消费者接入前必读 `docs/流程文档.md` §3.12.1 的接入清单;改规则必须跑 `--check -v` 实测命中,不许只看正则可编译 |

### LSGS 密文机制约束(2026-10 新增,改 sig_check.c/env_check.c 前必读)

- 上述两个 C 文件里的**所有功能语义字符串**(中文文案/检测特征串/外围串)
  一律走 `/*LSG:NAME|...*/` 或 `/*LSGS:NAME|...*/` 标记 → 构建期
  `scripts/sigcheck/log/make-sig-log.py` 扫描加密 → so 里只有密文。
- **新增/修改标记必须重新生成** `sig_log_data.h`(protect.sh 自动做);
  直接写明文字符串 = 改坏了(strings 零泄漏断言会红)。
- 注释里**禁止书写 LSGS 标记的字面形态**(嵌套注释提前终结,编译炸,
  报错速查已留档)。
- `sig_log_data.h` 是构建中间产物,不进 git,不存在"改坏"一说。

### 为什么"100% 正确"也必须冻结

历史事故(详见 `docs/流程文档.md` §9)中,正确模块被改坏的原因**从来不是
逻辑错,而是 AI 在改别处时顺手重写了它们**:

- 报错三: 移动脚本目录时 `__file__` 路径少算一级 → `ModuleNotFoundError`
- 报错七: 改写文件时 `r'\d'` → `r'\\d'` 双重转义 → 静默收窄匹配
- 报错十一: 抽公共 mk 模板时丢了 dcc 原版 `nc/*.cpp` 子目录布局 → 空壳 so
- 报错十二: maps 定位分支被重写时截掉 `base.apk` 文件名 → 必闪退

**教训: 文字警告防不住文本级重写,只有回归测试能。**

## 2. 允许的改动方式

1. **新增模块**: 新建文件/目录,实现新功能(如 `packer` 模块),不动冻结区。
2. **改非冻结脚本**: `scripts/pipelines/*.sh`、`scripts/lib/*.sh`、workflow yml。
3. **修复冻结模块的真实 bug**: 必须满足——
   - 用户在当次对话明确报告了该模块的错误行为(附日志/复现);
   - 改动后回归测试全绿(若 `tests/` 目录存在);
   - 在 `docs/流程文档.md` §9 变更历史追加一行(报错 N)记录根因。
4. **扩展冻结模块**(加日志、加防御): 只允许**追加**,不允许改写已有逻辑行。

## 3. 改动后的必做动作(任何改动,不论大小)

```bash
git diff                          # 自查: 只含预期改动
```

(原 `tests/run-tests.sh` 与 module-guard.yml CI 守卫已移除;改动冻结模块
仍需自查 diff,并在 docs/流程文档.md §9 留痕。)

## 4. 模块化契约(新增模块时遵守)

- 模块 = 独立脚本 + 明确 CLI 契约 `<输入> <输出> [参数]`,不 import 仓库内
  其他模块的内部函数(公共能力放 `scripts/lib/`)。
- so 名统一 `nc`;`ndk_write_mk` 是唯一 mk 模板来源(报错十一)。
- 每个新模块必须带最小回归测试(若仓库恢复 `tests/` 目录则挂进运行入口)。
- 文档 `docs/流程文档.md` 与代码同步更新,§9 追加变更历史。
