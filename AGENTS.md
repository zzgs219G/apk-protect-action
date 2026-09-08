# AGENTS.md — AI 改动本仓库前的必读契约

> 给 AI(以及人类)的硬约束。**改任何代码前先读完本文。**
> 违反下列任何一条,改动视为无效,必须回滚。
> 配套强制手段:`tests/run-tests.sh`(本地/CI 均会执行,冻结模块被改红即失败)。

---

## 1. 冻结模块清单(⛔ 禁止修改,除非用户在当次对话中明确点名)

以下模块经过真机/宿主端反复验证,是**已收敛的稳定资产**。
AI 不得"顺手优化"、"重构"、"重命名"、"整理格式"。它们的正确性靠
`tests/run-tests.sh` 中的回归测试钉死——**测试红了 = 你改坏了,立即回滚**。

| 冻结模块 | 职责 | 钉死的回归测试 |
|---|---|---|
| `sigcheck/src/sig_check.c` | 签名校验 native 实现(maps 定位截断、Signing Block 解析、SHA-256) | `tests/test_sig_check.sh`(宿主端编译+实包验证) |
| `scripts/inject/inject-loadlib.py` | loadLibrary 插桩(幂等、多 dex、AXMLPrinter) | `tests/test_inject_loadlib.py`(冒烟) |
| `scripts/sig-hash/extract-cert-fp.py` | 证书指纹提取(纯 stdlib 解析 Signing Block) | `tests/test_cert_fp.py`(伪造 APK 双场景) |
| `scripts/repack/mark-native.py` | native 壳替换 + 插桩 | 冒烟: `tests/run-tests.sh` 内嵌 |
| `sigcheck/dex2c/dcc/` | 第三方 dcc 工具(含内置 androguard) | 严禁任何改动(历史: 报错三/九) |
| `sigcheck/tools/apktool.jar` | 解包/重打包工具 | 严禁替换版本(历史: 报错四/五) |

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
   - 改动后 `tests/run-tests.sh` 全绿;
   - 在 `docs/流程文档.md` §9 变更历史追加一行(报错 N)记录根因。
4. **扩展冻结模块**(加日志、加防御): 只允许**追加**,不允许改写已有逻辑行。

## 3. 改动后的必做动作(任何改动,不论大小)

```bash
bash tests/run-tests.sh          # 全绿才算完成
git diff                          # 自查: 只含预期改动
```

CI(`.github/workflows/module-guard.yml`)会对所有 PR/push 强制执行,
冻结模块改动 + 测试红 = CI 直接失败,merge 不了。

## 4. 模块化契约(新增模块时遵守)

- 模块 = 独立脚本 + 明确 CLI 契约 `<输入> <输出> [参数]`,不 import 仓库内
  其他模块的内部函数(公共能力放 `scripts/lib/`)。
- so 名统一 `nc`;`ndk_write_mk` 是唯一 mk 模板来源(报错十一)。
- 每个新模块必须带最小回归测试,挂进 `tests/run-tests.sh`。
- 文档 `docs/流程文档.md` 与代码同步更新,§9 追加变更历史。
