# apk-protect-action

GitHub Action 形态的 APK 加固流水线：签名校验、环境检测、dex2c 转译、字符串加密、防对比混淆、so 段加密，按固定顺序编排，产物为加固后的未签名 APK。

## 使用

在 workflow 里以 `workflow_dispatch` 调用本仓库的 [protect-modules.yml](.github/workflows/protect-modules.yml)，传两个输入：

- `apk_url`：待加固 APK 的下载地址
- `protect_config`：模块勾选 JSON（schema 见 [configs/v1/config-schema.json](configs/v1/config-schema.json)）

示例：

```json
{"schema_version":1,"sigcheck":true,"dex2c":{"enabled":true,"rules_file":""},
 "stringenc":{"enabled":true,"rules_file":"**","dex2c_stub":true},
 "antidiff":true,"envcheck":true,"packer":{"enabled":false}}
```

## 文档入口

| 文档 | 内容 |
|---|---|
| [docs/项目导览.md](docs/项目导览.md) | 新人入口：目录结构、模块职责、数据流 |
| [docs/流程文档.md](docs/流程文档.md) | 现行机制细节（改代码前必读对应章节） |
| [docs/变更历史.md](docs/变更历史.md) | 报错档案 + 教训（排障先查这里） |
| [docs/报错速查.md](docs/报错速查.md) | 现象 → 根因 → 修法速查表 |
| [AGENTS.md](AGENTS.md) | AI/开发者改动前的硬约束（冻结模块清单等） |

## 模块一览

```
scripts/
├── pipelines/   protect.sh 总编排（唯一入口，固定顺序）
├── sigcheck/    签名校验 + 环境检测 + so 段加密（最大模块，内部再分层）
├── string-enc/  dex 字符串加密
├── anti-diff/   dex 结构噪声（防原版/加固版对比）
├── repack/      解包/回编/so 替换/dex 版本修补
├── packer/      基础加壳（dpt-shell）
├── inject/      loadLibrary 双保险注入
├── filter/      规则格式转换
├── lib/         公共库（日志/repack/ndk 编译/锁箱器/段标记器）
├── actions/     protect_config 解析与 schema 校验
└── ai-tools/    AI 排障辅助（dex-diff / dex-info / dex-verify）
```

## 开发约定

- 每个模块自带 `tests/`，改完跑对应回归；全部测试清单见各模块目录
- 冻结模块（见 AGENTS.md）未经用户点名不得修改
- 构建期工具（apktool.jar）在 `tools/` 根下，git 跟踪；转译引擎经 zip 分发幂等解压
