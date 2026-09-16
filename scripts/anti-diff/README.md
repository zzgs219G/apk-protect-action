# anti-diff — 防对比混淆模块(MVP)

> 给下一任 AI / 开发者:本模块的"为什么、做什么、红线"全部以
> [`docs/开发文档.md`](../../docs/开发文档.md) 为最终裁判,本文只是工程索引。

## 是什么

在现有加固流水线(sigcheck/dex2c/stringenc)基础上,新增的一层 **dex 层结构噪声**。
攻击者同时拿到原版 APK 与处理过的 APK,反编译后做逐文件 diff 时,
被抽/被改的类"稀疏、可定位";本模块让全量 smali 带上零语义无损的变换,
使 diff 结果"整包全红、像不同编译版本",掩盖真正被保护的那一个类。

## MVP 三变换(level 1)

| 变换 | 内容 | 跳过规则 |
|---|---|---|
| A 标签重命名 | 方法内 `:cond_0`/`:goto_0` 等 → `:ncXXXXXX` | `<init>`/`<clinit>` |
| B 类内块重排 | `.method`/`.field` 块确定性乱序 | `<init>`/`<clinit>` 与含 `.annotation` 的块钉在原地 |
| C 入口垃圾指令 | 方法首插 1~3 条 `const/4`/`move` | `<init>`/`<clinit>`、native、含 try-catch、`.registers < 5`、首指令非赋值类 |

红线(开发文档 §2.2):不改名 / 不改签名 / 不改字符串 / 不注死代码 / 不填 nop /
不做控制流平坦化。

## CLI

```
anti-diff.py <解包目录> [--seed-hex HEX] [--level 1] [--max-per-method N]
```

- 不给 `--seed-hex` 时,种子 = SHA-256(全部 smali 相对路径+内容),天然幂等;
- 每个处理过的类写入 `# nc-antidiff-applied v1` 标记注释,重跑整类跳过。

## 幂等

同一份解包目录跑两次,产物逐字节一致(测试 `tests/test-smoke.sh` 断言 6)。

## 在流水线里的位置

```
mark-native.py → encrypt-strings.py → 【anti-diff.py】→ repack_build
```

放最后的原因:stringenc 会改 `const-string` 并插桩,若 anti-diff 先做、
stringenc 后做,stringenc 的新差异会落在 anti-diff 的"已处理"区域上,
削弱防对比效果。见 `scripts/pipelines/protect.sh` 中 `--anti-diff` 分支。

## 测试

```
bash scripts/anti-diff/tests/test-smoke.sh
```

合成 smali,断言:三类变换生效、语义行零变化、`<init>`/native/try-catch 被跳过、
重跑幂等。真实包(apktool 回编/真机冷启动)验证按开发文档 §5.4 在真机环境执行,
不在本冒烟测试范围。
