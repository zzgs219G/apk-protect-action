# anti-diff — 防对比混淆模块(MVP)

> 给下一任 AI / 开发者:本模块的"为什么、做什么、红线"全部以
> [`docs/archive/开发文档-anti-diff.md`](../../docs/archive/开发文档-anti-diff.md) 为最终裁判,本文只是工程索引。

## 是什么

在现有加固流水线(sigcheck/dex2c/stringenc)基础上,新增的一层 **dex 层结构噪声**。
攻击者同时拿到原版 APK 与处理过的 APK,反编译后做逐文件 diff 时,
被抽/被改的类"稀疏、可定位";本模块让全量 smali 带上零语义无损的变换,
使 diff 结果"整包全红、像不同编译版本",掩盖真正被保护的那一个类。

## 现存变换(2026-10-20 起:E/C 已删除,零字节改写版)

| 变换 | 内容 | 跳过规则 |
|---|---|---|
| A 标签重命名 | 方法内 `:cond_0`/`:goto_0` 等 → `:ncXXXXXX` | `<init>`/`<clinit>` |
| B 类内块重排 | `.method`/`.field` 块确定性乱序 | `<init>`/`<clinit>` 与含 `.annotation` 的块钉在原地 |
| D 局部寄存器重编号(**主力**) | 局部区 `v0..vN` 确定性随机置换,dex 层每条指令的寄存器号真实变化 | `<init>`/`<clinit>`、native;参数 `pN` 区、`/range` 成员、wide 对(报错三十三/三十八) |
| F 恒等算术重编码 | `shl-int/lit8 vA, vB, k` ⇄ `mul-int/lit8 vA, vB, 2^k`(22b 等长 4 字节,32 位补码下数学恒等,乘 2 的幂的 mul 形态 R8 强度削减从不产出) | `<init>`/`<clinit>`;移位量 k=0 与 k>6 不转(2^k 超出 8 位字面量域);`lit16`/`2addr` 等相邻形态不碰(编码格式不同,互转不再等长) |
| C0 `.locals` 提升 | `.locals N<4` 提升到 4(为 D 扩大覆盖面;R8 产物常见 0/1) | 同 D |

> **2026-10-20 重构:体积增量归零。** 实测(样本
> `简盒_signed_09_09_37_sign.apk`,方法 = 解包 → 施加变换 → `apktool b` 回编 →
> `apktool d` 再反编译 → 归一化对比,与 `tools/normdiff.py` 同规则):
>
> | 变换 | 改动处数 | 往返后归一化差异 | dex 增量 |
> |---|---|---|---|
> | A 标签重命名 | 137,632 | **0 行** | 0 |
> | D 寄存器重编号 | 20,426 | **516,726 行 / 11,516 方法** | **0** |
> | F shl⇄mul | 528 | 1,056 行 / 357 方法 | **0** |
> | add⇄sub 等长替换 | 5,767 | **0 行**(汇编到同一字节) | 0 |
> | E+C+ | ~13,238 | 有效 | **+20.8 KB** |
> | 原全开(A+B+C+E+F) | — | — | **+70.8 KB**(其中 ~50KB 是 C0 提升后 C+/D 覆盖率暴涨的交互效应) |
>
> **结论:防对比强度不该用体积换。D 是唯一主力,E/C 删除。**
> `add⇄sub` 这类"看起来等长"的替换不能照抄 F——它俩汇编到同一个
> dex 字节,归一化与二进制层面都看不出来;F 能活是因为 R8/D8 从不产出
> "乘 2 的幂"的 mul 形态,这个窗口极窄,新增等长变换前必须先跑往返验证。

> 报错二十二教训(真实包 MT 对比实测,见 docs/对比测试apk/实际效果.md):
> 变换 A(标签)与 B(块重排)在 dex 层**完全无效**——标签只是 baksmali 的
> 临时命名、dex method_ids 不记源码顺序,回编→再反编译后 100% 复原。
> 判断"是否有效"必须以"回编→再反编译→MT 对比"往返为准,smali 文本
> diff 全红不算数。

白名单:android./androidx./kotlin./okhttp3./org.jsoup. 等系统与第三方依赖
类硬排除(与 stringenc `SYSTEM_CLASS_PREFIXES` 同型名单,见
`anti-diff.py` 的 `SKIP_CLASS_PREFIXES`)。

红线(开发文档 §2.2):不改名 / 不改签名 / 不改字符串 / 不注死代码 / 不填 nop /
不做控制流平坦化。

## CLI

```
anti-diff.py <解包目录> [--seed-hex HEX] [--level 1] [--enable-f]
```

- 不给 `--seed-hex` 时,种子 = SHA-256(全部 smali 相对路径+内容),天然幂等;
- 每个处理过的类写入 `# nc-antidiff-applied v1` 标记注释,重跑整类跳过。
- `--max-per-method` / `--max-cond-flip` 已于 2026-10-20 移除(原先只服务
  C+/E,两变换已删除)。

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

合成 smali,断言:变换生效、语义行零变化、`<init>`/native 被跳过、
重跑幂等。真实包(apktool 回编/真机冷启动)验证按开发文档 §5.4 在真机环境执行,
不在本冒烟测试范围。




作者添加

切记！MT的对比会支持以下功能:

忽略编译优化
忽略寄存器数量
忽略调试信息
忽略nop指令

所有要排除这四个因素进行对比