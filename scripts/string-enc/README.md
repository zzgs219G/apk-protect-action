# string-enc — dex 层字符串常量加密模块

构建期把「用户选中类」的 `const-string` 字面量加密，运行期由注入的纯 Java 解密桩
`Lcom/nc/strdec/StrDec;` 解密。目标：`strings`/静态特征扫描看不到明文（URL/API
key/日志文案）。**定位是防静态可见性，不是密码学安全**——密钥流派生材料同在包内，
懂格式者仍可解；真正的密钥材料请走服务端/白盒方案。

> 2026-10-12 验收注记：真机实测本模块成本 ≈10-20ms（非冷启动主因），体积代价
> ≈0.95MB dex（Base64 +33% 膨胀）。曾短暂讨论下线，最终保留（防静态可见性仍有
> 价值，且 L1 缓存已消除性能顾虑）。数据见 `docs/简盒-加壳对比测试报告.md` §六。

## 文件与数据流

```
StrDec.java ──build-stub.sh──► stub-src/StrDec.smali（桩骨架,哨兵种子）
                                     │
encrypt-strings.py ◄─────────────────┘
   │  ①解析桩骨架(双锚点注入 SEED)  ②按规则扫 const-string  ③加密+改写+注入桩
   ▼
<解包目录>/smali/**(密文 const-string + StrDec 桩) ──apktool b──► 加壳包
```

| 文件 | 职责 |
|---|---|
| `stub-src/StrDec.java` | **唯一源码真相**。算法只改这里，然后重跑 `build-stub.sh` |
| `build-stub.sh` | 编译链 javac → d8 → baksmali → 桩骨架 smali（含三道自检） |
| `stub-src/StrDec.smali` | **自动生成的中间产物，人永远不要手改**（报错二十一/二十二/二十五） |
| `encrypt-strings.py` | 构建期主脚本：找字符串 → 加密 → 改写 → 注入桩（最大单体） |
| `tools/d8.jar` | 固定版本 D8（r8 9.3.16，与 apktool.jar 同待遇，勿换版） |
| `tests/` | 冒烟 / 密钥流对拍 / 结构与续跑 三套件 + P3/P5 宿主工具 |

## 选类语法与硬排除

规则语法完全复用 dcc 那套解析（scripts/filter/rules-to-filter.py）：
`com.app.MainActivity`（精确）/ `com.test.**` / `com.test.*` / `com.test*` /
`activity*`（需 --classes，从 Manifest 动态提取）/ `!排除` / `# 注释` / 空行。

**硬排除（用户要求：全量通配也不许动）**——即使规则写了 `**`，下列前缀的类一律
不加密（系统类与框架依赖）：`android. androidx. android.support. com.android.
com.google.android. dalvik. java. javax. kotlin. kotlinx. org.jetbrains.
org.apache. org.json. org.w3c. org.xml. sun.` 外加解密桩自身。`!` 排除行在非系统类
范围内优先级最高；命中系统前缀的类无条件硬排除。

常用第三方依赖（反射/注解序列化/网络协议/跨进程绑定库）同列硬排除——此类库的
const-string 承载类名/字段名/协议/序列化标记（反射与注解处理必需），加密后
`Class.forName`/`getAnnotation`/序列化匹配、甚至网络协议会失效；加固只保护自家
代码，第三方字符串本非重要资产。

## 密文形态

`b64 = Base64( offset_be24 || cipher_bytes )`（NO_WRAP）

- `offset` — 该条明文 UTF-8 字节在「全包虚拟密钥流」里的起始下标（3 字节大端）
- `cipher[k] = plain_utf8[k] ^ keyByte(SEED, offset + k)`
- 分配器保证全包各条密文的 `[offset, offset+len)` 区段互不重叠

## 密钥流定义（Python/Java 必须逐字节一致，由 P3 对拍锁定）

```
splitmix64:  z ^= z >>> 30; z *= 0xBF58476D1CE4E5B9L;
             z ^= z >>> 27; z *= 0x94D049BB133111EBL; return z ^ (z >>> 31);
keyByte(seed, i) = (mix64(seed + (i >>> 3) * GAMMA) >>> ((i & 7) * 8)) & 0xFF
GAMMA = 0x9E3779B97F4A7C15L
```

易错点（历史事故，改代码前必读）：
1. Java 用 `>>>`（无符号右移），long 溢出天然 = mod 2^64；Python 侧每步 `& MASK64`，
   且 `>>` 只作用在已掩码的非负数上。
2. `d()` 的块展开里，内层 `j` 必须从 `(offset+k)&7` 起，不能固定从 0——offset 未必
   是 8 的倍数，块索引按 `offset+k` 算（§计划书 2.3 原样代码的缺陷，曾致 offset%8≠0
   的每条字符串全部解错）。
3. 解码必须 `byte[]` + `new String(byte[], "UTF-8")`——`char[]` 形态是 Latin-1 语义，
   中文/emoji 多字节 UTF-8 会乱码。

## SEED 注入契约（build-stub.sh ↔ encrypt-strings.py 共同维护，勿单方面改）

build-stub.sh 用**哨兵种子** `0x5EED000000000000L` 编译（源码里 SEED 初值是占位形态
`0L /*%SEED_LITERAL%*/`，编译前在临时副本替换，绝不回写仓库源文件）。d8 实测行为：

- 种子非 0 → 保留 `.field private static final SEED:J = 0x…L`
- 同时把种子**内联**到每个使用点（`const-wide vX, 0x…L`）

所以 encrypt-strings.py 必须做**双锚点一致性注入**：`.field` 初值与所有内联常量
同时改写为真种子，且改写数量守恒（错一个 → 运行期与构建期密钥流不一致，全包乱码）。
build-stub.sh 产出后自检两个锚点存在（缺失 fail-fast）；encrypt-strings.py 侧另有
终检（改写前后锚点数守恒）。

**绝不允许把种子写成运行期回填**：那需要把解密提前到 `<clinit>`，而字段常量回填链
必须在 SEED 就绪之后执行——顺序会被迫打乱（报错二十四同型）。

## L1 解密缓存（2026-10-12）

`d()` 缓存优先：`CACHE`（ConcurrentHashMap，key=密文 payload，value=明文），
命中 ~50-100ns 零分配，并恢复原生 const-string 的 intern 语义。

- **仅成功结果进缓存**；失败/退化结果原样返回不缓存（防毒缓存）
- `CACHE_CAP=30000` 上限守卫（racy 检查，极端并发略超无害）
- **桩内用 raw 类型**：泛型字段会让 javac 产出 `.annotation Signature` 块，撞桩骨架
  "类体顶层裸指令"守卫；缓存读写整体在 try 内（报错二十二守卫禁止向参数寄存器写常量）
- 实测（2026-10-12 真机）：缓存生效但冷启动持平——stringenc 全模块成本 ≈10-20ms，
  非冷启动主因（详见 `docs/字符串架构优化.md` 与简盒报告 §六）；L1 保留的理由是
  无回归 + CPU/PSS 改善 + intern 语义，而非当初的 ~200ms 假设

## 历史教训索引

| 事件 | 教训 |
|---|---|
| v1 冷启动首帧卡死（2026-09-11） | 每条解密 = Base64 + N 次 MessageDigest + intern + 查表，1.3 万条在 debuggable 解释执行下炸首帧——**慢的首次成本，缓存救不了**；S1/S2 先把密钥生产降到纳秒级，缓存才重新安全 |
| 报错二十一 | 手写 smali 的寄存器宽度陷阱：const-string 21c 格式 8 位寄存器 |
| 报错二十二 | 桩自检：参数寄存器不得被当临时槽覆盖（运行期传脏参数 → 闪退且无 FATAL 日志） |
| 报错二十四 | 字段常量回填引用的非法形态（初值指向 StrDec 字段）；构建期防线：产物 .field 初值禁止桩字段引用 |
| 报错二十五 | 桩骨架三防线（占位符残留/类体顶层裸指令/so 名合法性）——泛型字段也会撞它（Signature 注解） |

## 依赖与环境

- `javac`（JDK）、`tools/d8.jar`、`tools/dcc/tools/apktool.jar`（提供 baksmali）
- 编译期 classpath 需要 `android.util.Base64`：默认找
  `$HOME/tmp/toolchain/android-all.jar`，可用 `STUB_ANDROID_JAR` 覆盖；
  本机缺失时用 `tests/shims/android/util/Base64.java` 编一个最小 jar 即可
  （`javac -d <dir> tests/shims/android/util/Base64.java && jar cf a.jar -C <dir> android`）

## 测试

| 套件 | 覆盖 |
|---|---|
| `tests/test-encrypt-smoke.sh` | 全链加密→解密往返 + 桩自检（27 断言） |
| `tests/test-keystream-crosscheck.sh` | Python ↔ Java 密钥流逐字节对拍（288×2） |
| `tests/test-structure-resume.sh` | 续跑（offset 分配器）/ 桩结构不变量（含 L1 缓存断言） |
