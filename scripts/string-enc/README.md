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
4. `d()` 的块展开与 `keyByte()` 是同一密钥流的两份代码：**运行期唯一实现是 d() 的
   块展开**（一次 mix64 产 8 字节），keyByte 仅供 A1 第 1 层反射对拍；不让 d() 逐
   字节调 keyByte 是刻意的——未命中 keystream 成本会 ×8。两份实现的一致性由
   A1 第 2 层全链往返 + A3 真闭环（真实分配器产物）双向钉死；offset 样本覆盖
   %8 全部 8 个 residue，gen_plan 内置断言防样本集退化（2026-10-13 复核加固）。

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

## 运行期流程（加壳产物在设备上到底发生什么）

先回答最容易疑惑的问题：**解密严格按需（lazy），没有"启动集中解密"；缓存有且
只有一个 —— 进程内 L1，冷启动时永远是空的。** 本模块运行期唯一参与的就是
`StrDec` 这一个类（无回调注册、无 ContentProvider、无后台线程，不与壳层交互）。

### 冷启动时间线

```
进程创建 → dex 就绪（壳场景由壳层解密加载，与本模块无关）
   │  此刻：没有任何字符串被解密，L1 为空，StrDec 尚未初始化
   ▼
业务代码执行到被加密的调用点（三指令形态，process_file 产出）:
   const-string vX, "<payload>"     ← payload 是字符串池普通常量，零成本
   invoke-static/range {vX..vX}, Lcom/nc/strdec/StrDec;->d(...)
   move-result-object vX
   ├─ 全进程首次 invoke → 触发 StrDec <clinit>：只 new 一个空 ConcurrentHashMap
   ├─ d() 查 L1：未命中 → Base64 解码 + splitmix64 XOR + new String(UTF-8) → 写缓存
   └─ 同一调用点再执行（上限内）→ 缓存命中，~50-100ns 零分配返回同一实例
   ▼
static final String 字段：在所属类 <clinit> 里回填（inject_clinit_backfills 产出）:
   const-string v0, "<payload>" → d() → intern() → sput-object
   （类首次被主动使用才跑；这是字段值的唯一来源）
```

### 种子在运行期实际在哪

**d() 从不读 `.field SEED`** —— d8 把种子内联进了方法体指令流（smali 里
`const-wide/high16 v12, 0x5eed…L`），运行期用的是内联常量。`.field SEED` 初值
只在构建期有意义：它是双锚点注入的结构锚点 + 续跑时 `read_stub_seed` 的读取源。
这正是"双锚点必须同时改写"的原因：漏改内联锚点 = 运行期密钥流全错；漏改字段
锚点 = 续跑读到旧种子、旧密文解不开。

### 谁在什么时机调用 d()

| 落点 | 触发时机 | intern |
|---|---|---|
| 方法体调用点（每条 const-string → 三指令） | 该指令首次执行；此后同站点走 L1 | 否 |
| static final String 字段 | 所属类 <clinit>（类首次主动使用） | 是（回填链显式 intern） |

### d() 单次调用内部（StrDec.java）

```
CACHE.get(payload) 命中 → 直接返回（稳态，~50-100ns，零分配）
未命中 → Base64.decode(payload, NO_WRAP)
       → len<4 ？→ 原样返回（兜底，不缓存）
       → offset_be24 → 块展开 XOR（一个 mix64 产 8 字节，内层 j 从 (offset+k)&7 起）
       → new String(out, "UTF-8")
       → size<30000 ？→ CACHE.put（racy 检查，极端并发略超无害）
任何异常(Throwable) → 原样返回 payload，不缓存（防毒缓存）
```

### 缓存事实清单（有 / 没有）

**有的（仅 L1 一个）**：

| 性质 | 事实 |
|---|---|
| 结构 | `StrDec` 内的 raw ConcurrentHashMap，key=密文 payload，value=明文 String |
| 生命周期 | 随进程（严格说随加载 StrDec 的 ClassLoader）；**不落盘、不持久化，进程死即空** |
| 填充 | 懒填充：哪条密文先被用到才进缓存；无预热、无后台线程 |
| 上限 | 30000 条；超限后**不再写缓存**，该条退化为每次现算（正确性不变，只是变慢） |
| 失败 | 失败/退化结果原样返回且不进缓存 |
| 线程 | CHM 线程安全；两线程同时未命中同一条 → 各算一遍、一个写入胜出（无锁良性竞争） |

**没有的（别找了）**：

- ❌ L2/L3 缓存 —— 只存在于已归档的设计稿，从未实现（L2 判定"缓行"）
- ❌ 磁盘/持久化缓存 —— 明文从不落盘
- ❌ 启动期集中解密/预热 —— 没有任何代码在启动时扫密文
- ❌ 跨进程共享 —— 每个进程各自从空缓存开始
- ❌ KEYS 密钥表 —— S2 桩零表，唯一密钥材料是编进指令流的 8 字节 SEED
- ❌ 运行期种子回填 —— 种子构建期写死（SEED 注入契约明令禁止运行期回填）

### 语义细节（容易疑惑的点）

1. **冷启动永远付"首次成本"**：缓存不跨进程，每次冷启动，启动路径触碰到的每条
   字符串都要现算一次（Base64 解码 + O(len) XOR + 2 次分配）。2026-10-12 真机
   实测全部字符串首解总成本 ≈10-20ms（简盒报告 §六）—— 这就是"有缓存但冷启动
   收益≈0"的原因：缓存优化的是**稳态重复执行**，不是冷启动首帧。
2. **跨站点 `==` 语义**：分配器不按明文去重，同一明文在两个调用点 = 两个不同
   payload = 两个不同 String 实例，`==` 为 false（原生 const-string 同池同实例）。
   同站点重复执行在缓存上限内恒返回同一实例。**字段链显式 intern()**，字段引用
   语义与原生一致；方法体链无 intern（已知边界：业务若在字面量上依赖 `==` 需知悉）。
3. **失败静默语义**：解密失败一律返回密文本身（不抛异常/不崩溃/无日志）——
   这就是空串禁止加密的原因：3 字节 payload 会被兜底原样返回，把 Base64 串
   当"明文"用，语义错误。
4. **构建期"缓存"与运行期无关**：`stub-src/StrDec.smali` 是桩骨架的构建期产物
   缓存（改 StrDec.java 后重跑 build-stub.sh 刷新），别与运行期 L1 混淆。

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

## 桩随机化（2026-10-13,防引擎固定签名）

字符串加密防住了「字符串内容特征」,但桩自身曾是新特征:固定类名
`com.nc.strdec.StrDec` + 固定方法名 `d` 全包统一 —— 杀毒引擎可直接收录
`Lcom/nc/strdec/StrDec;->d` 精确签名,一查一个准。**桩随机化**消灭它:

- 生产默认(不传参数):每包随机生成包名(3 段)/类名/方法名,R8 混淆风短名
  (如 `La7x/k2m/Q9;->b3`),伪装成混淆产物的一部分;组合空间 >10^5,防精确签名
- `--stub-name '包名.类名[:方法名]'`:固定名,仅供测试/复现(三个既有测试传
  `com.nc.strdec.StrDec:d` 复现 legacy,断言零改动)
- 续跑复用:随机名写入组件标记(stringenc-components.json 的 desc/src),
  二次跑从标记+桩文件读回 —— 与种子复用同机制;标记在但恢复失败 = fail-fast
  (悄悄换名 = 旧调用点全部指向不存在的类)
- 替换范围:仅 .class 描述符(含桩内自引用全量 6 处)与解密主方法名;
  字段名(SEED/CACHE)与私有方法名(mix64/keyByte)是双锚点/P3 对拍契约,不动
- 派生物同源重建(报错四十八):STUB_DOT 与密文/回填引用/非法形态三个正则由
  `_rebuild_desc_derived()` 随主变量一起重建——漏重建的后果:续跑水位线失明
  (offset 复用=静默乱码)、`**` 规则下桩被当业务类二次加密、两条既有防线失明
- 语义不变:算法、种子注入、缓存、落点形态全部与 legacy 相同 —— 随机的是名字,
  不是行为。验收:`tests/test-stub-randomize.sh`(随机生效/零痕迹/续跑复用/
  改名拒绝/派生物同步/续跑水位线 六断言组)
## 历史教训索引



| 事件 | 教训 |
|---|---|
| v1 冷启动首帧卡死（2026-09-11） | 每条解密 = Base64 + N 次 MessageDigest + intern + 查表，1.3 万条在 debuggable 解释执行下炸首帧——**慢的首次成本，缓存救不了**；S1/S2 先把密钥生产降到纳秒级，缓存才重新安全 |
| 报错二十一 | 手写 smali 的寄存器宽度陷阱：const-string 21c 格式 8 位寄存器 |
| 报错二十二 | 桩自检：参数寄存器不得被当临时槽覆盖（运行期传脏参数 → 闪退且无 FATAL 日志） |
| 报错二十四 | 字段常量回填引用的非法形态（初值指向 StrDec 字段）；构建期防线：产物 .field 初值禁止桩字段引用 |
| 报错二十五 | 桩骨架三防线（占位符残留/类体顶层裸指令/so 名合法性）——泛型字段也会撞它（Signature 注解） |
| 报错四十八 | 桩随机化只改 4 个主变量，import 期派生物（STUB_DOT 与 3 个引用正则）不随重建 → 随机名下续跑水位线失明（offset 复用=静默乱码）、`**` 规则下桩被二次加密、报错二十二/二十四防线失明；**凡派生自主变量的东西，改名时必须同源重建并有断言锁住** |

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
| `tests/test-keystream-crosscheck.sh` | Python ↔ Java 对拍：第 1 层反射 keyByte/mix64 纯算术；**第 2 层真实编译桩 d() 全链往返**（4 种子 × 117 例，offset 覆盖 %8 全部 8 个 residue） |
| `tests/test-structure-resume.sh` | 续跑（offset 分配器）/ 桩结构不变量（含 L1 缓存断言） |
| `tests/test-stub-randomize.sh` | 桩随机化：随机生效/产物零 legacy 痕迹/续跑复用随机名/改名 fail-fast/派生物同步/** 规则两轮水位线（6 断言组） |
