字符串加密模块审查报告

整体设计是清晰的：规则复用 dcc 侧同一实现、硬排除带点号、intern() 保语义、幂等标记、组件标记（报错十八式 save/restore）——思路都对。但我通读代码后发现 1 个必修严重 bug 和几个边界问题，下面按严重程度列。

---

🔴 必修：字段常量场景 <clinit> 顺序错误 → NPE

STUB_TEMPLATE 里 <clinit> 的结构是：

```smali
.method static constructor <clinit>()V
.registers 2
%CLINIT_FILL%          ← 先解密字段（会调 d()）
new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;   ← 后初始化 CACHE
...
sput-object v0, Lcom/nc/strdec/StrDec;->CACHE:...
```

而 %CLINIT_FILL% 生成的是：

```smali
sget-object v0, ...->C_F000000:...
invoke-static {v0}, ...->d(...)      ← d() 里第一件事就是 sget-object CACHE
```

d() 的入口：

```smali
.method public static d(Ljava/lang/String;)Ljava/lang/String;
.registers 6
sget-object v0, Lcom/nc/strdec/StrDec;->CACHE:...   ← 此刻 CACHE 还是 null
invoke-virtual {v0, p0}, ...->get(...)               ← NPE（不在 try 块内）
```

结果：只要任意一个类含 static final String = "..."（R8 会折叠成 .field ... = "..."，这是极常见形态），该类 <clinit> 执行 → d() → NPE → ExceptionInInitializerError → 闪退。

为什么没被发现：文档里"字段与指令两类密文全对"看起来是静态验证（androguard 读回字节码正确），不是运行时验证。NPE 只有真机/真 JVM 跑才暴露。

修法：把 CACHE 初始化挪到 %CLINIT_FILL% 之前：

```smali
.method static constructor <clinit>()V
.registers 2
new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;
invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V
sput-object v0, Lcom/nc/strdec/StrDec;->CACHE:Ljava/util/concurrent/ConcurrentHashMap;
%CLINIT_FILL%
return-void
.end method
```

（%CLINIT_FILL% 里也用 v0 会覆盖，但 CACHE 已经 sput 了，无影响。）

---

🟠 建议修：三个边界一致性问题

1. clean 只删桩，不恢复已加密的类

clean_components 只删 stringenc-components.json 里登记的桩文件。但加密过的类里 # nc-strdec-encrypted 标记 + 密文 + invoke-static ...->d(...) 引用都还在。同一解包目录第二次跑时：

· clean → 删桩
· 加密循环 → 已加密类被 CLASS_MARK 跳过
· 结果：类还引用 Lcom/nc/strdec/StrDec;，桩没了 → smali 汇编失败 / 运行时 NoClassDefFoundError

正常流水线每次 mktemp -d 全新解包不触发，但本地反复调试会踩。建议 clean 里同时按 CLASS_MARK 恢复加密的类（或至少 fail-fast 拒绝在"半加密目录"上继续）。

2. 已有桩但本次产生新字段时不重写桩

```python
if need_write_stub and total_str > 0:
    stub_path = write_stub(args.decompiled, salt, all_stub_fields)
```

read_existing_salt 找到已有桩时 need_write_stub=False，于是新产生的 all_stub_fields 被丢弃：

· 桩里没有 F000005 的声明和 <clinit> 赋值
· 类里却写了 = StrDec;->F000005:... → 汇编时 NoSuchFieldError / 运行时空指针

正常流程有 clean 保底，但一旦 clean 没跑（比如用户跳步），就踩。建议：need_write_stub=False 时也要合并旧字段 + 新字段重写桩，或者检测到"有新字段但桩已存在"直接 fail-fast。

3. 幂等完全依赖类标记，标记丢失会二次加密

process_file 的续跑判定是：

```python
if STUB_DESC + '->d(' in line:
```

但加密后的形态是三行：

```
const-string v0, "密文"                              ← 不含 ->d(，不会命中跳过分支
invoke-static {v0}, ...->d(Ljava/lang/String;)...   ← 只有这行含 ->d(
move-result-object v0
```

循环是逐行的。遇到 const-string "密文" 那一行时 STUB_DESC + '->d(' in line 为 False → 走 parse_const_string → 把密文当明文再加密一次。

实际没暴露是因为 CLASS_MARK in content 整类跳过。但一旦标记被手工删了 / 被别的工具动过，就会把密文二次加密（结果是垃圾，且没报错）。

建议：在 parse_const_string 成功、准备加密前，向上/向下多看一行，若下一行是 invoke-static ...->d( 就跳过（更稳的续跑判定）。

---

🟡 边界 / 建议

4. max_existing_idx 只扫指令加密，不扫字段加密

```python
_PAYLOAD_RE = re.compile(r'const-string...\n...invoke-static...->d\(')
```

字段加密的形态是 .field ... = StrDec;->F000005:...，不匹配该正则。所以续跑时字段的 idx 不会被计入，可能和新加密的 idx 冲突 → 相同 salt + 相同 idx + 相同长度 → keystream 复用（密码学弱点）。

正常流程不触发（clean + 一次跑），标为已知边界即可。

5. 字段常量方案的运行时可行性需要真机验证

.field ... = Lcom/nc/strdec/StrDec;->F000000:Ljava/lang/String; 编译后是 dex 的 VALUE_FIELD 作为 static_value。smali 汇编器支持这种写法，但ART 在类加载时如何处理 static final String 的 VALUE_FIELD 初始值（是解析并取值，还是直接报错/置 null），需要真机验证。文档说测试过"字段与指令两类密文全对"，但看描述更像静态字节码校验而非真机跑。强烈建议做一次真机冒烟：

```
造一个类：
  static final String URL = "https://xxx";
  public static void main() { Log.d("T", URL); }
→ 加密 → 打包 → 真机看 URL 是否正常输出（而不是 null / 崩）
```

6. field_to_java_code 是死函数

```python
def field_to_java_code(field_type: str, literal: str) -> str:
    return '"' + literal + '"'
```

定义后从未被调用。删掉，避免误读。

7. 注释与实现有细微出入

classify 里 system 判定在 excluded 之前，注释却写"用户 ! 排除行优先级最高"。两者结果都是"不加密"，只是日志统计分类不同（记 system 还是 excluded），实际无害。可以修注释，也可以把顺序调成注释描述的样子。

---

✅ 做得好的地方

· 规则复用：_RULES.class_rule_to_filter / has_wildcard / expand_activity_keyword 全部从 rules-to-filter.py 复用，没有另写一套——这是全文档反复强调的"单一真相"。
· 硬排除带点号：is_system_class 用 startswith(('android.', ...))，正确避开了 androidXcustom 这类同前缀误伤。
· 指令改写用原寄存器：const-string vX, "..." → invoke-static {vX}, d(...) → move-result-object vX，全用 vX，不需要 .registers +1，从根上规避了报错十一/十三那一类寄存器错位。
· intern() + 缓存：保 == / switch 语义，和解密失败返回原串（不抛）——都是对的。
· 组件标记：stringenc-components.json 记录"描述符 + 源文件路径"，正是报错十八"信息在丢失前 save"的思路。
· clean 的路径安全检查：target.startswith(root_abs + os.sep) 防标记被篡改后越界删文件。
· 密钥流对拍：文档里 §7 第 6 步的 Python vs Java 对拍覆盖了 0/31/32/33 块边界，这是跨语言派生协议唯一可靠的验证方式。

---

优先级建议

优先级 问题 触发场景
P0 <clinit> CACHE 顺序 NPE 字段常量加密（极常见）
P1 clean 不恢复已加密类 本地反复调试
P1 已有桩 + 新字段丢桩 跳步或跨轮
P2 幂等依赖类标记 标记被手工删
P2 max_existing_idx 不扫字段 续跑
P3 字段方案真机验证 上线前必做
P3 死函数 / 注释 清理

P0 修完再做一次真机冒烟（含字段常量场景），这个模块才算闭环。其余 P1/P2 在正常流水线（每次全新解包 + 一次加密）下不会触发，可以作为已知边界先记录在 docs/流程文档.md §8，后续再补。