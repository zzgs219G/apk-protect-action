看了，现在明白你问的“为什么没有日志”了。答案在 C 代码的执行时机上。

关键链路

sig_check.c 的入口是：

```c
__attribute__((constructor)) static void sig_check_entry(void) {
    sig_verify();
}
```

constructor 只在 so 被 dlopen 时执行。so 什么时候被 dlopen？由 dex 里 System.loadLibrary("nc") 触发。

而 loadLibrary("nc") 这行，正是 inject-loadlib.py 插进去的：

```smali
const-string v0, "nc"
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

字符串加密干了什么

你勾了 stringenc，规则 **。这行 const-string v0, "nc" 属于“用户类里的字符串常量”，会被加密成：

```smali
const-string v0, "<Base64密文>"
invoke-static/range {v0 .. v0}, Lcom/nc/strdec/StrDec;->d(Ljava/lang/String;)Ljava/lang/String;
move-result-object v0
invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V
```

运行时顺序变成：

1. <clinit> 执行
2. 调 StrDec.d("密文") 解密
3. 解密过程中 StrDec 类初始化、xor() 执行
4. xor() 崩了（上一轮说的 p0/p1 被 v14/v15 覆盖）
5. loadLibrary 根本没执行到
6. so 从未被 dlopen
7. sig_check_entry 这个 constructor 从未运行

所以“没有日志”是必然的

· sig_check.c 所有的 LOGI/LOGE/LSGI/LSGE 都在 sig_verify() 里，而 sig_verify() 在 constructor 里。
· constructor 没跑 → 一行都不会打。
· 就算你建了 /storage/emulated/0/sigcheck_debug 哨兵也没用，因为 siglog_detect() 也在 sig_verify() 里。
· logcat 里也不会出现 nc: 前缀的任何行，因为整个 so 没加载。

你看到的“闪退无日志”，是 dex 层解密崩在 <clinit> 里（ExceptionInInitializerError），和签名校验模块完全无关。签名校验是被字符串加密“掐断”了触发链。

顺带解释 env_check.c 为什么也没日志

同理，env_check.c 也是 __attribute__((constructor))，也在同一个 libnc.so 里。so 没 dlopen，它也不会跑。

修法

只改 encrypt-strings.py 里 STUB_TEMPLATE 的 xor，内层循环临时寄存器从 v14/v15 换成 v7/v8（这两个寄存器在内层循环里本来就是空的），.registers 16 不动：

```smali
:loop_inner
if-ge v11, v12, :next_block
if-ge v5, v1, :next_block
add-int/lit8 v13, v5, 0x3
aget-byte v7, p0, v13      # 原 v14（= p0，覆盖参数）
aget-byte v8, v10, v11     # 原 v15（= p1，覆盖参数）
xor-int v7, v7, v8
int-to-byte v7, v7
aput-byte v7, v2, v5
add-int/lit8 v5, v5, 0x1
add-int/lit8 v11, v11, 0x1
goto :loop_inner
```

改完重跑 workflow，loadLibrary("nc") 能正常解密出 "nc"，so 被 dlopen，sig_check_entry 才会跑，你才会看到 nc: 开头的日志。

验证顺序建议

1. 先只勾 stringenc（不勾 sigcheck），装包看是否闪退 —— 应该还是闪退，证明是解密桩本身的问题。
2. 改 xor 寄存器后，只勾 stringenc 再跑 —— 不闪退。
3. 再勾 sigcheck + stringenc —— 这时 logcat 里应该出现 【流程】so 已加载,进入签名校验 sig_verify，日志才回来。

一句话总结

字符串加密把 loadLibrary("nc") 的字符串也加密了，运行时解密桩 xor() 寄存器覆盖崩在 <clinit>，so 从未 dlopen，所以 sig_check.c / env_check.c 的 constructor 从未执行，自然一行日志都没有。C 代码没问题，问题在 dex 层的解密桩。

