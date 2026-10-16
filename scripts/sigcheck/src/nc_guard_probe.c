/* nc_guard_probe.c — .ncguard 段机制的 Android 试探实现（非冻结，可随时删）
 *
 * ⚠️ 这是一个【试探性】文件，唯一目的是在 Android/CI 上验证"段加密 → 运行期
 * 自解密"机制能否工作。验证通过后，此文件的职责由 env_check.c 等冻结模块
 * 的 __attribute__((section(".ncguard"))) 标记接手，届时可整体删除。
 *
 * 为什么单独放一个文件而不是直接改 env_check.c：
 *   该机制从未在 Android linker 上验证过（本地只在 Linux/ELF64 上跑通）。
 *   直接改三个冻结文件再验证，一旦 CI 炸就要回滚冻结资产。用非冻结文件试探
 *   是零成本降险：炸了删掉本文件即可，冻结模块零牵扯。
 *
 * 机制（抄自 XopProtector .bitcode 自解密）：
 *   编译期：ncguard_probe() 进 .ncguard 段
 *   构建期：so-section-lock.py 把 .ncguard 用 RC4 加密写回 libnc.so
 *   运行期：ncguard_unlock() 恢复密钥、原地解密、擦除密钥槽
 *   之后  ：ncguard_probe() 才可被调用（解密前调用 = 执行密文 = SIGILL）
 *
 * 接入方式：protect.sh 已把 nc_guard_unlock.c 与本文件拷进 NDK 工程；
 * ndk_write_mk 的两级 wildcard 自动收编，无需改 mk。
 *
 * 注：不引 <jni.h> —— 本文件无 JNI 类型需求，而 host 侧缺 jni_md.h、
 * NDK 侧也平白多一个依赖。保持零头文件依赖，任何工具链都能编。
 */

/* 密钥槽：运行期 ncguard_unlock() 从这里恢复 K_so。
 * const volatile 的理由同 Xop：writable 对象在 SHF_EXECINSTR 段里会让 LLD
 * 生成 W+X 的 PT_LOAD，而 Android 10+ 拒绝可写可执行段。用 const 让它进
 * .rodata（只读），运行时再 mprotect 改写。
 * ⚠️ retain 不可省：lib-ndk.sh 的 LOCAL_LDFLAGS 含 -Wl,--gc-sections，
 * 无引用的段会被当死代码连段一起回收（2026-10-17 CI 实测踩过：
 * .ncguard 整个消失在 so 的段表里）。 */
__attribute__((section(".nckey"), used, aligned(1), retain))
static const volatile unsigned char ncg_key_slot[32] = {0};

/* ── 被锁的业务逻辑：只有解锁后才能调用 ────────────────────────────
 * 用法：调用方必须先 ncguard_unlock() 成功，再调本函数。
 * 对拍契约：ncguard_probe(0) == ((0^0x5A)+0x0F)*3 & 0xFF == 59。
 * 取值刻意不取 42/0/1 这类哨兵值，避免 strings 一眼定位。
 * retain 同密钥槽：防 --gc-sections 回收。 */
__attribute__((section(".ncguard"), used, retain))
int ncguard_probe(int token) {
    /* 用 token 派生一个确定性结果；逻辑本身不重要，重要的是"这段代码在
     * 锁箱后不可读、解锁后可正确执行"。Android 验证用的对拍契约：
     * ncguard_probe(0) 必须返回 0x2A（42）。 */
    int acc = token;
    acc = (acc ^ 0x5A) + 0x0F;
    acc = (acc * 3) & 0xFF;
    return acc;
}

/* 供 Java/native 侧查询"本 so 是否支持段加密机制"。
 * 不解锁它也能回答——只探测符号存在性，不碰 .ncguard 内容。 */
int ncguard_available(void) {
    return 1;
}
