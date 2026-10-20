/* nc_guard_probe.c — so 段加密设施的密钥槽定义 + 样例消费者
 *
 * ⚠️ 2026-10-18 定位纠正（此处曾有过期且危险的描述）：
 *   本文件头部曾写"这是试探性文件，验证通过后可整体删除"。
 *   【错。】`ncg_key_slot[96]` 就是 .nck 段的全部内容——删掉本文件 =
 *   .nck 段消失 → ncguard_unlock() 返回 -3 → 段保持密文 → 探针踩密文
 *   → SIGILL → App 起不来。它不是试探残留，是设施的承重墙。
 *
 * 本文件在通用设施（见 docs/流程文档.md §3.12）中承担两个角色：
 *   ① 【设施本体】ncg_key_slot —— .nck 段的唯一定义处，锁箱侧往里写
 *      wrapped_k_so / wrapped_k_mac / expect_mac
 *   ② 【样例消费者】ncguard_probe() —— 演示"一个函数如何进 .ncx"，
 *      对拍契约 probe(0)==59
 *
 * 新增消费者（dex2c 转译产物等）不需要改本文件，也不需要手写
 * __attribute__ —— 用通用标记器 scripts/lib/so_section_mark.py 按规则注入。
 *
 * 机制（抄自 XopProtector .bitcode 自解密）：
 *   编译期：ncguard_probe() 进 .ncx 段
 *   构建期：so-section-lock.py 把 .ncx 用 RC4 加密写回 libnc.so
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
 * .ncx 整个消失在 so 的段表里）。
 * ⚠️ 数组长度 96 = 锁箱侧 slot blob 长度（so-section-lock.py：magic16 +
 * wrapped_k_so16 + wrapped_k_mac16 + expect_mac32 + pkg_sha8 + reserved8）。
 * 2026-10-19 P1-a 从 80 扩到 96：末尾 16 字节用于包名指纹校验。这个数组【就是
 * .nck 段的全部内容】—— 长度不一致时 Python 的
 * assert len(blob)==slot['size'] 会当场炸，属好消息；
 * 坏消息是它只在跑过锁箱后才暴露，所以改一侧必须立刻改另一侧。 */
__attribute__((section(".nck"), used, aligned(1), retain))
static const volatile unsigned char ncg_key_slot[96] = {0};

/* ── 被锁的业务逻辑：只有解锁后才能调用 ────────────────────────────
 * 用法：调用方必须先 ncguard_unlock() 成功，再调本函数。
 * 对拍契约：ncguard_probe(0) == ((0^0x5A)+0x0F)*3 & 0xFF == 59。
 * 取值刻意不取 42/0/1 这类哨兵值，避免 strings 一眼定位。
 * retain 同密钥槽：防 --gc-sections 回收。 */
__attribute__((section(".ncx"), used, retain))
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
 * 不解锁它也能回答——只探测符号存在性，不碰 .ncx 内容。 */
int ncguard_available(void) {
    return 1;
}
