/* nc_guard_probe.c — so 段加密设施的密钥槽定义 + 样例消费者
 *
 * ⚠️ 本文件是设施的【承重墙】，不是试探残留：
 *   ncg_key_slot[96] 就是 .nck 段的全部内容。删掉本文件 = .nck 段消失
 *   → ncguard_unlock() 返回 -3 → 段保持密文 → 探针踩密文 → SIGILL
 *   → App 起不来。（文件头曾写"验证通过后可整体删除"，那是错的。）
 *
 * 两个角色：
 *   ① 设施本体：ncg_key_slot —— .nck 段的唯一定义处，锁箱侧往里写
 *      【诱饵密钥】+ expect_mac + pkg_sha8（布局见 nc_guard_layout.h）
 *   ② 样例消费者：ncguard_probe() —— 演示"一个函数如何进 .ncx"，
 *      对拍契约 probe(0) == 59
 *
 * 新增消费者（dex2c 转译产物等）不需要改本文件，也不需要手写
 * __attribute__ —— 用 scripts/lib/so_section_mark.py 按规则注入。
 *
 * 机制（抄自 XopProtector .bitcode 自解密）：
 *   编译期：ncguard_probe() 进 .ncx 段
 *   构建期：so-section-lock.py 用 RC4 加密 .ncx 后写回
 *   运行期：ncguard_unlock() 先解 .ncxh 拿到 k_so（证书派生），再解 .ncx
 *   之后  ：ncguard_probe() 才可被调用（解密前调用 = 执行密文 = SIGILL）
 *
 * 注：不引 <jni.h> —— 本文件无 JNI 类型需求，host 侧缺 jni_md.h、
 * NDK 侧也平白多一个依赖。唯一 include 是 nc_guard_layout.h（零依赖，
 * 只含契约常数与 _Static_assert，任何工具链都能编）。
 */

#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/尺寸/偏移 */

/* 密钥槽：.nck 段的全部内容（96 字节，布局见 nc_guard_layout.h）。
 *
 * const volatile 的理由：writable 对象在 SHF_EXECINSTR 段里会让 LLD 生成
 *   W+X 的 PT_LOAD，而 Android 10+ 拒绝可写可执行段。const 让它进 .rodata
 *   （只读），运行时再 mprotect 改写。
 *
 * ⚠️ retain 不可省：lib-ndk.sh 的 LOCAL_LDFLAGS 含 -Wl,--gc-sections，
 *   无引用的段会被当死代码连段一起回收（2026-10-17 CI 实测：
 *   .ncx 整个从 so 段表里消失）。
 *
 * ⚠️ 长度 96 必须与锁箱侧 blob 等长（NC_SLOT_SIZE）。不一致时 Python 的
 *   assert 会当场炸（好事），但它只在跑过锁箱后才暴露 —— 改一侧必须
 *   立刻改另一侧。 */
__attribute__((section(NC_SEC_SLOT), used, aligned(1), retain))
static const volatile unsigned char ncg_key_slot[96] = {0};

/* 样例消费者：只有解锁后才能调用。
 * 对拍契约：ncguard_probe(0) == ((0^0x5A)+0x0F)*3 & 0xFF == 59（0x3B）。
 *   ⚠️ 是 59，不是 42 —— 本处注释曾写"必须返回 0x2A（42）"，与公式
 *   矛盾且必然让对照测试失败。以公式与 59 为准。
 * 取值刻意不取 42/0/1 这类哨兵值，避免 strings 一眼定位。
 * retain 同密钥槽：防 --gc-sections 回收。 */
__attribute__((section(NC_SEC_CODE), used, retain))
int ncguard_probe(int token) {
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
