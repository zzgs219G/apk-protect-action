/* nc_guard_boot.c — 自解谜引导（明文 stub + 密文 unlock 本体）
 *
 * ───────────────────────────────────────────────────────────────────
 * 函数索引（2026-10-20 加。本文件 918 行，读之前先看这张表——
 *           它标了每个函数在哪一段、被谁调，能省掉全文扫描）
 * ───────────────────────────────────────────────────────────────────
 *
 * 第一部分：密文 unlock 本体（NC_SEC_HEAD = .ncxh，构建期被锁成密文）
 *   行 285  ncg_rc4              RC4（与 so-section-lock.py 逐字节同算法）
 *   行 307  ncg_find_section     按名字在 ELF 文件里找段（ELF64 only）
 *   行 341  ncg_resolve_self     dladdr 拿自身基址与路径
 *   行 372  ncg_self_pkg         从 /proc/self/cmdline 取包名（截到第一个 ':'）
 *   行 396  ncg_pkg_matches      包名指纹比对（SHA256(包名)[:8] vs slot）
 *   行 413  ncg_find_apk_path    定位自身 APK（maps 含 base.apk / so 路径反推）
 *   行 472  ncg_head_unlock      ★主流程★ 解出 .ncx/.ncxr 业务段
 *
 * 第二部分：明文 stub（.text，攻击者唯一能直接读到的部分）
 *   行 227  ncg_xor_key          运行期拼回 XOR_KEY（4 个 volatile uint16）
 *   行 715  ncg_crc32            CRC32（代码自绑定用，软件实现不用 __crc32d）
 *   行 761  ncg_magic_ok         magic 种子比对（恒定时间，无明文字面量）
 *   行 767  ncg_rd32             小端读 4 字节
 *   行 776  ncg_stub_recover     ★把 .ncxh 还原成明文★（-O2 下被内联进
 *                               ncguard_unlock，实测 225 行反汇编）
 *
 * 第三部分：对外接口与触发（.text 明文）
 *   行 916  ncguard_unlock       对外入口：算 CRC → 解 head → 解业务段
 *   行 950  ncg_boot_init        constructor(50)，so 加载即跑
 *
 * ⚠️ 三条调用纪律（违反即死锁/崩溃，均有真机实测依据）：
 *   ① stub（第二部分）只能调【.text 里】的函数。调 head 段里的函数
 *      （如 ncg_rc4）会执行密文 → 卡死/SIGILL。见行 851 附近注释。
 *   ② ncg_head_unlock 及其私有函数绝不能标进 .ncx —— 它得先被 stub
 *      解出来才能跑，标进去 = 开锁器被锁进箱子。
 *   ③ ncVerify/heartbeat 两个 JNI 入口（在 nc_link.c）绝不能标段——
 *      它们是 unlock 的调用方，标了即死锁。
 *
 * ───────────────────────────────────────────────────────────────────
 *
 * ⚠️ 2026-10-18 新增。这是"把开锁器锁进它开的那只箱子"的落地，针对外部
 *    逆向报告（docs/so层防御/简盒-06 §6.2）指出的唯一质变线：
 *    「解锁逻辑本身是明文，攻击者直接读函数反汇编就知道怎么解」。
 *
 * 与 nc_guard_unlock.c 的关系（零冻结改动路线）：
 *   nc_guard_unlock.c  保留在仓库、仍是冻结资产，但【不再进 NDK 工程】。
 *   nc_guard_boot.c    本文件 = 新的运行期入口，内含 unlock 本体的一份
 *                      实现（放在 .ncxh 段，构建期被锁成密文）。
 *   两份并存是刻意取舍：动 unlock.c 要破冻结纪律，而它已被真机验证过；
 *   本文件承接"可继续演进"的部分。unlock.c 自此是历史存档，不再维护。
 *
 * 三级结构（攻击面从外到内）：
 *   ① 明文 stub（.text）
 *       只做：算 CRC → 读 slot → 验 magic → 恢复 k_stub → mprotect → XOR → 跳转
 *       ⚠️ 实测口径（别照设计文档想象）：`ncg_stub_recover` 被 -O2
 *       【整个内联进 `ncguard_unlock`】（连同 `ncg_rd32`/`ncg_xor_key`/
 *       XOR 循环），无独立符号 —— `nm boot.o` 只剩 `.recovered` 静态变量。
 *       体积口径：2026-10-18 实测约 200 行 / 736B；2026-10-20 复测
 *       **225 行**（阶段3 加 CRC32 自绑定后变大）。
 *       我最初写"约 30 行一个分支"是乐观估计，实测达不到——内联把它撑大了。
 *       但内容仍是"无智力"的：没有 ELF 解析、没有 HMAC、没有 RC4 S 盒、
 *       没有 slot 布局解释。攻击者读完只知道"算个 CRC、异或一段然后跳"。
 *   ② 密文 unlock 本体（.ncxh，构建期锁箱）
 *       完整能力：ELF 段表解析、HMAC 校验、RC4 解密、页权限管理
 *       实测锁定后 objdump 对该段无有效输出（密文）
 *   ③ 密文业务段（.ncx，由 ② 负责解）
 *       dex2c 转译产物 + 12 个 env_check 探针
 *
 * 为什么 stub 不需要读盘 / 不需要 dladdr / 不需要段表：
 *   `&符号` 在 PIE 下由编译器生成 PC 相对引用（adr/bl），运行期天然正确
 *   （本地实测：对自定义段函数的引用均为 b 0x.. <sym> / adr x0, 0x..）。
 *   所以 stub 直接用 `&ncg_head_unlock` 拿段内入口运行期地址，段大小与
 *   入口偏移由锁箱器写进 slot，零 I/O。
 *
 * 未锁状态（锁箱器没跑过）也必须正常：
 *   slot magic 不匹配 → stub 直接返回，段是明文 → 本体照常执行 →
 *   本体发现 .nck 无 magic → 返回 0。开发期不锁箱也能跑。
 */
#include <elf.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "nc_guard_key.h"   /* khmac_sha256 */

/* LSGS 密文表（路径字面量用）。
 *
 * ⚠️ 本文件的路径【复用 env_check.c 定义的宏】（LSGS_PATH_CMDLINE /
 *    LSGS_PATH_MAPS），不另立标记 —— make-sig-log.py 只扫描
 *    sig_check.c 与 env_check.c，扫不到本文件。同内容复用同一条密文，
 *    既省体积也避免两条标记内容漂移。
 *
 * ⚠️ 为什么必须加密：这两个字面量所在函数虽标进 .ncxh，
 *    但 **C 的字符串字面量永远进 .rodata，不会跟着函数进自定义段**。
 *    实测确认：锁箱后 /proc/self/cmdline 仍在 .rodata 明文可搜。 */
#include "nc_guard_layout.h"  /* 契约常数单一真相源：段名/slot尺寸/偏移/magic seed */
#include "sig_log_data.h"

/* ── 契约常量：与 so-section-lock.py 共享，改一处必须同步另一侧 ── */
/* 常量表专用段（2026-10-19）：签名表的 salt/期望值放这里。
 * 为什么不能放 .ncx：那是 AXR（可执行）段，clang 拒绝让 const 数据
 * 进去（'causes a section type conflict'）。本段是 AWR，不可执行。
 * 与 .ncx 共用同一把 k_so 和同一个 MAC —— 逻辑上是同一份资产。 */
/* ⚠️ 2026-10-19：magic 不再以明文字面量出现在 .rodata。
 *
 * 原实现是字符串常量 "NCKEYLOCK"/"NCSTUBLK"，`strings -n 6` 直接扫出——
 * 攻击者一眼就知道"这里有个锁箱、magic 长这样"，属强度报告里"抗知道
 * 内部结构 = 零"的直接来源。实测旧产物 strings 可见 3 条（含半边
 * "NCSTUBLKEM"）。
 *
 * 现在：锁箱器往 slot 写的是 8 字节【随机种子】，不是可识别字符串；
 * 运行期把落盘字节与代码里的同名种子逐字节比较（ncg_magic_ok）。
 *
 * ⚠️⚠️ 2026-10-20 修正一处夸大表述（原注释是错的，别信）：
 *   原注释写"因 seed ^ xor_key == NCKEYLOC，攻击者即使 dump 到种子
 *   也需先拿到碎片密钥才能看出它是 magic"——【不成立】。
 *   事实：ncg_magic_ok() 只做 `diff |= got[i] ^ seed[i]` 累或，
 *   【碎片密钥完全不参与 magic 比较】（它只在 ncg_xor_key() 里用于
 *   恢复 k_stub / k_mac_head）。攻击者 dump 到 slot 前 8 字节即可
 *   直接与本文件的 NCG_MAGIC_SEED_SLOT/NCG_MAGIC_SEED_STUB 比对，零额外成本。
 *
 *   本机制的真实收益【只有一条】：strings 搜不到 "NCKEYLOCK" /
 *   "NCSTUBLK" 字面量。它买的是"自动扫描失效"，不是"人工逆向成本"。
 *   写清楚这条，是为了防止后人（或 AI）据此高估防御强度、少做别的加固。
 *
 * 语义不变：仍"匹配 = 已锁，不匹配 = 未锁放行"，开发期照常能跑。
 * 两侧契约：本文件的 NC_SEED_*（来自 nc_guard_layout.h）与 so-section-lock.py 的
 * SLOT_MAGIC_SEED / STUB_MAGIC_SEED 必须逐字节一致（该文件头部有
 * `assert seed ^ XOR_KEY == b'NCKEYLOC'` 自校验，但它只验 Python
 * 自我一致，不校验 C 侧——所以 test-so-lock.sh T20 负责跨语言对拍）。 */
/* magic 种子：落盘即此值，运行期与 slot 前 8 字节逐字节比。
 * 不是 magic 本身（magic = seed ^ XOR_KEY，仅用于人类记忆）。
 *
 * ⚠️ 值来自 nc_guard_layout.h 的 NC_SEED_*_INIT —— 契约的单一真相源。
 *    数组名保留 NCG_ 前缀：它是本文件的 C 侧私有符号，不属于跨语言契约
 *    （跨语言契约是"值"，不是"C 变量叫什么"）。刻意不改符号名——
 *    改名会改变 .rodata 布局，使 T22 的二进制等价性验证失效。 */
static const uint8_t NCG_MAGIC_SEED_SLOT[8] = NC_SEED_SLOT_INIT;
static const uint8_t NCG_MAGIC_SEED_STUB[8] = NC_SEED_STUB_INIT;
static int ncg_magic_ok(const volatile unsigned char *got, const uint8_t seed[8]);
/* ── slot 布局与尺寸：唯一真相源在 nc_guard_layout.h ──────────────
 * 本文件不再画布局图。2026-10-20 删除的原因：此处原有【三份】slot 布局图
 * （88 字节版 / 96 字节版 / 104 字节版），与 nc_guard_layout.h 的 NC_OFF_*
 * 构成多权威——扩容时改宏不改图，图就变成错的，而"权威的错图"比没有图
 * 更坏（AI/人会照着它改代码）。
 * 现行：段名看 NC_SEC_*，.nck 尺寸看 NC_SLOT_SIZE，.ncks 尺寸看
 * NC_STUB_SIZE，字段偏移看 NC_OFF_*。该头文件带 _Static_assert 挡偏移重叠，
 * 且 so-section-lock.py 从中抽取、test-so-lock.sh T20/T21/T22 对拍。
 *
 * 保留两条 layout.h 里没有的历史信息（防止"当初为什么这么设计"失传）：
 *   · .nck[80:88] 存 SHA256(包名) 前 8 字节而非明文包名：k_so 派生需要
 *     构建期那个包名，但明文会暴露"密钥与包名有关"这条线索。
 *   · .ncks 扩到 104 而非复用 [44:48) reserved：那里只有 4 字节，装不下
 *     addr+size 两个 u32；硬塞会与 expect_mac_head 重叠——那种重叠是
 *     【静默】破坏 MAC 校验的，编译期不报。 */

/* 为什么 head 段也要算 MAC（P0-b，2026-10-18；安全设计理由，勿删）：
 *   在此之前 head 段只有简单 XOR。攻击者可以改 head 密文中对应"unlock 本体
 *   的 MAC 校验函数"的那几位 → 解密后 unlock 本体还在，但它对 .ncx 的校验
 *   被改成恒真 → .ncx 的 HMAC 保护被绕过。这是具体路径，不是理论风险。
 *   加 MAC 后：改任何一位 → HMAC 不符 → 不解密 → head 保持密文 →
 *   调用即 SIGILL（与 .ncx 的 -11 语义完全对等）。
 *   MAC 对【密文】算，与 .ncx 一致：解密前就能验，验不过就不装明文。
 *
 * （原此处还有一份 88 字节旧版布局图作"历史存档"，2026-10-20 删除——
 *  它构成了第二份布局描述，与 nc_guard_layout.h 形成双权威。） */


/* ⚠️ 2026-10-18 与 LSGS 彻底分离（原值与 make-sig-log.py 的 key 相同，
 * 注释还写"与 LSGS 同源"——那是错的）：同一把 8 字节密钥此前同时护三处
 * （.ncx 的 wrapped_k_so/wrapped_k_mac、.ncxh 的 wrapped_k_stub、
 * 以及 make-sig-log.py 的中文日志 XOR 密文）。而 LSGS 侧自己的注释就写着
 * "不抗人工逆向"——共用的后果是破掉最脆的那套，强的一起破。
 * 本常量只服务 nc_guard；LSGS 侧保持原值不动。两把钥匙互不相关。
 * 改这里必须同步 so-section-lock.py 的 XOR_KEY（锁箱/开箱两侧契约）。
 *
 * ⚠️ 2026-10-18 不再是一整串 8 字节，而是拆成 4 片 uint16 常量、分散在 4
 * 个 noinline 函数的立即数里，运行期按 NCG_XOR_FRAG 查表 + 高低位规则拼回。
 * 原实现是整串常量放 .rodata，HEX 搜索可直接命中（实测 7e31a0dc8924bf6
 * 在 so 里明文出现 2 次）——那是"请照这个走"的垫脚石。拆开后连续 8 字节
 * 密钥在 .rodata 里消失（实测归零），攻击者要凑齐必须同时读出查表、4 个
 * 常量与高低位规则三处再手工重组。
 *
 * 存放约定（每个碎片装 2 个"逻辑字节"，无固定逻辑序）：
 *   frag_a=0xc831 → 低位=逻辑1(0x31) 高位=逻辑4(0xc8)
 *   frag_b=0x927e → 低位=逻辑0(0x7e) 高位=逻辑5(0x92)
 *   frag_c=0xf6a5 → 低位=逻辑2(0xa5) 高位=逻辑7(0xf6)
 *   frag_d=0x4b0d → 低位=逻辑3(0x0d) 高位=逻辑6(0x4b)
 * 运行时规则：逻辑 i<4 取低位、i>=4 取高位；碎片编号查 NCG_XOR_FRAG[i]。 */
static const uint8_t NCG_XOR_FRAG[8] = NC_XOR_FRAG_INIT;

/* ⚠️ 碎片必须是「运行期才知道」的值，否则白拆。
 *
 * 第一版：4 个 uint16 常量各放一个 noinline static 函数。实测被打脸——
 * LLVM 做函数间常量传播，把完整 8 字节密钥写回 .rodata
 * （boot.o 0x5b0/0x5b8 各一份连续 8 字节，HEX 一搜即中）。
 * noinline 挡不住：static 函数只有一处调用，编译器算得出返回值。
 *
 * 现在的做法：4 个碎片放 4 个独立 volatile 变量（各 2 字节，位于
 * .data 而非 .rodata）。volatile 读阻止编译期折叠，于是 .rodata 里
 * 不再出现连续 8 字节密钥；攻击者 dump 到的是 4 个看似无关的 16 位
 * 常量，还必须另外读出 NCG_XOR_FRAG 表与高低位规则才能重组。 */
static volatile uint16_t ncg_frag_a = 0xc831u;  /* 逻辑 1,4 */
static volatile uint16_t ncg_frag_b = 0x927eu;  /* 逻辑 0,5 */
static volatile uint16_t ncg_frag_c = 0xf6a5u;  /* 逻辑 2,7 */
static volatile uint16_t ncg_frag_d = 0x4b0du;  /* 逻辑 3,6 */

/* 运行期拼回完整 8 字节密钥。每次调用重算，不缓存——缓存就是又把密钥
 * 写进内存某处。调用方用完必须 memset 擦除。 */
static void ncg_xor_key(uint8_t out[8]) {
    /* volatile 读：编译器无法在编译期算出结果，也就无法把完整 8 字节
     * 密钥折回 .rodata。代价是 4 次 volatile load（若干纳秒），可忽略。 */
    uint16_t fr[4];
    fr[0] = ncg_frag_a;
    fr[1] = ncg_frag_b;
    fr[2] = ncg_frag_c;
    fr[3] = ncg_frag_d;
    for (int i = 0; i < 8; i++) {
        uint16_t v = fr[NCG_XOR_FRAG[i]];
        out[i] = (i < 4) ? (uint8_t)(v & 0xFF) : (uint8_t)((v >> 8) & 0xFF);
    }
}

/* ═══════════════════════════════════════════════════════════════════
 * 第一部分：密文 unlock 本体（进 .ncxh，构建期被锁）
 * ═══════════════════════════════════════════════════════════════════ */

/* ── master：HKDF 的 ikm，构建期随机化后藏进 head 密文段（2026-10-19）──
 *
 * 修的是实测报告静态部分 P1-1（报告排第二优先，本轮提前做，理由见下）：
 *   master[32] 原来是 `static const` 全 0x11 的占位符，躺在 .rodata。
 *   攻击者 `od` 一条命令读出，配合 APK 里的证书就能离线算出 k_so，
 *   8 分钟解开 .ncx —— 这条链【完全不需要运行、不需要真机、不需要证书私钥】。
 *
 * 为什么"只换成随机数"不够（这是本轮最关键的设计判断）：
 *   随机数若仍是 .rodata 里的裸常量，攻击者 `od` 一样读出来，成本不变。
 *   必须【同时】解决"值随机"和"藏到读不到的地方"。
 *
 * 现在的位置与链路：
 *   本变量在 .ncxh 段内 → 构建期被整段 XOR 锁成密文
 *   运行期必须【先解开 head】才能读到 master：
 *     碎片(4×uint16) → XOR_KEY → wrapped_k_stub → k_stub → 解 head → master → k_so
 *   攻击链从 2 步变 5 步，且中间任一步的产物都不是明文常量。
 *
 * ⚠️ 为什么 master 不用于解 head（避免循环依赖）：
 *   head 段用 k_stub 解（stub 只需碎片，零 I/O）；master 只用于派生
 *   k_so / k_mac 去解 .ncx 业务段。若让 master 参与解 head，
 *   就变成"要用 head 里的东西解 head 自己"——死循环。
 *   这也符合 Xop 的分层：引导密钥（stub）与业务密钥（master→k_so）分离。
 *
 * ⚠️ 未锁箱时（开发期）：master 保持全零，运行期检测到全零即视为未锁，
 *    不参与派生（与 magic 判"未锁"同语义）。全零不可能是合法 master，
 *    因为锁箱器强制写入随机值并断言非全零。 */
/* ⚠️ 段名用 .ncxhr 而不是 .ncxh：后者是 AXR（可执行），
 * clang 拒绝让数据进去（'ncg_rc4' causes a section type conflict with
 * 'ncg_master'）——本文件上一轮给签名表用 .ncxr 也是同一原因。
 *
 * 为什么它必须和 head 用【同一把 k_stub】加密、且在【同一次 lock_head】
 * 里一起锁：如果改用 k_so 加密，就成"k_so 的派生需要先解开 k_so 加密的
 * 东西"——循环依赖。用 k_stub 则链路是单向的：
 *   碎片 → XOR_KEY → k_stub → {解 head, 解 head_ro → master} → k_so
 * 且 stub 只需碎片、零 I/O，能独立完成这一步。 */
__attribute__((section(NC_SEC_HEADRO), used, retain, aligned(16)))
static uint8_t ncg_master[32] = {0};

/* RC4 —— 与 so-section-lock.py 的 rc4() 逐字节同算法 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static void ncg_rc4(const uint8_t *key, size_t keylen,
                    const uint8_t *in, uint8_t *out, size_t len) {
    uint8_t S[256];
    int i, j;
    for (i = 0; i < 256; i++) S[i] = (uint8_t)i;
    for (i = 0, j = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
    }
    for (i = 0, j = 0; len-- > 0; ) {
        uint8_t c;
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        uint8_t t = S[i]; S[i] = S[j]; S[j] = t;
        c = S[(S[i] + S[j]) & 0xFF];
        *out++ = *in++ ^ c;
    }
}

/* 在 ELF 文件里按名字找段（ELF64；armeabi-v7a 的 ELF32 支持是既有缺口，
 * 见 unlock.c 同款函数的历史说明，本轮不扩范围） */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_find_section(const char *so_path, const char *name,
                            Elf64_Shdr *out) {
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -1;
    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof(eh)) != sizeof(eh)
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0
        || eh.e_shoff == 0 || eh.e_shnum == 0) { close(fd); return -1; }
    if (eh.e_shstrndx >= eh.e_shnum) { close(fd); return -1; }

    Elf64_Shdr *shs = (Elf64_Shdr *)calloc(eh.e_shnum, sizeof(Elf64_Shdr));
    if (!shs) { close(fd); return -1; }
    if (pread(fd, shs, eh.e_shnum * sizeof(Elf64_Shdr), eh.e_shoff)
        != (ssize_t)(eh.e_shnum * sizeof(Elf64_Shdr))) { free(shs); close(fd); return -1; }

    Elf64_Shdr *strh = &shs[eh.e_shstrndx];
    char *strtab = (char *)calloc(strh->sh_size + 1, 1);
    if (!strtab) { free(shs); close(fd); return -1; }
    pread(fd, strtab, strh->sh_size, strh->sh_offset);

    int found = -1;
    for (int i = 0; i < eh.e_shnum; i++) {
        const char *n = strtab + shs[i].sh_name;
        if (strcmp(n, name) == 0) { *out = shs[i]; found = 0; break; }
    }
    free(strtab);
    free(shs);
    close(fd);
    return found;
}

/* so 路径解析：用 head 本体的地址 dladdr（dladdr 是 libc 的，但本体已在
 * 明文状态才被调用，所以这里用 libc 无妨——约束只针对明文 stub） */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_resolve_self(void **base, char *path, size_t pathcap) {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr((const void *)&ncg_resolve_self, &info) == 0
        || info.dli_fbase == NULL) return -1;
    *base = info.dli_fbase;
    if (info.dli_fname) {
        strncpy(path, info.dli_fname, pathcap - 1);
        path[pathcap - 1] = 0;
        return 0;
    }
    return -1;
}

/* ── P1-a 辅助（2026-10-19）：运行期定位自身 APK / 自身包名 ───────────
 *
 * 为什么不解析 AndroidManifest.xml 拿包名：
 *   那要在运行期跑一个 AXML 二进制解析器（字符串池 + 资源映射），
 *   任何边界 bug 都是新的崩溃源（参见报错四十九：为自检新增的类没生成
 *   → ULE 被 catch 吞掉 → 连带跳过心跳 → watchdog 误杀）。
 *   本机制只做"校验"不做"发现"：包名从 /proc 拿，指纹在构建期写进 slot，
 *   两者对不上就 fail-closed。零新增解析器、零新崩溃面。
 */

/* 从 /proc/self/cmdline 取包名（第一个 NUL 分隔字段）。
 *
 * ⚠️ 2026-10-19：Android 的 cmdline 是【进程名】，不一定是包名——
 * 子进程会带 ":remote" / ":push" / ":service" 之类后缀。若不截断，
 * 主进程能通过指纹校验、子进程全部 fail-closed(-12) → 正常功能挂掉。
 * 这里统一截到第一个 ':' 之前，与 AndroidManifest 的 package 对齐。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_self_pkg(char *out, size_t cap) {
    char _cb[24];
    const char *_cp = lsg_s(LSGS_PATH_CMDLINE, _cb, sizeof(_cb));
    int fd = _cp ? open(_cp, O_RDONLY) : -1;
    if (fd < 0) return -1;
    char buf[256];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    char *colon = strchr(buf, ':');
    if (colon) *colon = 0;
    size_t l = strlen(buf);
    if (l == 0 || l >= cap) return -1;
    memcpy(out, buf, l + 1);
    memset(buf, 0, sizeof(buf));
    return 0;
}

/* 包名指纹校验：构建期把 SHA256(pkg) 前 8 字节写进 slot[NC_OFF_PKG_SHA]。
 * 为什么要指纹而不是直接存明文包名：明文包名会让攻击者一眼看出
 * "密钥与包名有关"，且 slot 是明文段（.nck 只有内部字段被 XOR）。
 * 指纹长度 8 字节 = 64 bit，碰撞概率对本用途可忽略。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_pkg_matches(const uint8_t *slotdata, const char *pkg) {
    const uint8_t *want = slotdata + NC_OFF_PKG_SHA;
    uint8_t h[32];
    ksha256((const uint8_t *)pkg, strlen(pkg), h);
    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= (uint8_t)(h[i] ^ want[i]);
    memset(h, 0, sizeof(h));
    return diff == 0;
}

/* 定位自身 APK 路径。两条来源：
 *   ① /proc/self/maps 中含 "base.apk" 的行（extractNativeLibs=false 时
 *      so 直接映射自 APK；true 时也能命中，因为 ART 会映射 APK）
 *   ② 由 so 自身路径反推：.../lib/<abi>/libnc.so → .../base.apk
 * 与 sig_check.c:find_apk_path() 同思路，但不复用它——那是冻结模块，
 * 且这里在密文段里，必须自包含。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
static int ncg_find_apk_path(const char *so_path, char *out, size_t cap) {
    char _mb[24];
    const char *_mp = lsg_s(LSGS_PATH_MAPS, _mb, sizeof(_mb));
    int fd = _mp ? open(_mp, O_RDONLY) : -1;
    if (fd >= 0) {
        /* maps 可能上百 KB，按块读，逐行拼装 */
        static char buf[8192];
        ssize_t n;
        char line[600];
        size_t ll = 0;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                char c = buf[i];
                if (c == '\n') {
                    line[ll] = 0;
                    ll = 0;
                    const char *p = strstr(line, "base.apk");
                    if (p) {
                        /* 行格式：addr perms offset dev inode  path
                         * 路径从第一个 '/' 开始 */
                        const char *s = strchr(line, '/');
                        if (s && s <= p) {
                            size_t l = (size_t)(p - s) + 8;   /* 含 "base.apk" */
                            if (l < cap) {
                                memcpy(out, s, l);
                                out[l] = 0;
                                close(fd);
                                return 0;
                            }
                        }
                    }
                } else if (ll + 1 < sizeof(line)) {
                    line[ll++] = c;
                }
            }
        }
        close(fd);
    }

    /* ② 从 so 路径反推：.../lib/arm64-v8a/libnc.so → .../base.apk */
    const char *lib = strstr(so_path, "/lib/");
    if (lib) {
        size_t dirlen = (size_t)(lib - so_path);
        const char *base = "/base.apk";
        size_t bl = strlen(base);
        if (dirlen + bl < cap) {
            memcpy(out, so_path, dirlen);
            memcpy(out + dirlen, base, bl + 1);
            return 0;
        }
    }
    return -1;
}


/* ── unlock 本体主流程：解出 .ncx 业务段 ──────────────────────
 * 由明文 stub 解密后才可调用（此前它是密文）。
 * 返回 0 成功；负值含义与 nc_guard_unlock.c 的码表一致。 */
__attribute__((section(NC_SEC_HEAD), used, retain, noinline))
int ncg_head_unlock(void) {
    void *base;
    char so_path[512];
    if (ncg_resolve_self(&base, so_path, sizeof(so_path)) != 0) return -1;

    Elf64_Shdr sec, slot;
    if (ncg_find_section(so_path, NC_SEC_CODE, &sec) != 0) return -2;
    if (ncg_find_section(so_path, NC_SEC_SLOT, &slot) != 0) return -3;
    if (sec.sh_size == 0) return -4;
    if ((sec.sh_flags & SHF_ALLOC) == 0) return -5;

    uint8_t slotdata[NC_SLOT_SIZE];
    memset(slotdata, 0, sizeof(slotdata));
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -6;
    ssize_t got = pread(fd, slotdata, sizeof(slotdata), slot.sh_offset);
    close(fd);
    if (got < 32) return -7;
    if (!ncg_magic_ok(slotdata, NCG_MAGIC_SEED_SLOT)) {
        return 0;   /* 未锁，无需解锁 */
    }
    int have_mac = (got >= NC_SLOT_SIZE) && (slot.sh_size >= NC_SLOT_SIZE);

    static int ncg_unlocked = 0;
    if (ncg_unlocked) return 0;

    uint8_t key[16];
    {
        uint8_t xk[8];
        ncg_xor_key(xk);
        for (int i = 0; i < 16; i++) key[i] = slotdata[16 + i] ^ xk[i & 7];
        memset(xk, 0, sizeof(xk));
    }

    /* ═══ P1-a（2026-10-19）：运行期证书派生，取代 slot 里的 wrapped k_so ═══
     *
     * 修的是强度报告（简盒-07 §4）的核心指控「证书绑定是构建期属性、
     * 运行期零参与」——此前 k_so 直接由 slot[16:32] ^ XOR_KEY 得到，
     * 意味着【拿到 so 就能离线解密，不需要 APK 也不需要证书】。实测：
     * 20 秒纯静态 PoC 即可 dump 出全部明文（见 .p1a/attack_poc.py）。
     *
     * 现在：从【已安装的 APK】读第一签名者证书 → SHA256 → HKDF 派生 k_so。
     * slot[16:32] 保留但不再参与派生（见 locked 侧的 derive 分支），
     * 它只是"未启用证书绑定"时的兼容路径。
     *
     * fail-closed（用户 2026-10-19 拍板）：证书读不到 / 派生结果与
     * slot 里记录的指纹不符 → 直接返回 -12，不解密。
     * 与流程文档「重签必须用同一 keystore」的既有契约一致，
     * 只是把这条契约从"提示"升级为"强制"。
     *
     * 性能实测（真机级存储，真实 4.7MB 已签名 APK）：提取+SHA256+HKDF
     * 中位 14.1 us，占 60fps 一帧的 0.08%，且只在 constructor 跑一次。 */
    /* der_buf/pkg_buf 用 static：约 1.6KB 栈上开对 ART 的 8KB 线程栈偏大，
     * 且本函数全进程只跑一次，static 无并发风险（有 ncg_unlocked 守门）。 */
    static uint8_t der_buf[1536];
    static char pkg_buf[128];
    size_t der_len = 0;

    /* master 来自 head 段内的 ncg_master（2026-10-19 随机化 + 藏进密文）。
     *
     * 本函数【自身就在 head 段内】，所以执行到这里时 ncg_master 已经是
     * 明文（stub 已把整段解开）。这是关键前提：master 的可见性完全
     * 依附于"head 是否已解开"。
     *
     * 全零 = 未锁箱（开发期）：此时不应派生任何真密钥。用全零 master 走
     * 一遍 HKDF 也能算出结果，但那种产物本就未加密（.ncx 明文），
     * 所以行为等价于"没加锁"，不构成安全降级。
     * 锁箱器强制：master 必须非全零，否则 fail-fast。 */
    const uint8_t *master = ncg_master;
    {
        uint8_t acc = 0;
        for (int i = 0; i < 32; i++) acc |= master[i];
        if (acc == 0) {
            /* 未锁箱：走原来的路径（.ncx 本就是明文，不需要解密密钥），
             * 但也不应把全零 master 当成"有效派生源"去算 —— 直接返回 0
             * 让上层走"未锁"分支（magic 不匹配时本就返回 0）。 */
            return 0;
        }
    }
    {
        uint8_t k_cert[16];
        int cert_ok = 0;

        char apk_path[512];
        apk_path[0] = '\0';
        if (ncg_find_apk_path(so_path, apk_path, sizeof(apk_path)) == 0) {
            if (ncg_apk_first_cert_der(apk_path, der_buf, sizeof(der_buf),
                                       &der_len) == 0) {
                if (ncg_self_pkg(pkg_buf, sizeof(pkg_buf)) == 0 &&
                    ncg_pkg_matches(slotdata, pkg_buf) &&
                    ncg_derive_k_so_from_der(master, der_buf, der_len, pkg_buf,
                                             k_cert) == 0) {
                    cert_ok = 1;
                }
            }
        }

        if (!cert_ok) {
            /* fail-closed：证书/包名任一不可得 → 不解密。
             * 代价是"未签名调试包"直接起不来——这是刻意的：
             * 允许降级就等于允许攻击者把签名剥掉后照常跑。 */
            memset(key, 0, sizeof(key));
            memset(slotdata, 0, sizeof(slotdata));
            return -12;
        }

        /* 用证书派生的 k_so 覆盖 slot 里的诱饵值 */
        memcpy(key, k_cert, 16);
        memset(k_cert, 0, sizeof(k_cert));
    }


    /* ── 2026-10-19：受保护资产是两个段（代码 + 常量表）────────────
     * 实测报告 §8.1 的核心缺陷：判定算法（nc_verify_t1）与两张签名表
     * （SIG_SALT / SIG_HASH_STORED）原先全在明文 .rodata，攻击者 od
     * 一条命令读出、5 分钟反推出 32 字节通过凭据。加密层只保护了
     * ncVerify 这个转发壳，核心留在明文中——"锁很好，钥匙挂门上"。
     *
     * 现在拆成两段，共用一把 k_so、一个 MAC：
     *   .ncx     代码（AXR）—— nc_verify_t1 等
     *   .ncxr  常量表（AWR，不可执行）—— SIG_SALT / SIG_HASH_STORED
     * 为什么必须分两段：clang 拒绝 let const 数据进 AXR 段
     * （'causes a section type conflict'），见 nc_link.c 的注释。
     *
     * 向后兼容：老产物只有 .ncx、没有 .ncxr，此时 nseg=1，
     * MAC 与解密行为与历史版本逐字节一致（单段时 MAC 输入 == 该段密文）。 */
    Elf64_Shdr segs[2];
    int nseg = 0;
    segs[nseg++] = sec;
    {
        Elf64_Shdr ro;
        if (ncg_find_section(so_path, NC_SEC_CONST, &ro) == 0
            && ro.sh_size > 0 && (ro.sh_flags & SHF_ALLOC)) {
            segs[nseg++] = ro;
        }
    }

    uint8_t *target = (uint8_t *)base + sec.sh_addr;

    /* 完整性校验：先验后解（位置在 mprotect/解密之前）
     *
     * ⚠️ 2026-10-19 P1-a：k_mac 不再从 slot 读，而是与 k_so 一样从证书
     * 重新派生（label 用独立的 "nc-so-mac-v1"，与 so 域硬分隔）。
     * 理由：slot 里的 wrapped_k_mac 等于把完整性密钥交给攻击者——
     * 他能用它伪造 MAC，让被篡改的密文"验签通过"。
     * 锁箱侧对应地把该字段写成诱饵值（见 so-section-lock.py 的 _decoy_mac）。 */
    if (have_mac) {
        uint8_t k_mac[16], got_mac[32];
        if (ncg_derive_k_mac_from_der(master, der_buf, der_len, pkg_buf,
                                      k_mac) != 0) {
            memset(key, 0, sizeof(key));
            memset(slotdata, 0, sizeof(slotdata));
            return -12;
        }
        /* MAC 覆盖【所有段密文的拼接】，顺序与锁箱侧一致（代码段在前）。
         * 用增量 HMAC：两段不连续，一次性算需要额外拼缓冲（最多几十 KB，
         * 不值得为它 malloc + memcpy）。增量式零额外内存、零拷贝。 */
        {
            /* 不透明类型不能直接开栈对象 → 用对齐的字节缓冲 + 尺寸宏。
             * nc_guard_key.c 里有 static_assert 保证 sizeof <= KHMAC_CTX_SIZE，
             * 所以这里开 KHMAC_CTX_SIZE 必定够用。 */
            _Alignas(KHMAC_CTX_ALIGN) unsigned char hcbuf[KHMAC_CTX_SIZE];
            khmac_ctx *hc = (khmac_ctx *)hcbuf;
            khmac_init(hc, k_mac, 16);
            for (int i = 0; i < nseg; i++) {
                const uint8_t *p = (const uint8_t *)base + segs[i].sh_addr;
                khmac_update(hc, p, segs[i].sh_size);
            }
            khmac_final(hc, got_mac);
            memset(hcbuf, 0, sizeof(hcbuf));
        }
        const uint8_t *want = slotdata + NC_OFF_EXPMAC;
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) diff |= (uint8_t)(got_mac[i] ^ want[i]);
        memset(k_mac, 0, sizeof(k_mac));
        memset(got_mac, 0, sizeof(got_mac));
        if (diff != 0) {
            memset(key, 0, sizeof(key));
            return -11;
        }
    }

    /* ── 解密：逐段处理，权限各自最小 ──────────────────────────────
     * 代码段解完是 RX（可执行不可写），常量表段解完是 R（只读不可执行）。
     * 给数据段加 X 是没有必要的权限扩大——它从来不需要执行。
     * 页对齐：目标段可能与相邻段同页（历史报错五十：.ncx 与 .text 尾部
     * 同页导致 pwrite 写坏代码）。这里是 mprotect 而非 pwrite，同页只会
     * 让权限短暂放宽，不会破坏内容；但 mprotect 粒度是页，所以范围必须
     * 按页对齐，否则会失败。 */
    uintptr_t ps = getpagesize();
    for (int i = 0; i < nseg; i++) {
        uint8_t *tgt = (uint8_t *)base + segs[i].sh_addr;
        size_t len = (size_t)segs[i].sh_size;
        /* 数据段不需要 EXEC；代码段需要 */
        int is_code = (segs[i].sh_flags & SHF_EXECINSTR) != 0;
        uintptr_t s = (uintptr_t) tgt & ~(ps - 1);
        uintptr_t e = ((uintptr_t) tgt + len - 1 & ~(ps - 1)) + ps;
        if (mprotect((void *) s, e - s,
                     PROT_READ | PROT_WRITE | (is_code ? PROT_EXEC : 0)) != 0) {
            memset(key, 0, sizeof(key));
            return -8;
        }
        uint8_t *buf = (uint8_t *)malloc(len);
        if (!buf) { memset(key, 0, sizeof(key)); return -9; }
        ncg_rc4(key, 16, tgt, buf, len);
        memcpy(tgt, buf, len);
        free(buf);
        if (is_code) __builtin___clear_cache((char *)tgt, (char *)(tgt + len));
        if (mprotect((void *) s, e - s,
                     PROT_READ | (is_code ? PROT_EXEC : 0)) != 0) {
            memset(key, 0, sizeof(key));
            return -10;
        }
    }

    memset(key, 0, sizeof(key));
    memset(slotdata, 0, 16);   /* 只清前 16 字节（magic 区），保持历史行为 */
    ncg_unlocked = 1;
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════
 * 第二部分：明文 stub（.text，攻击者唯一能直接读到的部分）
 * ═══════════════════════════════════════════════════════════════════ */

/* stub 的密钥槽：由 so-section-lock.py 在锁箱时写入（88 字节，见上方布局图）
 *
 * ⚠️ 2026-10-18 为什么不存 entry_delta（入口符号 − 段起始偏移）：
 *   那需要从 .symtab 读符号地址，而 NDK ndk-build 默认 strip 符号表
 *   （CI 39074690534 实测：lock_head 报「符号 ncg_head_unlock 不在
 *   .symtab」→ protect.sh exit 1 → 构建失败）。
 *   也不能靠"让 CI 不 strip"绕过——那会把 frida_port_probe /
 *   xposed_maps_probe 等探针名暴露进符号表，等于泄露检测意图。
 *   改用【段头信息】推导：strip 只删 .symtab/.strtab，section header
 *   table 始终完整，段地址与段大小照样拿得到。
 *   镜像基址 = &ncg_stub_slot(运行期, PC 相对) − stub_slot_sh_addr(链接期) */
__attribute__((section(NC_SEC_STUBSLOT), used, aligned(1), retain))
static const volatile unsigned char ncg_stub_slot[NC_STUB_SIZE] = {0};

/* CRC32（IEEE 802.3，多项式 0xEDB88320）。软件实现——不用 __crc32d：
 * 那需要 -march=armv8-a+crc，而 armeabi-v7a 根本没有该指令，arms 上编译
 * 直接失败。实测软件版对 1.4KB（stub 区）耗时 8.4 us，可接受。
 * 用途：代码自绑定（见 ncg_self_bound_kstub）。 */
static uint32_t ncg_crc32(const uint8_t *p, size_t n) {
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++)
            c = (c >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(c & 1)));
    }
    return ~c;
}

/* 代码自绑定恢复 k_stub（2026-10-19，阶段3）。
 *
 * 攻击面背景（强度报告 §6「抗静态 patch = 弱」）：此前 k_stub 直接
 * slot[8:24] ^ XOR_KEY 得到，与代码零关联。攻击者 patch 明文 stub
 * （例如把 HMAC 校验改成恒真）无需付出任何代价——11 处 patch 点彼此
 * 独立、无链式依赖。
 *
 * 现在：k_stub = HKDF(master, slot_seed, crc32(自身代码区间)) 的前 16 字节。
 *   - 改任何一处 stub 代码 → CRC 变 → k_stub 变 → head 解出乱码
 *   - 没有"校验分支"可以单独 patch 掉：密钥本身就是错的
 *   - 攻击者要绕过，必须同时改代码【并】重新算出正确的 slot seed
 *     （而 seed 在锁箱期才生成，不随 so 分发）
 *
 * 代价实测：CRC32 对 stub 区（约 1.4KB）8.4 us，每次进程一次。
 * 区间取 .text 段中 [ncguard_unlock 起始, .ncxh 起始) ——
 * 该区间无重定位（readelf -r 全部落在 0x71d0 之后），文件字节与内存
 * 字节一致，所以锁箱期算的值与运行期算的值天然相同。 */
static uint32_t ncg_self_crc;   /* 由 ncguard_unlock() 在调用前算好 */

/* 生成式 magic 比较（2026-10-19）：字面量不进二进制。
 * want 由 NC_SEED_* 与碎片密钥运行期异或得出，不落在 .rodata。
 * ⚠️ 恒定时间不受影响：magic 不是秘密（攻击者能从密文段反推），
 *    这里求的是"没有明文字面量可搜"，不是防时序侧信道。
 *
 * ⚠️ 2026-10-20 修正口径：碎片密钥【不参与】本比较。
 *    早期注释写"攻击者需先拿到碎片密钥才能看出它是 magic"——那是错的。
 *    本函数只做 got[i] ^ seed[i] 累或，碎片密钥只在 ncg_xor_key() 里
 *    用于恢复 k_stub/k_mac。真实收益仅一条：strings 搜不到 "NCKEYLOCK"/
 *    "NCSTUBLK" 字面量。攻击者 dump 到 slot 前 8 字节即可直接比对。
 *    （已删除的 ncg_eq8 是同一语义的前身，语义等价，勿再引入。）
 *
 * 历史：旧实现叫 ncg_eq8(got, "NCKEYLOCK")，-O2 下被内联进
 *       ncguard_unlock（连同 ncg_rd32/XOR 循环，2026-10-18 实测约
 *       200 行 / 736B，2026-10-20 复测 225 行）。2026-10-19 改种子形式后
 *       ncg_eq8 已无调用方，
 *       2026-10-20 删除（-Wall 报 unused function；删除前后 .text
 *       section size 逐一相同，零字节影响）。 */
static int ncg_magic_ok(const volatile unsigned char *got,
                        const uint8_t seed[8]) {
    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= (uint8_t)(got[i] ^ seed[i]);
    return diff == 0;
}
static uint32_t ncg_rd32(const volatile unsigned char *p) {
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* 明文 stub：把 .ncxh 还原成明文。
 * 全程无循环展开以外的分支、无 libc 调用、无磁盘 I/O。
 * 未锁（slot magic 不匹配）时直接返回——段本就是明文。 */
static void ncg_stub_recover(void) {
    const volatile unsigned char *slot = ncg_stub_slot;

    if (!ncg_magic_ok(slot, NCG_MAGIC_SEED_STUB)) return;   /* 未锁 */

    static int recovered = 0;
    if (recovered) return;                         /* 本进程已解过 */

    /* 恢复 k_stub：slot[8:24] ^ XOR_KEY，再混入自身代码 CRC（阶段3 自绑定）。
     *
     * 混入方式刻意选【异或进密钥】而不是"算 CRC 后比较、不等就 return"：
     *   - 比较式：攻击者 patch 掉那条比较分支即可绕过（只多 1 处 patch）
     *   - 混入式：CRC 错了密钥就错，head 解出乱码 → 后续所有校验都失效，
     *     没有单点可以 patch 掉。这是"链式依赖"对"独立 patch"的本质差别。
     * 代码改一位 → CRC 变 → k_stub 变 → head 段解出乱码 → SIGILL。 */
    uint8_t k[16];
    {
        uint8_t xk[8];
        ncg_xor_key(xk);
        for (int i = 0; i < 16; i++) k[i] = (uint8_t)(slot[8 + i] ^ xk[i & 7]);
        memset(xk, 0, sizeof(xk));
        /* 把 4 字节 CRC 折叠进 16 字节密钥（每 4 字节异或一次同一 CRC，
         * 保证 16 字节全部参与，且不引入额外依赖） */
        uint32_t crc = ncg_self_crc;
        for (int i = 0; i < 16; i++)
            k[i] ^= (uint8_t)((crc >> ((i & 3) * 8)) & 0xFF);
        crc = 0;
    }

    uint32_t stub_sh_addr = ncg_rd32(slot + 24);
    uint32_t head_sh_addr = ncg_rd32(slot + 28);
    uint32_t head_size    = ncg_rd32(slot + 32);

    /* 合理性守卫：任一为 0 或段大小荒谬 → 视为未锁/损坏，直接放弃 */
    if (head_size == 0 || head_size > (64u << 20)
        || stub_sh_addr == 0 || head_sh_addr == 0) return;

    /* 镜像基址 = slot 自身运行期地址 − slot 链接期地址。
     * &ncg_stub_slot 由编译器生成 PC 相对引用（adr/add），运行期天然正确，
     * 且该符号是 static —— strip .symtab 不影响它的可链接性（本地编译产物
     * 里 nm 看不到它，但代码照常引用）。这是绕开"符号表被 strip"的关键。 */
    uintptr_t base = (uintptr_t) &ncg_stub_slot - stub_sh_addr;

    /* head 段起始 = 基址 + head 段链接期虚拟地址 */
    uint8_t *start = (uint8_t *)(base + head_sh_addr);

    /* ── P0-b：先验 MAC 再解密（2026-10-18）──────────────────────
     * 对【密文】算 HMAC-SHA256，与 slot 里的期望值恒定时间比较。
     * 位置刻意在 mprotect/解密【之前】：一旦不符，head 一个字都不改 → 段保持
     * 密文 → 后续调用踩密文 = SIGILL（fail-closed，与 .ncx 的 -11 语义
     * 完全对等）。此前 head 只有 XOR，攻击者可改"unlock 本体里的 MAC 校验
     * 函数"那几位，把 .ncx 的 HMAC 保护改成恒真从而绕过。
     *
     * k_mac_head 的恢复与 k_stub 同源：都是 wrapped ^ XOR_KEY。
     * 调用 khmac_sha256 不破坏"stub 无智力"约束——它只是复用 .text 里
     * 现成的密码学原语（nc_guard_key.c 的函数全在明文段），stub 本身仍没有
     * ELF 解析、没有 RC4 S 盒、没有密钥派生、没有 slot 布局解释。 */
    uint8_t k_mac[16], got_mac[32];
    {
        uint8_t xk[8];
        ncg_xor_key(xk);
        for (int i = 0; i < 16; i++)
            k_mac[i] = (uint8_t)(slot[NC_OFF_K_MAC_HEAD + i] ^ xk[i & 7]);
        memset(xk, 0, sizeof(xk));
    }
    khmac_sha256(k_mac, 16, start, head_size, got_mac);
    {
        const volatile unsigned char *want = slot + NC_OFF_EXPMAC_HEAD;
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++)
            diff |= (uint8_t)(got_mac[i] ^ want[i]);
        memset(k_mac, 0, sizeof(k_mac));
        memset(got_mac, 0, sizeof(got_mac));
        if (diff != 0) {
            /* 密文段被改过（或密钥与密文不匹配）→ 不解密、不动 mprotect */
            memset(k, 0, sizeof(k));
            return;
        }
    }

    uintptr_t ps = getpagesize();
    uintptr_t s = (uintptr_t) start & ~(ps - 1);
    uintptr_t e = ((uintptr_t) start + head_size - 1 & ~(ps - 1)) + ps;
    /* ⚠️ 2026-10-20 补返回值检查（此前未查，是本文件 5 个 mprotect 调用点
     *    里唯一漏的一处）。
     *
     * 不查的后果：mprotect 失败时下面那个 XOR 循环会往【仍只读】的页里写
     * → SIGSEGV。而 SIGSEGV 与"密文段被改过"的 SIGILL 是两种死法，
     * 排查时会被误导成"段被篡改"，实际是权限没改成功。
     *
     * 失败处理：直接 return，让 head 段【保持密文】。这与 655/666 的
     * -8/-10 语义对等（fail-closed），也与本函数上方 MAC 校验失败分支
     * （return、不动 mprotect）完全一致。本函数是 static void、无返回值
     * 通道，故用 return 而非返回码；后续对 head 段函数的调用都会踩密文
     * → SIGILL，从"非法指令"而非"段错误"即可判断是解密链路失败。
     *
     * 为什么早先不查：本函数在 .text 明文 stub 里，曾担心多加分支会改变
     * stub 形态。该顾虑不成立——CRC 自绑定是每次构建时对【当次】.text
     * 现算的（so-section-lock.py 的 lock_head），锁箱与运行天然自洽；
     * 且已发布 .so 是独立二进制，源码改动碰不到它。 */
    if (mprotect((void *) s, e - s, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        memset(k, 0, sizeof(k));
        return;   /* 权限没改成功 → 不解密，段保持密文 → 调用即 SIGILL */
    }

    for (uint32_t i = 0; i < head_size; i++) start[i] ^= k[i & 15];

    /* ── 顺带解开 master 数据段（2026-10-19）──────────────────────
     * 与 head 用同一把 k_stub、同一次遍历：master 只有解开这段才能读到，
     * 而这段的定位信息在 slot 的 NC_OFF_HEADRO_ADDR(96) 与
     * NC_OFF_HEADRO_SIZE(100) 两个 u32 里（.ncks 扩容到 104 时装它们）。
     *
     * 为什么必须在这里解、而不是在 ncg_head_unlock 里：
     *   ncg_master 是 head 段【外面】的另一个段，head 本体解完之后才能
     *   拿到 k_so；而取得 master 是派生 k_so 的前置。所以必须由 stub
     *   （唯一持有 k_stub 的地方）在解完 head 后立刻解它。
     *
     * 失败处理：段缺失或大小异常 → 不解，master 保持全零 →
     *   ncg_head_unlock 检测到全零即判定"未锁"直接返回 0。
     *   这是 fail-safe 而非 fail-open：未锁状态下 .ncx 本就是明文。 */
    {
        uint32_t ro_addr = ncg_rd32(slot + NC_OFF_HEADRO_ADDR);
        uint32_t ro_size = ncg_rd32(slot + NC_OFF_HEADRO_SIZE);
        if (ro_addr != 0 && ro_size > 0 && ro_size <= (1u << 16)) {
            uint8_t *ro = (uint8_t *)(base + ro_addr);
            uintptr_t ps2 = getpagesize();
            uintptr_t rs = (uintptr_t) ro & ~(ps2 - 1);
            uintptr_t re = ((uintptr_t) ro + ro_size - 1 & ~(ps2 - 1)) + ps2;
            if (mprotect((void *) rs, re - rs, PROT_READ | PROT_WRITE) == 0) {
                /* ⚠️ 必须用【简单循环 XOR】，不能调 ncg_rc4 ——
                 * ncg_rc4 本身就在 .ncxh 段里，此刻还是密文，
                 * 调用它会踩密文（实测卡死/SIGILL）。这是本文件第二次
                 * 踩同一个坑（head 段锁箱也不能用 rc4，见 lock_head 注释）
                 * ——规矩是：**stub 能碰到的函数只能是 .text 里的**。
                 * 循环 XOR 就地内联，无任何跨段函数调用。 */
                for (uint32_t i = 0; i < ro_size; i++)
                    ro[i] ^= k[i & 15];
                /* ⚠️ 恢复成 RW 而不是 R —— 实测踩过：
                 * .ncxhr 与 .data / .bss 【同页】
                 * （实测 arm64：.data 0x13ca8、head_ro 0x13cd0、
                 *   .bss 0x13cf0，全在页 0x13000 内）。
                 * mprotect 粒度是页，设成 READ 会把 .bss 也变只读 →
                 * 后续任何 .bss 写入即 SIGSEGV。
                 * 这个页本来就是 RW（.data/.bss 所在），恢复 RW 才是
                 * 还原原状；密文段保护不靠页权限，靠"内容是密文"。 */
                (void) mprotect((void *) rs, re - rs, PROT_READ | PROT_WRITE);
            }
        }
    }

    __builtin___clear_cache((char *) start, (char *)(start + head_size));
    memset(k, 0, sizeof(k));
    recovered = 1;
}

/* ═══════════════════════════════════════════════════════════════════
 * 第三部分：对外接口与触发（.text 明文）
 * ═══════════════════════════════════════════════════════════════════ */

/* 与 nc_guard_unlock.c 同名的对外入口：nc_guard_jni.c 的 selftest 依赖它 */
int ncguard_unlock(void) {
    static int done = 0;
    if (done) return 0;

    /* 阶段3 自绑定：先算自身代码 CRC，再进 stub 恢复。
     *
     * 区间取【ncguard_unlock 函数自身起始, 长度由 slot[36:40] 记录】——
     * 锁箱期把这段代码当作"受保护代码"，其 CRC 直接混进 k_stub。
     * 区间必须【不含】CRC 计算代码本身（否则自指、无解），所以：
     *   - 区间起点 = ncg_stub_recover 的地址（stub 主体）
     *   - 区间长度 = slot 里存的长度（锁箱期由 Python 按段表算）
     * 未锁时 slot 无 magic，ncg_self_crc 保持 0，stub 会直接返回，
     * 不影响开发期"不锁箱也能跑"。 */
    if (ncg_magic_ok(ncg_stub_slot, NCG_MAGIC_SEED_STUB)) {
        uint32_t code_addr = ncg_rd32(ncg_stub_slot + NC_OFF_CODE_ADDR);
        uint32_t code_len  = ncg_rd32(ncg_stub_slot + NC_OFF_CODE_LEN);
        if (code_len > 0 && code_len < (64u << 20) && code_addr != 0) {
            /* 镜像基址 = slot 运行期地址 − slot 链接期地址（同 stub 的算法） */
            uintptr_t base = (uintptr_t) ncg_stub_slot
                             - (uintptr_t) ncg_rd32(ncg_stub_slot + 24);
            const uint8_t *code = (const uint8_t *)(base + code_addr);
            ncg_self_crc = ncg_crc32(code, code_len);
        }
    }

    ncg_stub_recover();          /* 先确保 head 本体是明文 */
    int rc = ncg_head_unlock();  /* 再调本体解 .ncx */
    if (rc == 0) done = 1;
    return rc;
}

/* so 加载即跑：先解 head 本体，再由本体解业务段。
 * 优先级 50：早于任何可能的其它 constructor，确保业务段在 App 代码前就绪。 */
__attribute__((constructor(50)))
static void ncg_boot_init(void) {
    (void) ncguard_unlock();
}
