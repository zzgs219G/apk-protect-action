/* nc_guard_boot.c — 自解谜引导（明文 stub + 密文 unlock 本体）
 *
 * ⚠️ 2026-10-18 新增。这是"把开锁器锁进它开的那只箱子"的落地，针对外部
 *    逆向报告（docs/so层防御/简盒-06 §6.2）指出的唯一质变线：
 *    「解锁逻辑本身是明文，攻击者直接读函数反汇编就知道怎么解」。
 *
 * 与 nc_guard_unlock.c 的关系（零冻结改动路线）：
 *   nc_guard_unlock.c  保留在仓库、仍是冻结资产，但【不再进 NDK 工程】。
 *   nc_guard_boot.c    本文件 = 新的运行期入口，内含 unlock 本体的一份
 *                      实现（放在 .ncguard_head 段，构建期被锁成密文）。
 *   两份并存是刻意取舍：动 unlock.c 要破冻结纪律，而它已被真机验证过；
 *   本文件承接"可继续演进"的部分。unlock.c 自此是历史存档，不再维护。
 *
 * 三级结构（攻击面从外到内）：
 *   ① 明文 stub（.text）
 *       只做：读 slot → 验 magic → 恢复 k_stub → mprotect → XOR → 跳转
 *       ⚠️ 实测口径（2026-10-18，别照设计文档想象）：`ncg_stub_recover` 被
 *       -O2 内联进 `ncguard_unlock`，连同 `ncg_eq8`/`ncg_rd32`/XOR 循环一起，
 *       明文侧合计约 200 行反汇编 / 736 字节。我最初写"约 30 行一个分支"是
 *       乐观估计，实测达不到——内联把它撑大了。
 *       但内容仍是"无智力"的：没有 ELF 解析、没有 HMAC、没有 RC4 S 盒、
 *       没有 slot 布局解释。攻击者读完只知道"异或一段然后跳"。
 *   ② 密文 unlock 本体（.ncguard_head，构建期锁箱）
 *       完整能力：ELF 段表解析、HMAC 校验、RC4 解密、页权限管理
 *       实测锁定后 objdump 对该段无有效输出（密文）
 *   ③ 密文业务段（.ncguard，由 ② 负责解）
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
 *   本体发现 .nckey 无 magic → 返回 0。开发期不锁箱也能跑。
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

/* ── 契约常量：与 so-section-lock.py 共享，改一处必须同步另一侧 ── */
#define NCG_SECTION      ".ncguard"
#define NCG_SLOT         ".nckey"
#define NCG_HEAD         ".ncguard_head"
#define NCG_STUB_SLOT    ".nckey_stub"
#define NCG_SLOT_MAGIC   "NCKEYLOCK"
#define NCG_STUB_MAGIC   "NCSTUBLK"
#define NCG_SLOT_SIZE    80
#define NCG_STUB_SIZE    88

/* .nckey_stub slot 布局（88 字节，2026-10-18 P0-b 起；原 40 字节版见下方说明）：
 *   [ 0: 8) magic NCSTUBLK
 *   [ 8:24) wrapped k_stub      = k_stub ^ XOR_KEY
 *   [24:28) stub_sh_addr        .nckey_stub 自身链接期虚拟地址
 *   [28:32) head_sh_addr        .ncguard_head 链接期虚拟地址
 *   [32:36) head_size           .ncguard_head 字节数
 *   [36:40) reserved
 *   [40:56) wrapped k_mac_head  = k_mac_head ^ XOR_KEY   ← P0-b 新增
 *   [56:88) expect_mac_head     HMAC-SHA256(k_mac_head, head 密文) ← P0-b 新增
 *
 * 为什么 head 段也要 MAC（P0-b，补齐与 .ncguard 不对等的保护）：
 *   在此之前 head 段只有简单 XOR。攻击者可以改 head 密文中对应"unlock 本体的
 *   MAC 校验函数"的那几位 → 解密后 unlock 本体还在，但它对 .ncguard 的校验
 *   被改成恒真 → .ncguard 的 HMAC 保护被绕过。这是具体路径，不是理论风险。
 *   加 MAC 后：改任何一位 → HMAC 不符 → 不解密 → head 保持密文 →
 *   调用即 SIGILL（与 .ncguard 的 -11 语义完全对等）。
 *
 * MAC 对【密文】算，与 .ncguard 一致：解密前就能验，验不过就不装明文。 */
#define NCG_OFF_K_MAC_HEAD   40
#define NCG_OFF_EXPMAC_HEAD  56

/* ⚠️ 2026-10-18 与 LSGS 彻底分离（原值与 make-sig-log.py 的 key 相同，
 * 注释还写"与 LSGS 同源"——那是错的）：同一把 8 字节密钥此前同时护三处
 * （.ncguard 的 wrapped_k_so/wrapped_k_mac、.ncguard_head 的 wrapped_k_stub、
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
static const uint8_t NCG_XOR_FRAG[8] = {1, 0, 2, 3, 0, 1, 3, 2};

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
 * 第一部分：密文 unlock 本体（进 .ncguard_head，构建期被锁）
 * ═══════════════════════════════════════════════════════════════════ */

/* RC4 —— 与 so-section-lock.py 的 rc4() 逐字节同算法 */
__attribute__((section(NCG_HEAD), used, retain, noinline))
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
__attribute__((section(NCG_HEAD), used, retain, noinline))
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
__attribute__((section(NCG_HEAD), used, retain, noinline))
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

#define NCG_OFF_K_MAC   32
#define NCG_OFF_EXPMAC  48

/* ── unlock 本体主流程：解出 .ncguard 业务段 ──────────────────────
 * 由明文 stub 解密后才可调用（此前它是密文）。
 * 返回 0 成功；负值含义与 nc_guard_unlock.c 的码表一致。 */
__attribute__((section(NCG_HEAD), used, retain, noinline))
int ncg_head_unlock(void) {
    void *base;
    char so_path[512];
    if (ncg_resolve_self(&base, so_path, sizeof(so_path)) != 0) return -1;

    Elf64_Shdr sec, slot;
    if (ncg_find_section(so_path, NCG_SECTION, &sec) != 0) return -2;
    if (ncg_find_section(so_path, NCG_SLOT, &slot) != 0) return -3;
    if (sec.sh_size == 0) return -4;
    if ((sec.sh_flags & SHF_ALLOC) == 0) return -5;

    uint8_t slotdata[NCG_SLOT_SIZE];
    memset(slotdata, 0, sizeof(slotdata));
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -6;
    ssize_t got = pread(fd, slotdata, sizeof(slotdata), slot.sh_offset);
    close(fd);
    if (got < 32) return -7;
    if (memcmp(slotdata, NCG_SLOT_MAGIC, strlen(NCG_SLOT_MAGIC)) != 0) {
        return 0;   /* 未锁，无需解锁 */
    }
    int have_mac = (got >= NCG_SLOT_SIZE) && (slot.sh_size >= NCG_SLOT_SIZE);

    static int ncg_unlocked = 0;
    if (ncg_unlocked) return 0;

    uint8_t key[16];
    {
        uint8_t xk[8];
        ncg_xor_key(xk);
        for (int i = 0; i < 16; i++) key[i] = slotdata[16 + i] ^ xk[i & 7];
        memset(xk, 0, sizeof(xk));
    }

    uint8_t *target = (uint8_t *)base + sec.sh_addr;

    /* 完整性校验：先验后解（位置在 mprotect/解密之前） */
    if (have_mac) {
        uint8_t k_mac[16], got_mac[32];
        {
            uint8_t xk[8];
            ncg_xor_key(xk);
            for (int i = 0; i < 16; i++)
                k_mac[i] = (uint8_t)(slotdata[NCG_OFF_K_MAC + i] ^ xk[i & 7]);
            memset(xk, 0, sizeof(xk));
        }
        khmac_sha256(k_mac, 16, target, sec.sh_size, got_mac);
        const uint8_t *want = slotdata + NCG_OFF_EXPMAC;
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) diff |= (uint8_t)(got_mac[i] ^ want[i]);
        memset(k_mac, 0, sizeof(k_mac));
        memset(got_mac, 0, sizeof(got_mac));
        if (diff != 0) {
            memset(key, 0, sizeof(key));
            return -11;
        }
    }

    uintptr_t ps = getpagesize();
    uintptr_t s = (uintptr_t) target & ~(ps - 1);
    uintptr_t e = ((uintptr_t) target + sec.sh_size - 1 & ~(ps - 1)) + ps;
    if (mprotect((void *) s, e - s, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return -8;

    uint8_t *buf = (uint8_t *)malloc(sec.sh_size);
    if (!buf) return -9;
    ncg_rc4(key, 16, target, buf, sec.sh_size);
    memcpy(target, buf, sec.sh_size);
    free(buf);

    memset(key, 0, sizeof(key));
    memset(slotdata, 0, 16);

    __builtin___clear_cache((char *)target, (char *)(target + sec.sh_size));

    if (mprotect((void *) s, e - s, PROT_READ | PROT_EXEC) != 0) return -10;
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
__attribute__((section(NCG_STUB_SLOT), used, aligned(1), retain))
static const volatile unsigned char ncg_stub_slot[NCG_STUB_SIZE] = {0};

/* 手写 memcmp/memcpy：遵守"stub 不依赖 libc"的约束（-O2 下虽会内联，
 * 但写明意图，防止有人日后改成调用形式又把依赖引回来） */
static int ncg_eq8(const volatile unsigned char *a, const char *b) {
    for (int i = 0; i < 8; i++) if (a[i] != (unsigned char) b[i]) return 0;
    return 1;
}
static uint32_t ncg_rd32(const volatile unsigned char *p) {
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* 明文 stub：把 .ncguard_head 还原成明文。
 * 全程无循环展开以外的分支、无 libc 调用、无磁盘 I/O。
 * 未锁（slot magic 不匹配）时直接返回——段本就是明文。 */
static void ncg_stub_recover(void) {
    const volatile unsigned char *slot = ncg_stub_slot;

    if (!ncg_eq8(slot, NCG_STUB_MAGIC)) return;   /* 未锁 */

    static int recovered = 0;
    if (recovered) return;                         /* 本进程已解过 */

    /* 恢复 k_stub（16 字节，与 8 字节 XOR_KEY 循环异或） */
    uint8_t k[16];
    {
        uint8_t xk[8];
        ncg_xor_key(xk);
        for (int i = 0; i < 16; i++) k[i] = (uint8_t)(slot[8 + i] ^ xk[i & 7]);
        memset(xk, 0, sizeof(xk));
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
     * 密文 → 后续调用踩密文 = SIGILL（fail-closed，与 .ncguard 的 -11 语义
     * 完全对等）。此前 head 只有 XOR，攻击者可改"unlock 本体里的 MAC 校验
     * 函数"那几位，把 .ncguard 的 HMAC 保护改成恒真从而绕过。
     *
     * k_mac_head 的恢复与 k_stub 同源：都是 wrapped ^ NCG_XOR_KEY。
     * 调用 khmac_sha256 不破坏"stub 无智力"约束——它只是复用 .text 里
     * 现成的密码学原语（nc_guard_key.c 的函数全在明文段），stub 本身仍没有
     * ELF 解析、没有 RC4 S 盒、没有密钥派生、没有 slot 布局解释。 */
    uint8_t k_mac[16], got_mac[32];
    {
        uint8_t xk[8];
        ncg_xor_key(xk);
        for (int i = 0; i < 16; i++)
            k_mac[i] = (uint8_t)(slot[NCG_OFF_K_MAC_HEAD + i] ^ xk[i & 7]);
        memset(xk, 0, sizeof(xk));
    }
    khmac_sha256(k_mac, 16, start, head_size, got_mac);
    {
        const volatile unsigned char *want = slot + NCG_OFF_EXPMAC_HEAD;
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
    mprotect((void *) s, e - s, PROT_READ | PROT_WRITE | PROT_EXEC);

    for (uint32_t i = 0; i < head_size; i++) start[i] ^= k[i & 15];

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
    ncg_stub_recover();          /* 先确保 head 本体是明文 */
    int rc = ncg_head_unlock();  /* 再调本体解 .ncguard */
    if (rc == 0) done = 1;
    return rc;
}

/* so 加载即跑：先解 head 本体，再由本体解业务段。
 * 优先级 50：早于任何可能的其它 constructor，确保业务段在 App 代码前就绪。 */
__attribute__((constructor(50)))
static void ncg_boot_init(void) {
    (void) ncguard_unlock();
}
