/* ncguard-unlock.c — 运行期"开箱"：原地解密 .ncguard 段
 *
 * 与 scripts/lib/so-section-lock.py（构建期"锁箱"）配套。
 * 抄自 XopProtector crypto/section_decrypt.cpp，剥离其 6 个私有模块依赖
 * （hook/risk/so_guard/business_so/apk_sign/runtime_state），只保留
 * ELF 段定位 + RC4 解密 + mprotect + clear_cache 四件事。
 *
 * 用法：在 JNI_OnLoad 或 so constructor 里调一次 ncguard_unlock()。
 *       必须在任何 .ncguard 段的函数被调用之前。
 *
 * 密钥来源：.nckey 段的 slot = magic(16) + wrapped(16)。
 *   wrapped = k_so ^ XOR_KEY， recover 后就是 HKDF 派生的 so 域密钥。
 *   Xop 用 HKDF(master, cert_sha256, "nc-so-v1"+package)——本实现把
 *   derive_app_keys 内联进来，避免依赖 key_ladder。
 */
#include <elf.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dlfcn.h>

#include "nc_guard_key.h"   /* khmac_sha256：完整性校验用，见下方 -11 分支 */

/* ── 契约常量：与 so-section-lock.py 共享，改一处必须同步另一处 ── */
#define NCG_SECTION   ".ncguard"
#define NCG_SLOT      ".nckey"
#define NCG_SLOT_MAGIC "NCKEYLOCK"
#define NCG_SLOT_SIZE  80    /* magic(16)+wrapped_k_so(16)+wrapped_k_mac(16)+expect_mac(32) */

/* .nckey slot 布局（2026-12，与 so-section-lock.py 文件头的图逐字节一致）：
 *   [ 0:16) magic NCKEYLOCK
 *   [16:32) k_so  ^ XOR_KEY
 *   [32:48) k_mac ^ XOR_KEY   ← 本轮新增
 *   [48:80) expect_mac        ← HMAC-SHA256(k_mac, 密文)
 * ⚠️ 关于"向后兼容"的诚实口径：so-section-lock.py 的 lock() 有
 *   assert len(blob) == slot['size']，所以 .nckey 只有 32 字节的旧 so
 *   会在【构建期】就直接 AssertionError 失败，根本产不出工件。
 *   因此下面 have_mac 的降级分支在正常流水线下不可达——它保留是
 *   defense-in-depth：防手工构造/裁剪过的畸形 so 把 .nckey 之后 48 字节
 *   （那是别的段的数据）当成期望 MAC，从而误判 -11 把自己锁死。 */
#define NCG_OFF_K_MAC   32
#define NCG_OFF_EXPMAC  48

static const uint8_t NCG_XOR_KEY[8] =
        {0x5A, 0xC3, 0x11, 0x9E, 0xF0, 0x37, 0xB2, 0x6D};

/* page-align helper */
#define NCG_PAGE_START(p) ((uintptr_t)(p) & ~(uintptr_t)(getpagesize() - 1))

static int ncg_page_mprotect(void *start, void *end, int prot) {
    uintptr_t s = NCG_PAGE_START(start);
    uintptr_t e = NCG_PAGE_START((uintptr_t)end - 1) + (uintptr_t)getpagesize();
    return mprotect((void *)s, e - s, prot);
}

/* RC4 —— 与 so-section-lock.py 的 rc4() 逐字节同算法 */
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

/* 在 ELF 文件里按名字找段（运行时从磁盘副本读，dladdr 拿内存基址） */
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

    /* 段名字符串表 */
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

/* so 路径解析：dladdr(&ncguard_unlock) 拿基址与路径 */
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

/* ── 从 slot 恢复 K_so：wrapped ^ XOR_KEY ──────────────────────────
 * 2026-12 证书绑定后的完整链路：
 *   锁箱侧 so-section-lock.py：k_so = HKDF(master, SHA256(certDER), "nc-so-v1"+pkg)
 *                              → slot 存 k_so ^ XOR_KEY（wrapped）
 *   解锁侧（本函数）        ：wrapped ^ XOR_KEY 得回 k_so → RC4 解密
 * 这样 C 侧【不需要读 APK / 不提证书】（省 I/O、不拖冷启动，这是对
 * XopProtector「运行期读 APK」的刻意偏离——我们用构建期派生替代），
 * 同时证书绑定依然成立：换 key 重打包 → cert 变 → k_so 变 → slot 里的
 * wrapped 与新 k_so 不符 → 解密得到乱 C → 探针 SIGILL（fail-closed）。 */
static void ncg_recover_key(const uint8_t slot32[32], uint8_t k[16]) {
    for (int i = 0; i < 16; i++) k[i] = slot32[16 + i] ^ NCG_XOR_KEY[i & 7];
}

/* 主入口：原地解密 .ncguard。返回 0 成功，负值失败（调用方应 abort）。 */
int ncguard_unlock(void) {
    void *base;
    char so_path[512];
    if (ncg_resolve_self(&base, so_path, sizeof(so_path)) != 0) return -1;

    Elf64_Shdr sec, slot;
    if (ncg_find_section(so_path, NCG_SECTION, &sec) != 0) return -2;
    if (ncg_find_section(so_path, NCG_SLOT, &slot) != 0) return -3;
    if (sec.sh_size == 0) return -4;
    if ((sec.sh_flags & SHF_ALLOC) == 0) return -5;

    /* slot 校验：magic 必须匹配，否则视为未锁/已解锁（幂等返回 0）
     * 读 80 字节（新版布局）；旧版 so 的 .nckey 只有 32 字节 → pread 只回
     * 32，下面走"跳过 MAC"降级路径（旧槽没有 k_mac/expect_mac 可验）。 */
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

    /* ⚠️ 内存级幂等：本函数可能被调用两次（Java 侧 NcLink.selftest() 与
     * env_check_entry 的 constructor 各一次）。此前靠 pwrite 擦磁盘 magic
     * 来防重入，但那会破坏 MAP_PRIVATE 的 .text 映射导致 SIGILL（见下方
     * 注释）。改用 static 标志：已解锁过就直接返回 0。
     * 进程内有效；跨进程由磁盘 magic 天然保证（新进程读到的还是密文）。 */
    static int ncg_unlocked = 0;
    if (ncg_unlocked) {
        return 0;
    }

    uint8_t key[16];
    ncg_recover_key(slotdata, key);

    uint8_t *target = (uint8_t *)base + sec.sh_addr;

    /* ── 完整性校验：先验后解（2026-12 追加）───────────────────────
     * 对【内存里的密文】算 HMAC-SHA256，与 slot 里的期望值逐字节比。
     * 位置刻意选在 mprotect/解密【之前】：一旦不符，.ncguard 一个字都
     * 不会被改动 → 段保持密文状态 → 后续调用踩密文 = SIGILL（fail-closed）。
     * 若放到解密之后，篡改的明文已经生效，晚一步。
     * 为什么值得做：RC4 是流密码，改密文 1 位只翻明文 1 位，未必崩溃；
     * 没有 MAC 时攻击者可以"改一位→跑→看行为"做廉价 oracle，把 4012
     * 字节反推出来。有了 MAC，第一次试探就暴露，且暴露方式是"整段失效"。
     * 恒定时间比较：防时序侧信道（不提前退出的 memcmp 自己写）。 */
    if (have_mac) {
        uint8_t k_mac[16], got_mac[32];
        for (int i = 0; i < 16; i++)
            k_mac[i] = (uint8_t)(slotdata[NCG_OFF_K_MAC + i] ^ NCG_XOR_KEY[i & 7]);
        khmac_sha256(k_mac, 16, target, sec.sh_size, got_mac);
        const uint8_t *want = slotdata + NCG_OFF_EXPMAC;
        uint8_t diff = 0;
        for (int i = 0; i < 32; i++) diff |= (uint8_t)(got_mac[i] ^ want[i]);
        memset(k_mac, 0, sizeof(k_mac));
        memset(got_mac, 0, sizeof(got_mac));
        if (diff != 0) {
            /* -11 = 密文段被改过（或密钥与密文不匹配）。
             * 不解密、不动 mprotect —— 段保持密文，调用方拿到可判读的码。 */
            memset(key, 0, sizeof(key));
            return -11;
        }
    }

    if (ncg_page_mprotect(target, target + sec.sh_size,
                          PROT_READ | PROT_WRITE | PROT_EXEC) != 0) return -8;

    uint8_t *buf = (uint8_t *)malloc(sec.sh_size);
    if (!buf) return -9;
    ncg_rc4(key, 16, target, buf, sec.sh_size);
    memcpy(target, buf, sec.sh_size);
    free(buf);

    /* 擦敏感材料 */
    memset(key, 0, sizeof(key));
    memset(slotdata, 0, 16);

    /* ⚠️ 不要在运行时 pwrite 回写磁盘 slot！
     * 2026-10-17 真机实测：解锁成功后 pwrite 清零磁盘 magic 后，进程随即
     * SIGILL（PC 0x958c 落在 .text 尾部，ILL_ILLOPC）。根因是 so 的 .text
     * 是 MAP_PRIVATE 文件映射，pwrite 修改被映射文件会让同页映射失效/数据
     * 不一致 —— 而 .ncguard 与 .text 尾部共享同一页（0x95f4 起，页首 0x9000
     * 含 104 字节 .text），于是 .text 被连带破坏。
     * 幂等改由 nc_guard_jni.c 的原子守门（ncg_selftest_done）保证；
     * 本函数不再碰磁盘。slot 里的 wrapped 密钥留在磁盘也无妨 —— 它是密文，
     * 且 cert 绑定后换 key 重打包即失效。 */
    memset(key, 0, sizeof(key));
    memset(slotdata, 0, 16);

    __builtin___clear_cache((char *)target, (char *)(target + sec.sh_size));

    if (ncg_page_mprotect(target, target + sec.sh_size,
                          PROT_READ | PROT_EXEC) != 0) return -10;
    ncg_unlocked = 1;
    return 0;
}
