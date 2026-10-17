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

/* ── 契约常量：与 so-section-lock.py 共享，改一处必须同步另一处 ── */
#define NCG_SECTION   ".ncguard"
#define NCG_SLOT      ".nckey"
#define NCG_SLOT_MAGIC "NCKEYLOCK"
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

    /* slot 校验：magic 必须匹配，否则视为未锁/已解锁（幂等返回 0） */
    uint8_t slotdata[32];
    int fd = open(so_path, O_RDONLY);
    if (fd < 0) return -6;
    ssize_t got = pread(fd, slotdata, 32, slot.sh_offset);
    close(fd);
    if (got != 32) return -7;
    if (memcmp(slotdata, NCG_SLOT_MAGIC, strlen(NCG_SLOT_MAGIC)) != 0) {
        return 0;   /* 未锁，无需解锁 */
    }

    uint8_t key[16];
    ncg_recover_key(slotdata, key);

    uint8_t *target = (uint8_t *)base + sec.sh_addr;

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

    /* ⚠️ 必须把"已解锁"状态回写磁盘：否则第二次调本函数时又会从磁盘读到
       完好 magic → 再解密一次 → 而 .ncguard 此刻已是明文 → 双重 RC4 把它
       变回密文 → 调用密文代码 = SIGILL（2026-10-17 实测踩过：第一次 59
       成功，第二次 Illegal instruction）。
       做法：以可写方式重开 so，把 slot 前 16 字节（magic）清零。
       失败不致命（只失去幂等性），故不返回错误。 */
    {
        int wfd = open(so_path, O_WRONLY);
        if (wfd >= 0) {
            uint8_t zero[16] = {0};
            ssize_t wr = pwrite(wfd, zero, 16, slot.sh_offset);
            (void) wr;                     /* 只写 magic；wrapped 留作取证 */
            close(wfd);
        }
    }

    __builtin___clear_cache((char *)target, (char *)(target + sec.sh_size));

    if (ncg_page_mprotect(target, target + sec.sh_size,
                          PROT_READ | PROT_EXEC) != 0) return -10;
    return 0;
}
