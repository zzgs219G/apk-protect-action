/*
 * test-nclink.c — nc_verify_t1 判决逻辑宿主验证(clang 编译,无 NDK 依赖)。
 * 输入向量由 test-javacheck.sh 的 python 侧按与 make-sig-hash.sh 相同的公式生成:
 *   fp = 32B(确定性伪随机) → t1 = SHA256(fp) → stored[i] = t1[i]^salt[i%16]^(i*0x9E&0xFF)
 * 场景:正确 t1 → 通过;翻转 1 位 → 不过;长度 31 → 不过;NULL → 不过。
 * 另有全零槽位变体(调试模式)单独编译运行:任意输入 → 通过(跳过)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int nc_verify_t1(const unsigned char *t1, int len);

static unsigned char *slurp(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror(path); exit(2); }
    unsigned char *buf = malloc(64);
    size_t n = fread(buf, 1, 64, fp);
    fclose(fp);
    if (n != 32) { fprintf(stderr, "vector size %zu != 32\n", n); exit(2); }
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: test-nclink <good.bin> <bad.bin> [debug-skip]\n"); return 2; }
    unsigned char *good = slurp(argv[1]);
    unsigned char *bad = slurp(argv[2]);
    /* debug-skip 模式:SIG_HASH_STORED 全零(调试模式),任意输入都应放行 */
    int debug_skip = (argc > 3 && strcmp(argv[3], "debug-skip") == 0);
    int fail = 0;

    if (nc_verify_t1(good, 32) != 1) { printf("FAIL: correct t1 rejected\n"); fail = 1; }
    if (nc_verify_t1(bad, 32) != (debug_skip ? 1 : 0)) {
        printf("FAIL: tampered t1 %s\n", debug_skip ? "rejected(debug 应放行)" : "accepted");
        fail = 1;
    }
    if (!debug_skip && nc_verify_t1(good, 31) != 0) { printf("FAIL: short length accepted\n"); fail = 1; }
    if (!debug_skip && nc_verify_t1(good, 33) != 0) { printf("FAIL: long length accepted\n"); fail = 1; }
    if (nc_verify_t1(NULL, 32) != 0) { printf("FAIL: NULL accepted\n"); fail = 1; }

    free(good); free(bad);
    printf(fail ? "❌ nc_verify_t1 判决测试失败\n"
                : "✅ nc_verify_t1 判决测试通过(正确/篡改/异形/NULL%s)\n",
           debug_skip ? "/调试模式全零槽位放行" : "");
    return fail;
}
