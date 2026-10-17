#pragma once
#include <stdint.h>
#include <stddef.h>

/* nc_guard_key.c 的对外接口：SHA-256 / HMAC / HKDF / APK 证书 DER / K_so 派生
 * 与 scripts/lib/so-section-lock.py 的派生规则逐字节一致（契约，改一侧必须同步另一侧）。 */

/* SHA-256（实现照抄 sig_check.c 已验证版本；此处只暴露不透明句柄） */
typedef struct ksha_ctx_s ksha_ctx;

void ksha_init(ksha_ctx *ctx);
void ksha_update(ksha_ctx *ctx, const uint8_t *data, size_t len);
void ksha_final(ksha_ctx *ctx, uint8_t out[32]);

/* HMAC-SHA256（RFC 2104） */
void khmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* HKDF-SHA256（RFC 5869，与 so-section-lock.py 的 hkdf_sha256() 同算法） */
void khkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                  const uint8_t *salt, size_t salt_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len);

/* 从 APK 提取第一签名者证书 DER（只读 EOCD/CD/Signing Block，几十 KB）。
 * v3 优先，回退 v2。der 需 ≥ 4096；返回 0 成功。 */
int ncg_apk_first_cert_der(const char *apk_path, uint8_t *der, size_t der_cap,
                           size_t *der_len);

/* k_so = HKDF-SHA256(ikm=master, salt=SHA256(certDER), info="nc-so-v1"+pkg, 16) */
int ncg_derive_k_so(const uint8_t master[32], const uint8_t cert_sha256[32],
                    const char *pkg, uint8_t out[16]);
