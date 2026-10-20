#pragma once
#include <stdint.h>
#include <stddef.h>

/* so 段加密设施（全项目共用）的密钥派生接口：SHA-256 / HMAC / HKDF /
 * APK 证书 DER / K_so / K_mac 派生。
 * 与 scripts/lib/so-section-lock.py 的派生规则逐字节一致（契约，改一侧必须同步另一侧）。
 *
 * ⚠️ 2026-10-18 定位重构：文件名仍叫 nc_guard_key.c（改名会动冻结清单、牵连
 * 回归测试，收益不抵风险），但它是【设施层】而非某个模块的私有代码：
 *   第1层 段加密服务：本文件 + nc_guard_unlock.c + so-section-lock.py
 *   第2层 通用标记器：so_section_mark.py（规则=函数头正则）
 *   第3层 消费者：sigcheck 探针 / ncguard_probe / dex2c 转译产物 / 未来模块
 */

/* SHA-256（实现照抄 sig_check.c 已验证版本；此处只暴露不透明句柄） */
typedef struct ksha_ctx_s ksha_ctx;

void ksha_init(ksha_ctx *ctx);
void ksha_update(ksha_ctx *ctx, const uint8_t *data, size_t len);
void ksha_final(ksha_ctx *ctx, uint8_t out[32]);

/* SHA-256 一步到位（吃完整消息，出 32 字节）。
 * 2026-10-19 新增：ksha_ctx 在 .h 里是不透明句柄，密文段里的调用方
 * （包名指纹校验）开不出栈对象。与 ksha_init/update/final 三步等价。 */
void ksha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* HMAC-SHA256（RFC 2104） */
void khmac_sha256(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len, uint8_t out[32]);

/* 增量 HMAC（2026-10-19）：分段喂消息，用于 MAC 覆盖多个不连续段。
 *
 * 为什么需要它：.ncx 与 .ncxr 是两个不连续的 ELF 段，
 * 一次性算 HMAC 得先把两段拼进临时缓冲（最多几十 KB malloc + memcpy）。
 * 增量式零额外内存、零拷贝。
 * 语义与 khmac_sha256(k,m1||m2) 完全等价（对拍测试钉死）。
 * 用法：init → update* → final。ctx 由调用方在栈上开（不透明类型，见下）。 */
typedef struct khmac_ctx_s khmac_ctx;
void khmac_init(khmac_ctx *ctx, const uint8_t *key, size_t key_len);
void khmac_update(khmac_ctx *ctx, const uint8_t *data, size_t len);
void khmac_final(khmac_ctx *ctx, uint8_t out[32]);

/* 增量 HMAC 的上下文尺寸（构造期断言用；调用方需按此开栈对象）。
 * ⚠️ 与 nc_guard_key.c 的 struct khmac_ctx_s 保持一致——改一处必须改另一处，
 *    下面的 static_assert 在编译期把关，不一致会直接编译失败（好事）。 */
#define KHMAC_CTX_SIZE   256   /* 实际 88+88+32 = 208，留余量防将来扩字段 */
#define KHMAC_CTX_ALIGN  8

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

/* 便捷版：直接吃 certDER，内部做 SHA256(certDER) 再 HKDF。
 * 2026-10-19 新增：运行期证书派生（P1-a）需要它——ksha_ctx 是不透明句柄，
 * 调用方在栈上开不出对象（head 本体是密文段里的代码，必须尽量小）。
 * 与 ncg_derive_k_so(master, SHA256(der), pkg, out) 逐字节等价。 */
int ncg_derive_k_so_from_der(const uint8_t master[32],
                             const uint8_t *cert_der, size_t der_len,
                             const char *pkg, uint8_t out[16]);

/* 同上的 mac 域版本（label "nc-so-mac-v1"）。
 * 2026-10-19 P1-a：运行期 k_mac 也改为证书派生，不再从 slot 读——
 * slot 里的 wrapped_k_mac 等于把完整性密钥交给攻击者。 */
int ncg_derive_k_mac_from_der(const uint8_t master[32],
                              const uint8_t *cert_der, size_t der_len,
                              const char *pkg, uint8_t out[16]);

/* k_mac = HKDF-SHA256(..., info="nc-so-mac-v1"+pkg, 16)
 * 2026-12 完整性校验专用域，只参与 .ncx 密文的 HMAC 计算。
 * ⚠️ 与 k_so 必须用不同 label —— 复用同一把钥匙等于"知道 RC4 密钥就能
 * 伪造 MAC"，校验形同虚设。改 label 必须同步 so-section-lock.py 的
 * derive_app_keys()（本轮已用真证书对拍验证两侧逐字节一致）。
 *
 * 2026-10-20 更正一处过期表述：本函数【有调用方】。早期注释写
 * "当前无调用方（unlock 走 slot 里的 wrapped_k_mac），它是契约证明"，
 * 那是在 P1-a 之前的口径。P1-a 起 k_mac 改为运行期从证书派生，
 * nc_guard_boot.c:591 调 ncg_derive_k_mac_from_der()，它内部调本函数。
 * 同理 ncg_derive_k_so() 由 ncg_derive_k_so_from_der() 调用
 * （boot.c:533），也不是无调用方。 */
int ncg_derive_k_mac(const uint8_t master[32], const uint8_t cert_sha256[32],
                     const char *pkg, uint8_t out[16]);
