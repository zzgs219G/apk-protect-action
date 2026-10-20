/* nc_guard_layout.h — so 段加密设施的【唯一契约真相源】
 *
 * 本文件不含任何逻辑，只有契约常数。存在的唯一目的：
 *   把"改一处必须同步另一处"从注释变成编译期/构建期强制。
 *
 * 为什么需要它（2026-10-20 立项背景）：
 *   契约常数此前散落 4 种语言、7 个文件、24 处副本。slot 已扩过两次
 *   （80→96、88→104），下次一定还会扩；漏同步任何一处的症状是
 *   【运行期 SIGILL】，Java 侧只看到 selftest != 59，没有任何线索
 *   指向"某个长度常量没同步"——这类问题排查成本是半天量级。
 *   仓库历史报错三/九/十一/十二全是同类根因。
 *
 * ⚠️ 纪律：改本文件任何常量，必须跑
 *      bash scripts/lib/tests/test-so-lock.sh
 *   其中 T20 用 Python 从本文件抽取，与 so-section-lock.py 的本地常量
 *   逐字节对拍；T21 扫描全仓段名字面量（未登记即失败）；T22 验证改动
 *   不改变产物字节。三项任一红 = 构建期 fail-fast，而不是运行期 SIGILL。
 *
 * ⚠️ 本文件会被拷进 NDK 工程（protect.sh 的拷贝清单），故不得 include
 *    仓库内其它头文件，保持零依赖、任何工具链都能编。
 */
#ifndef _NC_GUARD_LAYOUT_H_
#define _NC_GUARD_LAYOUT_H_

/* ═══════════════════════════════════════════════════════════════════
 * 一、段名（6 个）
 * ═══════════════════════════════════════════════════════════════════
 * 2026-10-19 中性化改名（旧名 → 新名）：
 *   .ncguard         → .ncx      .ncguard_ro      → .ncxr
 *   .ncguard_head    → .ncxh     .ncguard_head_ro → .ncxhr
 *   .nckey           → .nck      .nckey_stub      → .ncks
 * 改名理由：旧名自解释（ncguard/nckey 一眼看出机制），readelf -S
 * 即可列举出全部加固结构。
 *
 * ⚠️ 段名是 so 的指纹特征。改名会让所有历史产物的锁箱/开箱契约失效，
 *    故 2026-10-19 之后不再变动。要加新段，先在 T21 登记。
 *
 * 消费方（改名前同步检查这些位置）：
 *   C:    nc_guard_boot.c / nc_link.c / env_check.c / sig_check.c /
 *         nc_guard_probe.c
 *   Py:   so-section-lock.py / so_section_mark.py
 *   Sh:   make-sig-hash.sh（生成 sig_hash.h 的段属性宏）/ protect.sh
 */
#define NC_SEC_CODE      ".ncx"    /* 加密代码段（AXR，可执行）*/
#define NC_SEC_CONST     ".ncxr"   /* 加密常量表段（AWR，不可执行）*/
#define NC_SEC_HEAD      ".ncxh"   /* unlock 本体（二级锁箱对象）*/
#define NC_SEC_HEADRO    ".ncxhr"  /* master 数据段（AWR，32B）*/
#define NC_SEC_SLOT      ".nck"    /* 一级密钥槽*/
#define NC_SEC_STUBSLOT  ".ncks"   /* 二级 stub 密钥槽*/

/* ═══════════════════════════════════════════════════════════════════
 * 二、.nck 一级密钥槽：96 字节
 * ═══════════════════════════════════════════════════════════════════
 * 布局（偏移为相对 slot 起始的字节数）：
 *   [ 0:16) magic        seed + 8 个 0
 *   [16:32) decoy        诱饵（P1-a 起非真密钥，真 k_so 由运行期证书派生）
 *   [32:48) decoy_mac    诱饵（同上）
 *   [48:80) expect_mac   HMAC-SHA256(k_mac, 密文) 32B
 *   [80:88) pkg_sha8     SHA256(包名) 前 8 字节
 *   [88:96) reserved     对齐预留
 *
 * 锁箱侧：so-section-lock.py lock() 的 blob 组装
 * 开箱侧：nc_guard_boot.c ncg_head_unlock()
 * C 侧段本体：nc_guard_probe.c 的 ncg_key_slot[NC_SLOT_SIZE]
 */
#define NC_SLOT_SIZE      96
#define NC_OFF_EXPMAC     48   /* [48:80) expect_mac 起点*/
#define NC_OFF_PKG_SHA    80   /* [80:88) 包名指纹起点*/

/* ═══════════════════════════════════════════════════════════════════
 * 三、.ncks 二级 stub 密钥槽：104 字节
 * ═══════════════════════════════════════════════════════════════════
 * 布局：
 *   [ 0: 8) magic seed
 *   [ 8:24) wrapped k_stub      = k_stub ^ XOR_KEY
 *   [24:28) stub_sh_addr        .ncks 段自身链接期虚拟地址
 *   [28:32) head_sh_addr        .ncxh 链接期虚拟地址
 *   [32:36) head_size           .ncxh 字节数
 *   [36:40) code_addr           .text 段起始（自绑定 CRC 区间起点）
 *   [40:44) code_len            .text 段长度
 *   [44:48) reserved
 *   [48:64) wrapped k_mac_head  = k_mac_head ^ XOR_KEY
 *   [64:96) expect_mac_head     HMAC-SHA256(k_mac_head, head 密文)
 *   [96:100) head_ro_addr       .ncxhr 段链接期虚拟地址
 *   [100:104) head_ro_size      该段字节数
 *   [104:112) frag[4]           XOR_KEY 碎片（构建期随机，见 NC_OFF_FRAGS）
 *
 * 锁箱侧：so-section-lock.py lock_head() 的 blob 组装 + 两条 assert
 * 开箱侧：nc_guard_boot.c 明文 stub（ncg_stub_recover / ncguard_unlock）
 * C 侧段本体：nc_guard_boot.c 的 ncg_stub_slot[NC_STUB_SIZE]
 */
#define NC_STUB_SIZE        112   /* 2026-10-21 104→112：[104:112) 碎片区 */
/* 碎片区（2026-10-21）：XOR_KEY 的 4 个 uint16，构建期随机生成。
 * 为什么挪进 slot：原放 .data（ncg_frag_a/b/c/d volatile 常量），
 * 攻击者 objdump 读 .data + 反汇编拼回逻辑即可重组（破解复盘实测
 * "5 分钟拿到 XOR_KEY"）。挪进 slot 后：
 *   · .data/.rodata 不再有真碎片（留诱饵，见 boot.c）
 *   · 碎片每次构建随机（diff 两个 so 无法识别碎片）
 *   · 与 wrapped_k_stub 同住 slot——攻击者必须先读懂 slot 布局
 *     （壳的核心格式）才有重组输入，把"读常量"变成"读格式" */
#define NC_OFF_FRAGS        104   /* [104:112) 4×uint16 碎片（随机）*/
#define NC_OFF_CODE_ADDR    36   /* 代码自绑定 CRC 区间起始*/
#define NC_OFF_CODE_LEN     40   /* 区间长度（字节）*/
#define NC_OFF_K_MAC_HEAD   48   /* wrapped k_mac_head 起点*/
#define NC_OFF_EXPMAC_HEAD  64   /* expect_mac_head 起点*/
#define NC_OFF_HEADRO_ADDR  96   /* .ncxhr 段链接期虚拟地址*/
#define NC_OFF_HEADRO_SIZE 100   /* .ncxhr 段字节数*/

/* ═══════════════════════════════════════════════════════════════════
 * 四、magic 种子（8 字节）
 * ═══════════════════════════════════════════════════════════════════
 * 语义：slot 前 8 字节 == 本 seed ⇒ 已锁箱；不匹配 ⇒ 未锁，放行。
 * 锁箱器落盘的就是 seed 本身（不是 seed ^ XOR_KEY），运行期直接逐字节比。
 *
 * ⚠️ 真实收益仅一条：strings 搜不到 "NCKEYLOCK"/"NCSTUBLK" 字面量。
 *    碎片密钥【不参与】magic 比较（见 ncg_magic_ok：只做 got[i]^seed[i]
 *    累或）——它只在 ncg_xor_key() 里用于恢复 k_stub / k_mac_head。
 *    攻击者 dump 到 slot 前 8 字节即可直接比对，零额外成本。
 *    写清楚这条是防止后人据此高估防御强度、少做别的加固。
 */
#define NC_SEED_SLOT_INIT \
    { 0x30, 0x72, 0xEE, 0x48, 0x91, 0xDE, 0x04, 0xB5 }
#define NC_SEED_STUB_INIT \
    { 0x30, 0x72, 0xF6, 0x59, 0x9D, 0xD0, 0x07, 0xBD }

/* ═══════════════════════════════════════════════════════════════════
 * 五、XOR_KEY 碎片表
 * ═══════════════════════════════════════════════════════════════════
 * 完整 8 字节 XOR_KEY 由 4 个 volatile uint16 在运行期拼回
 * （见 nc_guard_boot.c 的 ncg_xor_key()）。
 * 本表是"逻辑字节 i 取哪个碎片"的映射；i<4 取低位、i>=4 取高位。
 *
 * ⚠️ 与 so-section-lock.py 的 XOR_KEY 必须逐字节一致（T20 对拍）。
 *    碎片常量本体（ncg_frag_a/b/c/d）刻意【不】进本文件——它们是运行期
 *    才知道的值，集中放一个表就等于把它们重新聚成一串可被一次性读走的
 *    常量。分散在 volatile 变量里正是为了阻止编译期折叠与集中读取。
 */
#define NC_XOR_FRAG_INIT \
    { 1, 0, 2, 3, 0, 1, 3, 2 }

/* ═══════════════════════════════════════════════════════════════════
 * 六、编译期自检
 * ═══════════════════════════════════════════════════════════════════
 * 这几条 _Static_assert 挡的是"偏移重叠/越界"类手误——那是上一轮
 * 88→104 扩容时最危险的错误模式（新字段与既有 MAC 字段重叠会
 * 【静默】破坏校验，编译期完全不报）。 */
_Static_assert(NC_OFF_EXPMAC + 32 <= NC_SLOT_SIZE,
               "NC_OFF_EXPMAC+32 溢出 .nck slot");
_Static_assert(NC_OFF_PKG_SHA + 8 <= NC_SLOT_SIZE,
               "NC_OFF_PKG_SHA+8 溢出 .nck slot");
_Static_assert(NC_OFF_HEADRO_SIZE + 4 <= NC_STUB_SIZE,
               "NC_OFF_HEADRO_SIZE+4 溢出 .ncks slot");
_Static_assert(NC_OFF_EXPMAC_HEAD + 32 <= NC_OFF_HEADRO_ADDR,
               "expect_mac_head 与 head_ro 字段重叠");
_Static_assert(NC_OFF_K_MAC_HEAD + 16 <= NC_OFF_EXPMAC_HEAD,
               "k_mac_head 与 expect_mac_head 重叠");
_Static_assert(NC_OFF_FRAGS + 8 <= NC_STUB_SIZE,
               "碎片区溢出 .ncks slot");

#endif /* _NC_GUARD_LAYOUT_H_ */
