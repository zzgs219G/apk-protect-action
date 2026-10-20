#!/usr/bin/env bash
# test-sig-verify.sh — sig_check.c 完整签名校验链路回归（host 端，真实 APK）
#
# 为什么必须存在（2026-10-21 事故，报错五十八口径）：
#   sig_block_magic 的 lsg_s 缓冲 16→应 17（少 1 字节 NUL）→ lsg_decode
#   判 "len+1 > buflen" 恒失败 → 返回 NULL → 所有正常包被判"无 v2/v3
#   签名块" → delayed_kill 误杀 → 真机全量闪退（tombstone 03:51 实锤）。
#   而当时 11 套回归全绿——因为【没有任何测试走 sig_check.c 的 APK
#   解析路径】：javacheck 对拍走 nc_link.c；lsgs 对拍只用正确缓冲。
#   "11 套绿"掩盖了"核心路径 0 覆盖"。
#
# 本测试用真实 APK 走完整链：EOCD → magic 比对（lsg_s 解码）→ v2/v3
# 解析 → SHA256 → 与 make-sig-hash.sh 生成的 sig_hash.h 对拍。
# APK 定位同 test-so-lock.sh（TEST_APK 环境变量 > 仓库样本 > 简盒目录）。
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tsv.XXXXXX" 2>/dev/null || mktemp -d "$HOME/.tsv.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $*" >&2; }
skip() { echo "  ⚠ $*（跳过）"; }

echo "=== sig_check.c 完整签名校验回归（$WORK）==="

# APK 定位（与 test-so-lock.sh 同优先级）
if [ -z "${TEST_APK:-}" ]; then
    for cand in /storage/emulated/0/简盒/*_sign.apk; do
        [ -f "$cand" ] && TEST_APK="$cand" && break
    done
fi
if [ -z "${TEST_APK:-}" ] || [ ! -f "${TEST_APK:-}" ]; then
    skip "无已签名 APK（TEST_APK=<已签名.apk> bash $0 指定）"
    echo "结果: 0 通过, 0 失败"; exit 0
fi
echo "  APK: $TEST_APK"

command -v clang >/dev/null || { skip "无 clang"; exit 0; }

SRC="$ROOT/scripts/sigcheck/src"
cp "$SRC/sig_check.c" "$SRC/env_check.c" "$SRC/nc_guard_layout.h" "$WORK/"
# sig_hash.h 由生成器产出（两张表含真值），本测试同时充当"生成器→C 侧"对拍
bash "$ROOT/scripts/sigcheck/hash/make-sig-hash.sh" "$TEST_APK" "$WORK/sig_hash.h" \
    >"$WORK/sighash.log" 2>&1 || { bad "sig_hash.h 生成失败"; tail -3 "$WORK/sighash.log" >&2; exit 1; }
python3 "$ROOT/scripts/sigcheck/log/make-sig-log.py" \
    "$SRC/sig_check.c" "$SRC/env_check.c" "$WORK/sig_log_data.h" >/dev/null 2>&1 \
    || { bad "sig_log_data.h 生成失败"; exit 1; }

cd "$WORK"

# ── T1 编译（SIGCHECK_HOST_TEST：走 sig_verify_test 纯逻辑入口）──
# 关键：SIGCHECK_TEST_APK 指向真 APK → find_apk_path 走宿主路径，其余逻辑
# 与真机完全同一条代码路径（EOCD→magic→v2/v3→SHA256→对拍）。
cat > driver.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>   /* sleep */
/* host 没有 liblog —— 提供 stub。日志同时落 stderr 便于失败时看。 */
int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)tag; (void)prio;
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    return 0;
}
extern void sig_verify_test(void);
int main(int argc, char **argv) {
    sig_verify_test();
    /* ⚠️ 校验失败的处置是【异步杀】（杀线程 sleep 1~2s 后 abort），
     * main 若立即返回，进程退出 = 杀线程陪葬 → 观察不到 SIGABRT。
     * 真机上是 App 常驻所以能看到 tombstone（2026-10-21 实锤）；
     * host 端复现该行为必须 main 挂住等它。
     * argv[1]=="wait" → 睡 15s：delayed_kill_2（缺省最重变体）的
     *   堆碎片化循环实测可耗 10s+（24~47 轮 × 每轮 20~139 次
     *   usleep 1~2.5ms）+ sleep(2~4s)。5s 不够（第一版实测踩过：
     *   rc=0，杀线程还没引爆 main 就退出了）。 */
    if (argc > 1 && argv[1][0] == 'w') sleep(15);
    return 0;
}
EOF
if clang -O1 -DSIGCHECK_HOST_TEST -I. \
        driver.c sig_check.c -o verify 2>build.log; then
    ok "T1 编译通过（含真实 sig_hash.h）"
else
    bad "T1 编译失败"; head -10 build.log >&2; exit 1
fi

# ── T2 完整校验链路：必须通过（解析失败会 abort → 非零退出）──
# SIGCHECK_TEST_LOG 指向文件以捕获 LSG 日志（debug 哨兵开 log）
export SIGCHECK_TEST_LOG="$WORK/sigcheck.log"
export SIGCHECK_TEST_APK="$TEST_APK"
if ./verify 2>&1; then
    ok "T2 完整链路通过（EOCD→magic(lsg_s 17B)→v2/v3→SHA256→对拍）"
else
    rc=$?
    bad "T2 签名校验失败（rc=$rc）——正是 2026-10-21 off-by-one 的暴露形态"
    echo "--- sigcheck 日志末尾（定位失败在哪一步）---" >&2
    tail -8 "$SIGCHECK_TEST_LOG" 2>/dev/null | sed 's/^/    /' >&2
    exit 1
fi

# ── T3 日志必须含"签名校验通过"（防"进程没崩但其实跳过了校验"）──
if grep -q "【通过】.*签名\|【成功】.*指纹" "$SIGCHECK_TEST_LOG" 2>/dev/null; then
    ok "T3 日志含签名校验通过（非静默跳过）"
else
    bad "T3 日志无通过记录——可能全零槽位跳过了校验"
    cat "$SIGCHECK_TEST_LOG" 2>/dev/null | tail -5 | sed 's/^/    /' >&2
    exit 1
fi

# ── T4 反向：篡改 sig_hash.h 的期望值 → 必须失败（防恒真）──
sed 's/0x[0-9a-f]\{2\}/0x00/g' sig_hash.h > sig_hash_zero.h
mv sig_hash.h sig_hash_real.h && mv sig_hash_zero.h sig_hash.h
# 全零槽位 = 调试模式跳过（设计行为），故反向测试改用"错误值"而非全零：
python3 - <<'PY'
s=open('sig_hash_real.h').read()
import re
# 把 SIG_HASH_STORED 每个字节 +1（必定与真实指纹不符）
# ⚠️ 数组声明是 [SIG_HASH_LEN] 宏形态，不是 [32] —— 正则按宏名匹配
def bump(m):
    vals=[int(x,16) for x in m.group(1).split(',') if x.strip()]
    vals=[(v+1)&0xff for v in vals]
    return 'SIG_HASH_STORED[SIG_HASH_LEN] = { ' + ', '.join('0x%02x'%v for v in vals) + ','
s2=re.sub(r'SIG_HASH_STORED\[SIG_HASH_LEN\] = \{([^}]*)', bump, s, count=1)
assert s2 != s, "篡改正则未命中 SIG_HASH_STORED"
open('sig_hash.h','w').write(s2)
PY
if clang -O1 -DSIGCHECK_HOST_TEST -I. \
        driver.c sig_check.c -o verify_bad 2>/dev/null; then
    # ⚠️ 失败路径是【异步杀】：sig_verify 判定失败 → 起杀线程（sleep 1~3s
    #    后 abort）→ 主线程照常返回 → main 退出码 0。所以不能只看退出码，
    #    必须等杀线程引爆（delayed_kill 的 abort 会让进程以 SIGABRT 终止，
    #    bash 里表现为 rc=134）。timeout 10s 兜底防挂。
    # ⚠️ 必须 `|| true`：预期内的 SIGABRT(rc=134) 会让 set -e 直接终止脚本
    #    （实测：Aborted 打出来但"结果"行永远到不了）。
    rc=0
    SIGCHECK_TEST_APK="$TEST_APK" timeout 20 ./verify_bad wait >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
        bad "T4 篡改期望值仍通过——校验恒真（严重！）"
        exit 1
    elif [ "$rc" -ge 128 ] || [ "$rc" -eq 134 ]; then
        ok "T4 篡改期望值 → 延时杀触发（rc=$rc，判定真实有效非恒真）"
    else
        ok "T4 篡改期望值 → 校验失败（rc=$rc，非零即有效）"
    fi
else
    skip "T4 篡改版编译失败，跳过"
fi

echo
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
