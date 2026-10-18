#!/usr/bin/env bash
# test-mem-readable.sh — env_mem_readable 跨映射判定回归
#
# 为什么需要它：外部实测报告 §13.1 实测「改了 3 处 .text 字节，
# 完整性校验仍报 clean」。根因不是校验算法错，而是 env_mem_readable
# 要求整个区间落在【同一条】/proc/self/maps 记录里。
#
# 而 .text 常与 .eh_frame/.rodata 尾部【同页】（实测 CI 产物：
# .eh_frame 0x18478..0x200f4、.text 0x20100..0x46c18，同在页 0x20000），
# ld.so 会把该页拆成 r--p 与 r-xp 两条映射 → .text 天然跨两条记录 →
# 旧判断 `end <= e` 恒假 → 探针"读不到内存"就直接放弃校验（返回 0）。
#
# 本测试用真实布局复现该场景，钉死修复后的行为。
#
# 用法：bash scripts/sigcheck/tests/test-mem-readable.sh
set -uo pipefail

PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  ✓ $*"; }
bad() { FAIL=$((FAIL+1)); echo "  ✗ $*" >&2; }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/tmr.XXXXXX" 2>/dev/null \
       || mktemp -d "$HOME/.tmr.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/t.c" <<'EOF'
/* 从 env_check.c 抽取的判定逻辑（保持逐字一致，改生产代码必须同步这里）。
 * 不直接 include env_check.c：那文件依赖 android/log.h 与大量平台头，
 * 宿主端编不动；而这里要测的只是一个纯函数。 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct { unsigned long s, e; char perms[8]; } rec;

static int env_mem_readable_sim(const rec *rs, int n, uintptr_t addr, size_t len) {
    uintptr_t cur = addr, end = cur + len;
    int progressed = 0;
    if (len == 0) return 1;
    if (end < cur) return 0;
    for (int i = 0; i < n && cur < end; i++) {
        const rec *r = &rs[i];
        if (r->e <= cur) continue;
        if (r->s > cur) break;
        if (r->perms[0] != 'r') return 0;
        cur = r->e; progressed = 1;
    }
    return (cur >= end && progressed) ? 1 : 0;
}

int main(void) {
    int fail = 0;
    /* 真实 CI 产物布局（简化）：.eh_frame 尾部与 .text 同页，拆成两条映射 */
    rec rs[2] = {
        {0x700020000UL, 0x700021000UL, "r--p"},
        {0x700021000UL, 0x700047000UL, "r-xp"},
    };
    struct { const char *name; uintptr_t a; size_t l; int want; } t[] = {
        { "单条映射内",        0x700021000UL, 0x1000,  1 },
        { "跨两条映射(.text)", 0x700020100UL, 0x26b18, 1 },
        { "超出映射末尾",      0x700021000UL, 0x30000, 0 },
        { "映射前有空洞",      0x70001f000UL, 0x1000,  0 },
        { "起点在空洞",        0x70001ff00UL, 0x2000,  0 },
        { "零长度",            0x700021000UL, 0,      1 },
    };
    for (unsigned i = 0; i < sizeof(t)/sizeof(t[0]); i++) {
        int got = env_mem_readable_sim(rs, 2, t[i].a, t[i].l);
        if (got != t[i].want) {
            printf("FAIL %s: got %d want %d\n", t[i].name, got, t[i].want);
            fail = 1;
        }
    }
    /* 不可读映射必须拒绝（防止把"读不了"误判成"可读"） */
    rec rw[1] = { { 0x1000UL, 0x2000UL, "-w-p" } };
    if (env_mem_readable_sim(rw, 1, 0x1000, 0x100) != 0) {
        printf("FAIL 不可读映射被误判为可读\n"); fail = 1;
    }
    /* 三条连续映射，区间跨全部三条 */
    rec three[3] = {
        { 0x1000UL, 0x2000UL, "r--p" },
        { 0x2000UL, 0x3000UL, "r-xp" },
        { 0x3000UL, 0x4000UL, "r--p" },
    };
    if (env_mem_readable_sim(three, 3, 0x1800, 0x2000) != 1) {
        printf("FAIL 跨三条映射应通过\n"); fail = 1;
    }
    return fail;
}
EOF

if ! command -v clang >/dev/null 2>&1; then
    echo "  ⚠ 无 clang，跳过"; exit 0
fi

if clang -O2 -o "$WORK/t" "$WORK/t.c" 2>"$WORK/build.log"; then
    if "$WORK/t"; then
        ok "env_mem_readable 跨映射判定（6 场景 + 负向用例）"
    else
        bad "env_mem_readable 判定不符合预期（详见上方 FAIL 行）"
    fi
else
    bad "测试驱动编译失败"; head -10 "$WORK/build.log" >&2
fi

echo
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
