#!/usr/bin/env bash
# test-so-lock.sh — so 段加密设施的回归测试（host 端，无需 NDK/真机）
#
# 为什么必须存在：本仓库此前对 so-section-lock.py / so_section_mark.py
# 零回归测试，AGENTS.md §4 要求"新模块必须带最小回归测试"，这条一直缺。
# 更实际的理由：本轮（2026-10-19）三次改动都靠"跑一遍看结果"发现的 bug——
#   ① 证书解析 offset 错（Python 返回公钥当证书，C 侧 100% 失败）
#   ② 自绑定 CRC 两侧算法不一致（未 patch 也 SIGSEGV）
#   ③ magic 落盘仍是明文（以为改了其实没改）
# 这三个都是"改完不跑就发现不了"的类型。
#
# 覆盖 6 项：
#   T1 编译（同 NDK flags）→ 四段齐全
#   T2 一级锁箱 → .nckey 96 字节
#   T3 二级锁箱 → .nckey_stub 96 字节
#   T4 未改代码 → selftest == 59
#   T5 改 .text 1 位 → 自绑定生效 → 非 59（SIGILL/崩溃）
#   T6 明文路标归零（NCKEYLOCK / NCSTUBLK 不可 strings 搜到）
#
# 用法：bash scripts/lib/tests/test-so-lock.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tso.XXXXXX" 2>/dev/null \
       || mktemp -d "$HOME/.tso.XXXXXX")
SRC="$ROOT/scripts/sigcheck/src"
LOCK="$ROOT/scripts/lib/so-section-lock.py"
APK=${TEST_APK:-$ROOT/docs/so层防御/jh_patched_signed.apk}
PKG=com.xixin.box

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ✓ $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  ✗ $*" >&2; }
skip() { echo "  ⚠ $*（跳过）"; }

cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

echo "=== so 段加密回归（$WORK）==="

# ── T0 前置：需要真签名 APK 与 clang ──
if ! command -v clang >/dev/null; then skip "无 clang，整套跳过"; exit 0; fi
if [ ! -f "$APK" ]; then skip "缺测试 APK: $APK"; exit 0; fi

cp "$SRC/nc_guard_boot.c" "$SRC/nc_guard_probe.c" "$SRC/nc_guard_jni.c" \
   "$SRC/nc_guard_key.c" "$SRC/nc_guard_key.h" "$WORK/"
cd "$WORK" || { echo "cd 失败"; exit 2; }

# ── T1 编译 ──
CFLAGS="-fPIC -shared -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections"
LDFLAGS="-Wl,--gc-sections -Wl,--build-id=none"
if clang $CFLAGS -I. nc_guard_boot.c nc_guard_probe.c nc_guard_jni.c \
        nc_guard_key.c $LDFLAGS -o libnc.so 2>build.log; then
    ok "T1 编译通过（$(stat -c%s libnc.so) B）"
else
    bad "T1 编译失败"; head -20 build.log >&2; exit 1
fi

have_sec() { readelf -S libnc.so 2>/dev/null | grep -q "$1"; }
for s in .nckey .nckey_stub .ncguard .ncguard_head; do
    have_sec "$s" && ok "T1 段 $s 存在" || bad "T1 段 $s 缺失"
done

sec_size() {
    python3 - "$1" <<'PY'
import struct,sys
d=open('libnc.so','rb').read()
sh=struct.unpack('<Q',d[0x28:0x30])[0];es=struct.unpack('<H',d[0x3a:0x3c])[0]
en=struct.unpack('<H',d[0x3c:0x3e])[0];si=struct.unpack('<H',d[0x3e:0x40])[0]
so=struct.unpack('<Q',d[sh+si*es+0x18:sh+si*es+0x20])[0]
for i in range(en):
    o=sh+i*es;no=struct.unpack('<I',d[o:o+4])[0]
    nm=d[so+no:d.index(b'\0',so+no)].decode()
    if nm==sys.argv[1]:
        print(struct.unpack('<Q',d[o+0x20:o+0x28])[0]);break
PY
}

# ── T2 一级锁箱 ──
if python3 "$LOCK" libnc.so libnc.so --from-apk "$APK" >l1.log 2>&1; then
    ok "T2 一级锁箱成功"
    [ "$(sec_size .nckey)" = 96 ] && ok "T2 .nckey 96 字节" \
        || bad "T2 .nckey 大小 $(sec_size .nckey) != 96"
else
    bad "T2 一级锁箱失败"; tail -20 l1.log >&2; exit 1
fi

# ── T3 二级锁箱 ──
if python3 "$LOCK" libnc.so libnc.so --lock-head >l2.log 2>&1; then
    ok "T3 二级锁箱成功"
    [ "$(sec_size .nckey_stub)" = 96 ] && ok "T3 .nckey_stub 96 字节" \
        || bad "T3 .nckey_stub 大小 $(sec_size .nckey_stub) != 96"
else
    bad "T3 二级锁箱失败"; tail -20 l2.log >&2; exit 1
fi

# ── T6 明文路标（在锁箱后的产物上查）──
leak=0
for lit in NCKEYLOCK NCSTUBLK; do
    if strings -n 6 libnc.so 2>/dev/null | grep -q "$lit"; then
        bad "T6 明文路标残留: $lit"; leak=1
    fi
done
[ $leak -eq 0 ] && ok "T6 明文路标归零（magic 已改为种子形式）"

# ── T4/T5 运行期：需构造 fake Android 环境 ──
cat > t.c <<'EOF'
#include <dlfcn.h>
#include <stdio.h>
int main(int c, char **v) {
    void *h = dlopen(v[1], RTLD_NOW);
    if (!h) { printf("-999\n"); return 0; }
    int (*f)(void *, void *) =
        (int (*)(void *, void *))dlsym(h, "Java_com_nc_link_NcLink_selftest");
    printf("%d\n", f ? f(NULL, NULL) : -998);
    return 0;
}
EOF
if ! clang t.c -o t -ldl 2>/dev/null; then
    skip "T4/T5 无法编译测试驱动"
else
    rm -rf fake && mkdir -p "fake/$PKG/lib/arm64-v8a"
    cp libnc.so "fake/$PKG/lib/arm64-v8a/"
    cp "$APK" "fake/$PKG/base.apk"
    cd "fake/$PKG" || exit 2

    # run_so：崩溃时 stdout 可能为空（SIGILL/SIGSEGV 打断），
    # 所以返回码与输出分开判断，别把"空输出"当成"没通过"的唯一依据。
    run_so() {
        out=$(bash -c "exec -a $PKG '$WORK/t' ./lib/arm64-v8a/libnc.so" 2>/dev/null)
        rc=$?
        if [ $rc -ne 0 ]; then printf 'CRASH(%d)' "$rc"; else printf '%s' "$out"; fi
    }

    # T4 正常路径
    rc=$(run_so)
    [ "$rc" = "59" ] && ok "T4 未改代码 → selftest=59" \
        || bad "T4 期望 59，实得 '$rc'（P1-a 证书派生或解锁链路失败）"

    # T5 代码自绑定：改 .text 1 位必须自毁
    cp lib/arm64-v8a/libnc.so ../orig.so
    python3 - <<'PY'
import struct
p='lib/arm64-v8a/libnc.so'
d=bytearray(open(p,'rb').read())
sh=struct.unpack('<Q',d[0x28:0x30])[0];es=struct.unpack('<H',d[0x3a:0x3c])[0]
en=struct.unpack('<H',d[0x3c:0x3e])[0];si=struct.unpack('<H',d[0x3e:0x40])[0]
so=struct.unpack('<Q',d[sh+si*es+0x18:sh+si*es+0x20])[0]
for i in range(en):
    o=sh+i*es;no=struct.unpack('<I',d[o:o+4])[0]
    nm=d[so+no:d.index(b'\0',so+no)].decode()
    if nm=='.text':
        off=struct.unpack('<Q',d[o+0x18:o+0x20])[0]
        size=struct.unpack('<Q',d[o+0x20:o+0x28])[0]
        d[off+size//2]^=0x01
        break
open(p,'wb').write(d)
PY
    rc2=$(run_so)
    [ "$rc2" != "59" ] && ok "T5 改 .text 1 位 → 自毁（实得 $rc2）" \
        || bad "T5 改了代码仍返回 59 —— 代码自绑定未生效"
    cp ../orig.so lib/arm64-v8a/libnc.so
fi

echo
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
