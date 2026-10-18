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
#   T7 签名表进加密段（SIG_SALT/SIG_HASH_STORED 明文零命中）★ 2026-10-19
#   T8 篡改 .ncguard_ro 1 字节 → MAC 拒解（-11），证明 MAC 覆盖两段
#   T9 kill 链无 PLT 软目标（abort/_exit/raise/syscall 四个桩全部消失）★
#   T10 kill 逻辑进加密段（env_delayed_kill 落在 .ncguard 内且不可反汇编）
#
# 用法：bash scripts/lib/tests/test-so-lock.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tso.XXXXXX" 2>/dev/null \
       || mktemp -d "$HOME/.tso.XXXXXX")
SRC="$ROOT/scripts/sigcheck/src"
LOCK="$ROOT/scripts/lib/so-section-lock.py"
# 需要一个【已签名】APK（锁箱要提证书）。默认取仓库内样本，可用 TEST_APK 覆盖。
# 为什么必须已签名：本轮 P1-a 起 k_so 由证书派生，未签名包会在锁箱阶段
# fail-fast（"非 APK Signing Block magic"）——这是设计行为，不是 bug。
APK=${TEST_APK:-/storage/emulated/0/简盒/简盒_signed_23_59_49_sign.apk}
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
if [ ! -f "$APK" ]; then
    skip "缺测试 APK（需已签名）: $APK\n    用 TEST_APK=<已签名.apk> bash $0 指定"
    exit 0
fi

# 拷【全量】源文件：env_check.c 必须一起编，否则 T10（kill 链进加密段）
# 会被跳过 —— 一项关键断言被静默跳过比失败更糟。
# 顺带覆盖 sigcheck+envcheck 的真实组合，而不是只测 sigcheck-only。
cp "$SRC/nc_guard_boot.c" "$SRC/nc_guard_probe.c" "$SRC/nc_guard_jni.c" \
   "$SRC/nc_guard_key.c" "$SRC/nc_guard_key.h" "$SRC/nc_link.c" \
   "$SRC/env_check.c" "$SRC/sig_check.c" "$WORK/"
# sig_hash.h 是构建期生成的（含两张签名表），必须先生成再编译
bash "$ROOT/scripts/sigcheck/hash/make-sig-hash.sh" "$APK" "$WORK/sig_hash.h" \
     >"$WORK/sighash.log" 2>&1 \
    || { echo "  ⚠️ sig_hash.h 生成失败（详见 $WORK/sighash.log）"; }
cd "$WORK" || { echo "cd 失败"; exit 2; }

# ── T1 编译 ──
# -DNC_GUARD_SECTIONED：让判决核心与两张签名表进加密段（生产配置）。
# 宿主测试路径（test-javacheck.sh）走 NCLINK_HOST_TEST，不受影响。
CFLAGS="-fPIC -shared -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections -DNC_GUARD_SECTIONED"
LDFLAGS="-Wl,--gc-sections -Wl,--build-id=none"
# sig_log_data.h 依赖 sig_check.c + env_check.c 的 LSG 标记，必须先跑生成器
python3 "$ROOT/scripts/sigcheck/log/make-sig-log.py" \
     sig_check.c env_check.c sig_log_data.h >siglog.log 2>&1 || true
if clang $CFLAGS -I. nc_guard_boot.c nc_guard_probe.c nc_guard_jni.c \
        nc_guard_key.c nc_link.c env_check.c sig_check.c \
        $LDFLAGS -o libnc.so 2>build.log; then
    ok "T1 编译通过（$(stat -c%s libnc.so) B）"
else
    bad "T1 编译失败"; head -20 build.log >&2; exit 1
fi

# ⚠️ 必须用词边界匹配：`.nckey` 是 `.nckey_stub` 的子串，裸 grep 会漏判
# （实测踩过：T1 报 ".nckey 缺失"，实际段存在、只是被 .nckey_stub 抢先匹配）。
have_sec() {
    readelf -SW libnc.so 2>/dev/null | awk '{print $2}' | grep -qxF "$1"
}
for s in .nckey .nckey_stub .ncguard .ncguard_ro .ncguard_head; do
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
if python3 "$LOCK" libnc.so libnc.so --section ".ncguard,.ncguard_ro" \
        --from-apk "$APK" >l1.log 2>&1; then
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

# ── T7 签名表必须已加密（2026-10-19，修实测报告 §8.1 最致命缺陷）──
# 判据：这两张表的内容不应出现在产物的**任何位置**（明文零命中）。
# 表内容从生成的 sig_hash.h 里解析出来，避免硬编码（每次 salt 随机）。
if [ -f sig_hash.h ]; then
    if python3 - <<'PYT7'
import re, sys
try:
    h = open('sig_hash.h').read()
except OSError:
    sys.exit(2)
def grab(name):
    m = re.search(r'%s\[[^\]]*\]\s*=\s*\{(.*?)\}' % name, h, re.S)
    if not m: return None
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', m.group(1)))
so = open('libnc.so', 'rb').read()
bad = []
for nm in ('SIG_SALT', 'SIG_HASH_STORED'):
    v = grab(nm)
    if v is None: sys.exit(2)
    if v in so: bad.append(nm)
if bad:
    print('明文残留: ' + ', '.join(bad), file=sys.stderr); sys.exit(1)
sys.exit(0)
PYT7
    then ok "T7 签名表已加密（SIG_SALT/SIG_HASH_STORED 明文零命中）"
    else bad "T7 签名表仍以明文出现在产物中（判定核心未上锁）"
    fi
else
    skip "T7 无 sig_hash.h，跳过"
fi

# ── T9 kill 链无 PLT 软目标（2026-10-19 方案2）────────────────────
# 实测报告 §12.1：改 abort/_exit/raise 三个 PLT 桩各 4 字节 → 380 个
# 调用点全废。本项断言这四个符号在产物里【不再是未定义符号】，
# 即二进制里没有这些 PLT 表项可供 patching。
bad_syms=""
for sym in abort _exit raise syscall; do
    if nm -D -u libnc.so 2>/dev/null | grep -qw "$sym"; then
        bad_syms="$bad_syms $sym"
    fi
done
if [ -z "$bad_syms" ]; then
    ok "T9 kill 链无 PLT 软目标（abort/_exit/raise/syscall 均已改为内联 svc）"
else
    bad "T9 仍依赖 PLT 软目标:$bad_syms（攻击者可改 4 字节废掉整条 kill 链）"
fi

# ── T10 kill 逻辑必须进加密段 ──────────────────────────────────────
# 判据：env_delayed_kill 的符号地址落在 .ncguard 段 [addr, addr+size) 内。
# 若为 0 或落在 .text，说明段标记没生效 —— 攻击者静态就能看到 kill 逻辑。
if nm libnc.so 2>/dev/null | grep -q "env_delayed_kill"; then
    killaddr=$(nm libnc.so | awk '/env_delayed_kill$/{print $1}')
    insec=$(python3 - "$killaddr" <<'PYT10'
import struct, sys
addr = int(sys.argv[1], 16)
d = open('libnc.so', 'rb').read()
sh = struct.unpack('<Q', d[0x28:0x30])[0]
es = struct.unpack('<H', d[0x3a:0x3c])[0]
en = struct.unpack('<H', d[0x3c:0x3e])[0]
si = struct.unpack('<H', d[0x3e:0x40])[0]
so = struct.unpack('<Q', d[sh+si*es+0x18: sh+si*es+0x20])[0]
for i in range(en):
    o = sh + i*es
    no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    if nm == '.ncguard':
        sa = struct.unpack('<Q', d[o+0x10:o+0x18])[0]
        sz = struct.unpack('<Q', d[o+0x20:o+0x28])[0]
        print('yes' if sa <= addr < sa + sz else 'no')
        break
else:
    print('no')
PYT10
)
    [ "$insec" = "yes" ] && ok "T10 kill 逻辑在 .ncguard 内（env_delayed_kill @ 0x$killaddr）" \
        || bad "T10 env_delayed_kill 不在加密段（攻击者可静态定位 kill 逻辑）"
else
    skip "T10 本组合未编入 env_check.c（sigcheck-only），跳过"
fi

# ── T4/T5 运行期：需构造 fake Android 环境 ──
# 编入 env_check.c/sig_check.c 后会引入 liblog 依赖（__android_log_print）。
# 宿主没有 bionic，给个桩让 dlopen 能解析到（仅测试用，不进产物）。
cat > logstub.c <<'EOF'
#include <stdarg.h>
#include <stdio.h>
int __android_log_print(int prio, const char *tag, const char *fmt, ...) {
    (void)prio; (void)tag;
    va_list ap; va_start(ap, fmt);
    int n = vfprintf(stderr, fmt, ap);
    va_end(ap); fputc('\n', stderr);
    return n;
}
int __android_log_write(int prio, const char *tag, const char *text) {
    (void)prio; (void)tag; return fprintf(stderr, "%s\n", text);
}
EOF
clang -shared -fPIC logstub.c -o liblog.so 2>/dev/null

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
        out=$(LD_PRELOAD="$WORK/liblog.so" \
              bash -c "exec -a $PKG '$WORK/t' ./lib/arm64-v8a/libnc.so" 2>/dev/null)
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

    # ── T8 篡改 .ncguard_ro 必须拒解（证明 MAC 覆盖两段，不只代码段）──
    # 这是本轮新增两段结构的关键断言：若 MAC 只算 .ncguard，那么改常量表
    # 不会触发任何检测 → 攻击者可以直接替换 salt/期望值绕过判定。
    if python3 - <<'PYT8'
import struct, sys
d = bytearray(open('lib/arm64-v8a/libnc.so', 'rb').read())
sh = struct.unpack('<Q', d[0x28:0x30])[0]
es = struct.unpack('<H', d[0x3a:0x3c])[0]
en = struct.unpack('<H', d[0x3c:0x3e])[0]
si = struct.unpack('<H', d[0x3e:0x40])[0]
so = struct.unpack('<Q', d[sh+si*es+0x18: sh+si*es+0x20])[0]
for i in range(en):
    o = sh + i*es
    no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    if nm == '.ncguard_ro':
        off = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        d[off] ^= 0x01
        open('lib/arm64-v8a/libnc.so', 'wb').write(d)
        sys.exit(0)
sys.exit(2)
PYT8
    then
        rc3=$(run_so)
        [ "$rc3" != "59" ] && ok "T8 篡改 .ncguard_ro → 拒解（实得 $rc3，MAC 覆盖两段）" \
            || bad "T8 改了常量表仍返回 59 —— MAC 未覆盖 .ncguard_ro"
    else
        skip "T8 无 .ncguard_ro 段，跳过"
    fi
    cp ../orig.so lib/arm64-v8a/libnc.so
fi

echo
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
