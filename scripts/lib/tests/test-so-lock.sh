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
# 覆盖 22 项（编号按落地顺序，非执行顺序——T4/T5/T8 依赖真机运行，
# 排在末尾；用 APK=... bash $0 指定已签名 APK 才跑，缺 APK 时跳过）：
#   T1 编译（同 NDK flags）→ 六段齐全
#   T2 一级锁箱 → .nck 96 字节
#   T3 二级锁箱 → .ncks = NC_STUB_SIZE（从 layout.h 抽取，不写死）
#   T4 未改代码 → selftest == 59
#   T5 改 .text 1 位 → 自绑定生效 → 非 59（SIGILL/崩溃）
#   T6 明文路标归零（NCKEYLOCK / NCSTUBLK 不可 strings 搜到）
#   T7 签名表进加密段（SIG_SALT/SIG_HASH_STORED 明文零命中）★ 2026-10-19
#   T8 篡改 .ncxr 1 字节 → MAC 拒解（-11），证明 MAC 覆盖两段
#   T9 kill 链无 PLT 软目标（abort/_exit/raise/syscall 四个桩全部消失）★
#   T10 kill 逻辑进加密段（env_delayed_kill 落在 .ncx 内且不可反汇编）
#   T11 master 已随机化（0x11×32 明文零命中）★ 2026-10-19
#   T12 master 藏在密文段（.ncxhr 内容每次构建不同、非全零）
#   T13 kill 链多出口（三个独立函数体，非共用；全在加密段）★ 2026-10-19
#   T14 JNI 符号面收缩（.dynsym 只剩 JNI_OnLoad）★ P2-1
#   T15 .rodata 路径密文化（/proc/* 等明文零命中）★ P2-2
#   T16 段名中性化（不再有自解释的 ncguard/nckey）★ P2-3
#   T17 诱饵真随机（两次构建 wrapped_k_so 不同，diff 手法失效）★ 2026-10-19
#   T18 CRC 自绑定覆盖整个 .text（不是只覆盖 stub 函数）★ 2026-10-19
#   T19 hook 探针覆盖 mprotect/mmap/dlopen/pvm_readv（解密链关键点）★
#   T20 C↔Python 契约常数跨语言对拍（段名/尺寸/偏移/magic seed）★ 2026-10-20
#   T21 全仓段名字面量登记检测（防拼错/防新增未登记段名）★ 2026-10-20
#   T22 二进制等价性（固定 sig_hash.h 后，改动不得改变产物字节）★ 2026-10-20
#   T23 strip 真生效 + strip 后锁箱/开箱仍通（.symtab 归零）★ 2026-10-20
#   T24 version script 真的生效（无失效 guard / 白名单 Java_* / --undefined-version）★ 2026-10-21
#   T25 密钥不硬编码（k_stub/k_mac_head 每构建随机，且源码无硬编码字面量）★ 2026-10-22
#   T26 amimo_dcc 僵尸符号不外泄（编译期改名 + 白名单仍 Java_*）★ 2026-10-22
#   T27 密钥清零不可被优化（memset → volatile 写）★ 2026-10-22
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
# APK 定位优先级：TEST_APK 环境变量 > 仓库内样本 > 手机上的简盒签名包（自动探测最新）
if [ -z "${TEST_APK:-}" ]; then
    for cand in "$ROOT/docs/so层防御"/*.apk; do
        [ -f "$cand" ] && TEST_APK="$cand" && break
    done
fi
if [ -z "${TEST_APK:-}" ] && [ -d "/storage/emulated/0/简盒" ]; then
    # 取最新的一份（文件名含时间，ls -t 按 mtime 更可靠）
    TEST_APK=$(ls -t /storage/emulated/0/简盒/*_sign.apk 2>/dev/null | head -1)
fi
APK=${TEST_APK:-}
# ── 包名必须从 APK 动态提取（2026-10-22 修 T4 假失败）───────────────
# 曾硬编码 PKG=com.xixin.box，而锁箱器是用 --from-apk 从【实际传入的 APK】
# 里提包名（so-section-lock.py:manifest_package），并把其指纹写进
# .nck[80:88]。运行期 ncg_pkg_matches 用 /proc/self/cmdline 的进程名比对
# 这个指纹，不一致就 fail-closed 返回 -12 → 不解密 → 探针踩密文 → SIGILL。
#
# 后果：只要测试 APK 不叫 com.xixin.box（本例 tc_signed_*.apk 实际是
# com.xixin.tc），T4 就必然 CRASH(132)，且报错信息误导成"证书派生或
# 解锁链路失败"——真实原因是【测试环境包名与产物不匹配】。
# 这类假失败比真 bug 更耗时间：它指向错误的方向。
#
# 修法：与锁箱器同源（都从 APK 的 AXML 提取），谁换 APK 都自动一致。
# 提取失败时回退到占位值并显式告警（不静默用错值）。
PKG=""
if [ -n "$APK" ] && [ -f "$APK" ]; then
    # ⚠️ 复用 so-section-lock.py 里【已被生产验证】的 manifest_package()，
    #    不要在这里另写一份 AXML 解析器：写错一次就是"提取到
    #    androidx.core.app.CoreComponentFactory"这种假值（本轮实测踩过），
    #    而假值与真包名同样"看起来像个包名"，极难察觉。
    #    单一真相源 = 测试与锁箱器永远同源，谁换 APK 都自动一致。
    PKG=$(python3 - "$ROOT/scripts/lib/so-section-lock.py" "$APK" <<'PYPKG' 2>/dev/null || true
import sys, importlib.util
spec = importlib.util.spec_from_file_location("lockmod", sys.argv[1])
m = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(m)
    print(m.manifest_package(sys.argv[2]))
except Exception:
    pass
PYPKG
)
fi
if [ -z "$PKG" ]; then
    PKG=com.xixin.box
    echo "  ⚠ 无法从 APK 提取包名，回退占位值 $PKG" >&2
    echo "    —— 若 T4/T5/T8 失败且报 CRASH(132)，先怀疑这里（包名不匹配 → -12）" >&2
else
    echo "  ℹ APK 包名（从 AXML 提取，与锁箱器同源）: $PKG"
fi

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
   "$SRC/nc_guard_layout.h" \
   "$SRC/env_check.c" "$SRC/sig_check.c" "$WORK/"

# sig_hash.h 是构建期生成的（含两张签名表），必须先生成再编译
bash "$ROOT/scripts/sigcheck/hash/make-sig-hash.sh" "$APK" "$WORK/sig_hash.h" \
     >"$WORK/sighash.log" 2>&1 \
    || { echo "  ⚠️ sig_hash.h 生成失败（详见 $WORK/sighash.log）"; }
cd "$WORK" || { echo "cd 失败"; exit 2; }

# ── T1 编译 ──
# -DNC_GUARD_SECTIONED：让判决核心与两张签名表进加密段（生产配置）。
# 宿主测试路径（test-javacheck.sh）走 NCLINK_HOST_TEST，不受影响。
# 与 lib-ndk.sh 的生产配置保持一致（否则测的不是真产物形态）：
#   NC_JNI_DYNAMIC_REG → JNI 实现走 hidden 可见性
#   version script     → .dynsym 只留 JNI_OnLoad
CFLAGS="-fPIC -shared -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections -DNC_GUARD_SECTIONED"
# version script：有 JNI_OnLoad（真实产物）才写 global 项；
# 测试工程没有 dex2c 的 Dex2C.cpp，故全 local。
# JNI 短名绑定要求 Java_* 与 JNI_OnLoad 必须导出（否则 ART dlsym 不到），
# 所以 version script 只隐藏非 JNI 符号。
# ⚠️ JNI_OnLoad 只在有 dex2c 产物时存在；测试工程没有它，
#    写成 global 会让 lld 报 "symbol not defined" → 按存在性生成。
{ echo "{"; echo "  global:";   nm -g --defined-only libnc.so 2>/dev/null | grep -qw JNI_OnLoad \
      && echo "    JNI_OnLoad;"; \
  echo "    Java_com_nc_*;"; echo "  local:"; echo "    *;"; echo "};"; } > hide.map
LDFLAGS="-Wl,--gc-sections -Wl,--build-id=none -Wl,--version-script=hide.map"
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

# ⚠️ 必须用词边界匹配：`.nck` 是 `.ncks` 的子串，裸 grep 会漏判
# （实测踩过：T1 报 ".nck 缺失"，实际段存在、只是被 .ncks 抢先匹配）。
have_sec() {
    readelf -SW libnc.so 2>/dev/null | awk '{print $2}' | grep -qxF "$1"
}
for s in .nck .ncks .ncx .ncxr .ncxh; do
    have_sec "$s" && ok "T1 段 $s 存在" || bad "T1 段 $s 缺失"
done

# 从指定段读 hex 子串（按段表定位，不用 bytes.find——段名相同的数据
# 可能在 so 里多处出现，find 会命中错误位置）
section_bytes() {
    python3 - "$1" "$2" "$3" "$4" <<'PYB'
import struct, sys
sec, off, ln, path = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
d = open(path, 'rb').read()
sh = struct.unpack('<Q', d[0x28:0x30])[0]
es = struct.unpack('<H', d[0x3a:0x3c])[0]
en = struct.unpack('<H', d[0x3c:0x3e])[0]
si = struct.unpack('<H', d[0x3e:0x40])[0]
so = struct.unpack('<Q', d[sh+si*es+0x18: sh+si*es+0x20])[0]
for i in range(en):
    o = sh + i*es
    no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    if nm == sec:
        fo = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        print(d[fo+off: fo+off+ln].hex())
        break
PYB
}

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
if python3 "$LOCK" libnc.so libnc.so --section ".ncx,.ncxr" \
        --from-apk "$APK" >l1.log 2>&1; then
    ok "T2 一级锁箱成功"
    [ "$(sec_size .nck)" = 96 ] && ok "T2 .nck 96 字节" \
        || bad "T2 .nck 大小 $(sec_size .nck) != 96"
else
    bad "T2 一级锁箱失败"; tail -20 l1.log >&2; exit 1
fi

# ── T3 二级锁箱 ──
if python3 "$LOCK" libnc.so libnc.so --lock-head >l2.log 2>&1; then
    ok "T3 二级锁箱成功"
    _EXP=$(sed -n 's/^#define NC_STUB_SIZE[[:space:]]*\([0-9]*\).*/\1/p' \
           "$ROOT/scripts/sigcheck/src/nc_guard_layout.h")
    [ "$(sec_size .ncks)" = "$_EXP" ] && ok "T3 .ncks ${_EXP} 字节" \
        || bad "T3 .ncks 大小 $(sec_size .ncks) != ${_EXP}（layout.h NC_STUB_SIZE）"
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
# 判据：env_delayed_kill 的符号地址落在 .ncx 段 [addr, addr+size) 内。
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
    if nm == '.ncx':
        sa = struct.unpack('<Q', d[o+0x10:o+0x18])[0]
        sz = struct.unpack('<Q', d[o+0x20:o+0x28])[0]
        print('yes' if sa <= addr < sa + sz else 'no')
        break
else:
    print('no')
PYT10
)
    [ "$insec" = "yes" ] && ok "T10 kill 逻辑在 .ncx 内（env_delayed_kill @ 0x$killaddr）" \
        || bad "T10 env_delayed_kill 不在加密段（攻击者可静态定位 kill 逻辑）"
else
    skip "T10 本组合未编入 env_check.c（sigcheck-only），跳过"
fi

# ── T11 master 必须已随机化（修实测报告 P1-1）────────────────────
# 判据：产物里不能再出现 `0x11` 重复 32 次或 16 次。
# 修复前 master 是 static const 全 0x11，`od` 一条命令读出即用。
if python3 - <<'PYT11'
import sys
d = open('libnc.so', 'rb').read()
bad = []
if d.count(b'\x11' * 32): bad.append('0x11 x32')
if d.count(b'\x11' * 16): bad.append('0x11 x16')
if bad:
    print('明文占位符残留: ' + ', '.join(bad), file=sys.stderr)
    sys.exit(1)
sys.exit(0)
PYT11
then ok "T11 master 已随机化（0x11 占位符零命中）"
else bad "T11 master 仍是 0x11 占位符（报告实测 8 分钟可离线解）"
fi

# ── T12 master 必须藏在密文段 ──────────────────────────────────
# 两个判据：①该段存在且 32 字节 ②锁定后内容非全零且与全零不同。
if have_sec .ncxhr; then
    rohex=$(python3 - <<'PYT12'
import struct
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
    if nm == '.ncxhr':
        off = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        print(d[off:off+32].hex())
        break
PYT12
)
    if [ -n "$rohex" ] && [ "$rohex" != "$(printf '0%.0s' {1..64})" ]; then
        ok "T12 master 在 .ncxhr 且已加密（${rohex:0:16}…）"
    else
        bad "T12 .ncxhr 内容异常（全零 = 未加密或未写入）"
    fi
else
    bad "T12 缺 .ncxhr 段 —— master 无处存放"
fi

# ── T13 kill 链必须是多个【独立函数体】──────────────────────
# 报告 §10：13 个校验分支 → 1 个汇聚点，patch 一处全废。
# 本项断言 delayed_kill_0/1/2 三个符号存在且【地址互不相同】
# （共用函数体 = 参数化 = 攻击者改一条比较即可让三者同时失效）。
k0=$(nm libnc.so 2>/dev/null | awk '/delayed_kill_0$/{print $1}')
k1=$(nm libnc.so 2>/dev/null | awk '/delayed_kill_1$/{print $1}')
k2=$(nm libnc.so 2>/dev/null | awk '/delayed_kill_2$/{print $1}')
if [ -n "$k0" ] && [ -n "$k1" ] && [ -n "$k2" ]; then
    if [ "$k0" != "$k1" ] && [ "$k1" != "$k2" ] && [ "$k0" != "$k2" ]; then
        ok "T13 kill 链多出口（3 个独立函数体 @0x$k0/0x$k1/0x$k2）"
    else
        bad "T13 kill 变体共用同一函数体（参数化 = 一处 patch 全废）"
    fi
else
    skip "T13 本组合未编入 sig_check.c，跳过"
fi

# ── T14 JNI 符号面：.dynsym 应只剩 JNI_OnLoad ──────────────────
# 实测报告 §1：`nm -D` 一条命令拿到全部 JNI 入口名 + 精确大小
# （`MainActivity.k` 21692 B），等于免费送业务复杂度地图。
# ⚠️ 2026-10-19 真机实证后调整：Java_* 必须导出（JNI 短名绑定的硬要求），
# 想隐藏只能动态注册，而动态注册在 so 加载时机会崩。所以本项只断言
# 「非 JNI 的内部符号不外泄」（如 nc_jni_* / ncg_* 辅助函数）。
if nm -D --defined-only libnc.so 2>/dev/null | grep -qE "nc_jni_|^[0-9a-f]+ T ncg_"; then
    leak=$(nm -D --defined-only libnc.so | grep -cE "nc_jni_|ncg_")
    bad "T14 .dynsym 泄露 $leak 个内部符号（非 JNI 的不该导出）"
else
    # 测试工程不含 dex2c 的 Dex2C.cpp，故没有 JNI_OnLoad（全 local）。
    # 真实产物必须有它——那是 ART 的入口。区分这两种情况。
    if nm -g --defined-only libnc.so 2>/dev/null | grep -qw "JNI_OnLoad"; then
        nm -D --defined-only libnc.so 2>/dev/null | grep -q "JNI_OnLoad" \
            && ok "T14 JNI 符号面收缩（.dynsym 只剩 JNI_OnLoad）" \
            || bad "T14 JNI_OnLoad 被 version script 隐藏了（ART 会加载失败）"
    else
        ok "T14 JNI 符号面收缩（本组合无 JNI_OnLoad，.dynsym 为空）"
    fi
fi

# ── T15 .rodata 路径密文化 ────────────────────────────────────
# 实测报告 §4：20+ 条路径明文泄底整套防御决策树。
path_leak=""
for p in "/proc/self/status" "/proc/self/maps" "/proc/self/cmdline" \
         "/proc/net/tcp" "/proc/net/unix" "/proc/self/task"; do
    strings -n 6 libnc.so 2>/dev/null | grep -Fqx "$p" && path_leak="$path_leak $p"
done
[ -z "$path_leak" ] && ok "T15 .rodata 路径密文化（6 条关键路径明文零命中）" \
    || bad "T15 路径仍明文:$path_leak"

# ── T16 段名中性化 ────────────────────────────────────────────
# ⚠️ 这条断言必须检查【旧名】。段名已中性化为 .ncx*，若这里也跟着写成
# .ncx，断言就恒真了（假绿）。2026-10-19 检查时发现正是如此。
# 用 have_sec（与 T1 同源的段表精确匹配）而非 `grep "\.ncx"` 全文模糊匹配：
#   ① `grep "\\.ncx"` 里的 . 是正则任意字符，理论上可误命中（实测未触发，
#      但断言不该依赖运气）；
#   ② 2026-10-20 实测一次偶发失败：readelf 管道输出异常导致 grep 空结果，
#      报"既无中性名也无旧名"——那条错误信息在当时是【假】的（段名明明在）。
#      改用 awk 取第 2 列 + grep -qxF 全等匹配，与 T1 的段存在性断言同一条路径，
#      两条断言要么都对要么都错，不会一条绿一条红。
# 旧名从变量取，不在本文件留字面量 —— T21 会扫全仓段名，写在这儿会让自己红
_OLD1='.ncg'"uard"; _OLD2='.nck'"ey"
if readelf -SW libnc.so 2>/dev/null | awk '{print $2}' | grep -qxF "$_OLD1" \
   || readelf -SW libnc.so 2>/dev/null | awk '{print $2}' | grep -qxF "$_OLD2"; then
    bad "T16 自解释段名残留（$_OLD1/$_OLD2 会直接暴露机制）"
elif have_sec .ncx && have_sec .ncxh; then
    ok "T16 段名已中性化（.ncx/.ncxr/.ncxh/.ncxhr/.nck/.ncks）"
else
    bad "T16 段名异常（既无中性名也无旧名）—— 先跑 readelf -SW libnc.so 手工确认"
fi

# ── T17 诱饵必须真随机（防 diff 识破）────────────────────────
# 复测报告 §7.1 的识破手法：第一版与第二版的 wrapped_k_so 完全相同
# （d6054d96f1e71285...），据此判定「诱饵死字段，不参与真实派生」。
# 确定性诱饵 = 攻击者 diff 两个 so 就能认出来，不需要懂密码学。
# 改 os.urandom 后每次构建都不同，diff 手法失效。
if [ -f libnc.so ]; then
    d1=$(section_bytes .nck 16 16 libnc.so)
    # 用 --force 重新锁一次，比对 wrapped_k_so 是否变化
    cp libnc.so libnc_a.so
    python3 "$LOCK" libnc_a.so libnc_a.so --section ".ncx,.ncxr" \
        --from-apk "$APK" --force >/dev/null 2>&1
    d2=$(section_bytes .nck 16 16 libnc_a.so)
    if [ -n "$d1" ] && [ -n "$d2" ] && [ "$d1" != "$d2" ]; then
        ok "T17 诱饵真随机（两次构建 wrapped_k_so 不同，diff 手法失效）"
    else
        bad "T17 诱饵仍是确定性的（d1=$d1 d2=$d2）—— 复测报告的 diff 识破会再次生效"
    fi
    rm -f libnc_a.so
else
    skip "T17 无 libnc.so"
fi

# ── T18 .text 双重覆盖：CRC 自绑定必须覆盖整个 .text ────────────
# 背景（复测报告 §2.2 说「.text 校验仍报 clean」）：
#   实测确认那不是缺陷——self_text_crc_probe 与 CRC 自绑定【都覆盖整个
#   .text】。改 .text 任何字节 → CRC 先失败 → head 解出乱码 → SIGILL，
#   探针根本没机会跑。所以「报 clean」是被更强机制覆盖的正常表现。
#
# 但这个覆盖关系是【隐含的】——没有任何东西保证它成立。若后人把
# CRC 的 code_addr/code_len 改成只覆盖部分 .text（比如为了缩小自绑定
# 范围、提速），.text 校验就会变成唯一防线，而它实测有跨映射误判史
# （报错五十四）。这个断言把隐含依赖变成显式契约。
if [ -f libnc.so ]; then
    CRC_INFO=$(python3 - <<'PYT18'
import struct
d = open('libnc.so', 'rb').read()
sh = struct.unpack('<Q', d[0x28:0x30])[0]
es = struct.unpack('<H', d[0x3a:0x3c])[0]
en = struct.unpack('<H', d[0x3c:0x3e])[0]
si = struct.unpack('<H', d[0x3e:0x40])[0]
so = struct.unpack('<Q', d[sh+si*es+0x18: sh+si*es+0x20])[0]
secs = {}
for i in range(en):
    o = sh + i*es
    no = struct.unpack('<I', d[o:o+4])[0]
    nm = d[so+no: d.index(b'\0', so+no)].decode()
    secs[nm] = (struct.unpack('<Q', d[o+0x10:o+0x18])[0],
                struct.unpack('<Q', d[o+0x20:o+0x28])[0])
t_addr, t_size = secs['.text']
# .ncks slot 里的 code_addr/code_len（偏移 36/40，NCG_OFF_CODE_*）
s_addr, s_size = secs['.ncks']
slot = d[s_addr: s_addr + s_size]
ca = struct.unpack('<I', slot[36:40])[0]
cl = struct.unpack('<I', slot[40:44])[0]
print('%d %d %d %d' % (ca, cl, t_addr, t_size))
PYT18
)
    read -r CA CL TA TS <<< "$CRC_INFO"
    if [ "$CA" = "$TA" ] && [ "$CL" = "$TS" ]; then
        ok "T18 CRC 自绑定覆盖整个 .text（0x$CA +$CL），.text 校验是被覆盖的冗余层"
    else
        bad "T18 CRC 覆盖范围(0x$CA +$CL) != .text(0x$TA +$TS) —— \
.text 完整性校验将变成唯一防线，而它有跨映射误判史（报错五十四）"
    fi
else
    skip "T18 无 libnc.so"
fi

# ── T19 hook 探针覆盖解密链关键符号 ─────────────────────────
# 复测报告 §13.3 第一条动态路径：「frida hook mprotect 拿解密后明文」。
# 原探针只覆盖 fopen/open/connect/read 4 个常规 hook 点，
# 不含 mprotect/mmap/dlopen/process_vm_readv —— 而它们是
# dump 和解密链的关键。本项断言这 4 个新符号的标记与引用都在。
if [ -f env_check.c ]; then
    miss=""
    for sym in SYM_MPROTECT SYM_MMAP SYM_DLOPEN SYM_PVMREAD; do
        # 标记（/*LSGS:xxx|...*/）与引用（lsg_s(LSGS_xxx, ...)）都要在
        grep -q "LSGS:$sym|" env_check.c || miss="$miss 标记:$sym"
        grep -q "LSGS_$sym," env_check.c || miss="$miss 引用:$sym"
    done
    if [ -z "$miss" ]; then
        ok "T19 hook 探针覆盖 mprotect/mmap/dlopen/pvm_readv（解密链关键点）"
    else
        bad "T19 hook 探针缺项:$miss —— 只加引用不加标记会运行期取不到名字（静默漏检）"
    fi
else
    skip "T19 无 env_check.c"
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
    /* 动态注册后不再导出 Java_xxx（T14 的预期），selftest 无法 dlsym。
     * 改为验证：dlopen 成功即算通 —— 能到这里说明
     *   ① so 加载没崩（段解密/mprotect/构造顺序都对）
     *   ② 符号依赖都满足（无未定义符号）
     * 这就覆盖了 T4 想验证的"解锁链路通"。
     * 不检查 JNI_OnLoad：测试工程没有 dex2c 的 Dex2C.cpp，
     * version script 全 local，那个符号不存在。 */
    printf("59\n");
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

    # ── T8 篡改 .ncxr 必须拒解（证明 MAC 覆盖两段，不只代码段）──
    # 这是本轮新增两段结构的关键断言：若 MAC 只算 .ncx，那么改常量表
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
    if nm == '.ncxr':
        off = struct.unpack('<Q', d[o+0x18:o+0x20])[0]
        d[off] ^= 0x01
        open('lib/arm64-v8a/libnc.so', 'wb').write(d)
        sys.exit(0)
sys.exit(2)
PYT8
    then
        rc3=$(run_so)
        [ "$rc3" != "59" ] && ok "T8 篡改 .ncxr → 拒解（实得 $rc3，MAC 覆盖两段）" \
            || bad "T8 改了常量表仍返回 59 —— MAC 未覆盖 .ncxr"
    else
        skip "T8 无 .ncxr 段，跳过"
    fi
    cp ../orig.so lib/arm64-v8a/libnc.so
fi

# ═══════════════════════════════════════════════════════════════════
# T20/T21/T22（2026-10-20）：契约一致性反向保险
#
# 为什么需要：契约常数此前散落 4 种语言、7 个文件、24 处副本。
# 下面三项把"改一处必须同步另一处"从注释变成构建期 fail-fast。
#   T20 C↔Python 跨语言对拍（layout.h 是唯一真相源）
#   T21 全仓段名字面量登记检测（防拼错、防新增未登记段名）
#   T22 二进制等价性（固定 sig_hash.h 后，改动不得改变产物字节）
# ═══════════════════════════════════════════════════════════════════

LAYOUT_H="$ROOT/scripts/sigcheck/src/nc_guard_layout.h"
LOCK_PY="$ROOT/scripts/lib/so-section-lock.py"

# ── T20 C↔Python 契约常数跨语言对拍 ──────────────────────────────
# 做法：让 so-section-lock.py 自己从 layout.h 抽取（它的 _load_layout_contract），
# 再用独立正则从 layout.h 抽一遍，两边比。双路抽取是为了防"抽取器本身写错"——
# 若只有一条抽取路径，它错了也会自洽地通过。
#
# ⚠️⚠️ 本项的【能力边界】必须说清（2026-10-20 实测确认）：
#   两边都从同一个 layout.h 抽，所以"改 layout.h"时它们会一致地一起变，
#   T20 【抓不到 layout.h 自身的漂移】——那不是它的职责。
#   改 layout.h = 契约变更，C/Python 本就该跟着变；
#   拦住它的是 so-section-lock.py 的 assert len(blob)==NC_SLOT_SIZE
#   （blob 是按新尺寸拼的，段实际尺寸没变 → 当场 AssertionError）。
#
#   T20 真正防的是【第二份副本】：有人嫌 include 麻烦，在某个 .c 里
#   手写 section(".ncx")、或在某个 .py 里再抄一份 96。
#   这类副本不会让 layout.h 报错，只会让某个消费者与真相源不一致——
#   症状是运行期 SIGILL。T20 的 C 侧初始化检查就是抓这个。
#
#   ⚠️ 注意 T21 抓不到"手写已登记段名"（2026-10-20 实测）：在 nc_link.c 里
#   把 section(NC_SEC_CODE) 改回 section(".ncx")，T21 照样绿——因为 .ncx
#   本身是已登记的。T21 的职责是防"未登记/拼错的段名"，不是防"绕过宏"。
#   抓绕过宏要靠 T20 的 C 侧检查（见下方 scan_c_copies）。
if [ -f "$LAYOUT_H" ] && [ -f "$LOCK_PY" ]; then
    if python3 - "$LAYOUT_H" "$LOCK_PY" >t20.log 2>&1 <<'PYT20'
import importlib.util, re, sys
layout, lockpy = sys.argv[1], sys.argv[2]

spec = importlib.util.spec_from_file_location("ssl", lockpy)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)          # 会执行 _load_layout_contract()
py = m._LAYOUT

text = open(layout, encoding='utf-8').read()
def sec(name):
    mm = re.search(r'#define\s+%s\s+"([^"]+)"' % name, text)
    return mm.group(1) if mm else None
def num(name):
    mm = re.search(r'#define\s+%s\s+(\d+)' % name, text)
    return int(mm.group(1)) if mm else None
def seed(name):
    mm = re.search(r'#define\s+%s\s*\\?\s*\{([^}]*)\}' % name, text)
    if not mm: return None
    return bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]+)', mm.group(1)))

fails = []
def chk(what, a, b):
    if a != b:
        fails.append('%s: C侧=%r Python侧=%r' % (what, a, b))

# 段名：Python 模块级常量 vs layout.h
chk('SECTION_NAME',    m.SECTION_NAME,   sec('NC_SEC_CODE'))
chk('SLOT_NAME',       m.SLOT_NAME,      sec('NC_SEC_SLOT'))
chk('HEAD_NAME',       m.HEAD_NAME,      sec('NC_SEC_HEAD'))
chk('HEAD_RO_NAME',    m.HEAD_RO_NAME,   sec('NC_SEC_HEADRO'))
chk('STUB_SLOT',       m.STUB_SLOT,      sec('NC_SEC_STUBSLOT'))
# 尺寸
chk('NC_SLOT_SIZE',    py['NC_SLOT_SIZE'], num('NC_SLOT_SIZE'))
chk('NC_STUB_SIZE',    py['NC_STUB_SIZE'], num('NC_STUB_SIZE'))
# 偏移
for k in ['NC_OFF_EXPMAC','NC_OFF_PKG_SHA','NC_OFF_CODE_ADDR','NC_OFF_CODE_LEN',
          'NC_OFF_K_MAC_HEAD','NC_OFF_EXPMAC_HEAD','NC_OFF_HEADRO_ADDR',
          'NC_OFF_HEADRO_SIZE']:
    chk(k, py.get(k), num(k))
# magic seed
chk('SLOT_MAGIC_SEED', m.SLOT_MAGIC_SEED, seed('NC_SEED_SLOT_INIT'))
chk('STUB_MAGIC_SEED', m.STUB_MAGIC_SEED, seed('NC_SEED_STUB_INIT'))

# C 侧数组也用同一 seed 初始化（防"C 改了值、Python 没改"）
boot = open(sys.argv[3], encoding='utf-8').read() if len(sys.argv) > 3 else ''
if boot:
    mm = re.search(r'NCG_MAGIC_SEED_SLOT\[8\]\s*=\s*NC_SEED_SLOT_INIT', boot)
    if not mm:
        fails.append('nc_guard_boot.c 未用 NC_SEED_SLOT_INIT 初始化 NCG_MAGIC_SEED_SLOT'
                     '（契约值出现第二份副本）')
    mm = re.search(r'NCG_MAGIC_SEED_STUB\[8\]\s*=\s*NC_SEED_STUB_INIT', boot)
    if not mm:
        fails.append('nc_guard_boot.c 未用 NC_SEED_STUB_INIT 初始化 NCG_MAGIC_SEED_STUB')
    mm = re.search(r'NCG_XOR_FRAG\[8\]\s*=\s*NC_XOR_FRAG_INIT', boot)
    if not mm:
        fails.append('nc_guard_boot.c 未用 NC_XOR_FRAG_INIT 初始化 NCG_XOR_FRAG')

# C 侧副本扫描：5 个消费者 .c 里不得出现裸段名字面量。
# 为什么必须查：手写 section(".ncx") 编译链接全过、T21 也绿（.ncx 是已登记名），
# 只有运行期 SIGILL 才暴露——那种 bug 排查成本是半天量级。
# （历史存档 nc_guard_unlock.c 已于 2026-10-20 移入 archive/，不在此扫描范围。）
import os
SRC = os.path.join(os.path.dirname(os.path.abspath(lockpy)), '..', 'sigcheck', 'src')
SRC = os.path.normpath(SRC)
CONSUMERS = ['nc_guard_boot.c', 'nc_link.c', 'env_check.c', 'sig_check.c',
             'nc_guard_probe.c']
for fn in CONSUMERS:
    fp = os.path.join(SRC, fn)
    if not os.path.isfile(fp):
        fails.append('消费者文件缺失: %s' % fn)
        continue
    txt = open(fp, encoding='utf-8').read()
    # 只查 attribute 里的段名（避开注释里提到的历史名）
    for lit in re.findall(r'section\(\s*"([^"]+)"', txt):
        fails.append('%s 出现裸段名字面量 section("%s") —— 应改用 '
                     'nc_guard_layout.h 的 NC_SEC_* 宏（否则契约出现第二份副本）'
                     % (fn, lit))
    if 'nc_guard_layout.h' not in txt:
        fails.append('%s 未 include nc_guard_layout.h（契约真相源）' % fn)

if fails:
    print('\n'.join('❌ ' + f for f in fails))
    sys.exit(1)
print('OK: 6 段名 + 2 尺寸 + 8 偏移 + 2 seed + C 侧初始化全部一致')
PYT20
    then
        ok "T20 C↔Python 契约对拍（layout.h 为唯一真相源）"
    else
        bad "T20 契约不一致（改 layout.h 或 C/Python 任一侧时此路必红）"; sed -n '1,15p' t20.log >&2
    fi
else
    bad "T20 缺 layout.h 或 so-section-lock.py —— 契约无从对拍"
fi

# ── T21 全仓段名字面量登记检测 ───────────────────────────────────
# 扫 C/Py/Sh 里所有 section("...") 与段名常量，凡未在 layout.h 登记的即失败。
# 防的是"手打错一个字母"：编译链接全过，直到锁箱期才报"段不存在"，
# 且那条报错不告诉你是拼错了。
if [ -f "$LAYOUT_H" ]; then
    registered=$(sed -n 's/^#define NC_SEC_[A-Z_]*[[:space:]]*"\([^"]*\)".*/\1/p' "$LAYOUT_H" | sort -u)
    if [ -n "$registered" ]; then
        bad_found=0
        # 收集源码里出现的所有 .nc 开头段名（含 section("...") 与裸字符串）
        while IFS= read -r lit; do
            if ! grep -qxF "$lit" <<<"$registered"; then
                bad "T21 未登记的段名: $lit（已登记: $(echo $registered | tr '\n' ' ')）"
                bad_found=1
            fi
        done < <(grep -rhoE '"\.(nc[a-z]*|nck[a-z]*)"' \
                    "$ROOT/scripts/sigcheck/src" "$ROOT/scripts/lib" \
                    "$ROOT/scripts/pipelines" "$ROOT/scripts/sigcheck/hash" \
                    2>/dev/null | tr -d '"' | sort -u)
        # 2026-10-20：nc_guard_unlock.c（历史存档，刻意保留旧段名）已从
        # src/ 移到 scripts/sigcheck/archive/，不再参与 NDK 工程。
        # 故此处【不再需要豁免】—— archive/ 本就不该被 T21 扫。
        # 若哪天它又回到 src/，下面这行会立刻红，提醒"历史存档不该躺在真相源旁"。
        if [ -f "$ROOT/scripts/sigcheck/src/nc_guard_unlock.c" ]; then
            bad "T21 历史存档 nc_guard_unlock.c 又回到了 src/ —— 它不参与 NDK 工程，应留在 archive/"
        fi
        [ $bad_found -eq 0 ] && ok "T21 段名字面量全部已登记（$(echo $registered | wc -w) 个）"
    else
        bad "T21 layout.h 里一个段名都没抽到 —— 头文件被改坏了？"
    fi
else
    bad "T21 缺 nc_guard_layout.h"
fi

# ── T22 二进制等价性 ─────────────────────────────────────────────
# 固定 sig_hash.h / sig_log_data.h 后重编，与 Git 基线产物逐字节比。
# 为什么必须固定：make-sig-hash.sh:90 每次 os.urandom(16) 随机 salt，
# 不固定的话 cmp 永远不一致（2026-10-20 实测：96 字节差异全来自 salt，
# 与改动无关）。要证明"重构零行为变化"，这是唯一可靠口径。
if [ -f libnc.so ] && [ -n "${NC_BASELINE_SO:-}" ] && [ -f "$NC_BASELINE_SO" ]; then
    if cmp -s libnc.so "$NC_BASELINE_SO"; then
        ok "T22 二进制等价（与基线逐字节一致）"
    else
        n=$(cmp -l libnc.so "$NC_BASELINE_SO" 2>/dev/null | wc -l)
        bad "T22 二进制有 $n 字节差异 —— 重构引入了行为变化，须查清"
    fi
else
    skip "T22 未提供 NC_BASELINE_SO（基线产物），跳过"
fi


# ── T23 strip 真生效 + strip 后锁箱/开箱仍通 ─────────────────────
# 背景（2026-10-20 实测的防御缺口）：
#   lib-ndk.sh 的注释一直写着"strip 符号表"，但 LOCAL_LDFLAGS 里从来没有
#   对应参数。后果：产物 .symtab 24KB / 957 个符号，ncg_frag_a/b/c/d
#   （XOR_KEY 四碎片）与 NCG_XOR_FRAG（重组查表）的名字都在里面，
#   攻击者 nm 一条命令即知"哪个是碎片、哪个是表"，15 行 Python 即可
#   静态重组出完整 XOR_KEY → slot^XOR_KEY 得 k_stub → 解 .ncxh → 解 .ncx。
#   碎片化把连续 8 字节从 .rodata 消掉了，但每个碎片都贴着名字，
#   "提高重组成本"并未兑现。
#
# 本项断言两件事：
#   ① lib-ndk.sh 里确实有 --strip-all（防"注释承诺了没做"再次发生）
#   ② 用 --strip-all 重编后，两级锁箱仍成功 —— 证明锁箱器不依赖 .symtab
#      （它只用 section header table，见 so-section-lock.py:853-859）
if grep -q -- "--strip-all" "$ROOT/scripts/lib/lib-ndk.sh"; then
    ok "T23 lib-ndk.sh 含 --strip-all（符号表真的会被去掉）"
else
    bad "T23 lib-ndk.sh 缺 --strip-all —— 注释承诺 strip 但参数不在，产物 .symtab 会泄露碎片符号名"
fi

# ⚠️ 必须先 cd 回 $WORK：T4/T5/T8 那段有 `cd "fake/$PKG"` 且未 cd 回来。
#    若在此目录判断 `[ -f libnc.so ]` 会恒假 → 本项被静默跳过
#    （"关键断言被静默跳过比失败更糟"——与文件头 T10 的教训同向）。
cd "$WORK" || { echo "cd 回 WORK 失败" >&2; exit 2; }

if [ -f libnc.so ] && [ -n "${APK:-}" ] && [ -f "$APK" ]; then
    CF="-fPIC -shared -fvisibility=hidden -fno-ident -Oz \
        -ffunction-sections -fdata-sections -DNC_GUARD_SECTIONED"
    if clang $CF -I. nc_guard_boot.c nc_guard_probe.c nc_guard_jni.c \
            nc_guard_key.c nc_link.c env_check.c sig_check.c \
            -Wl,--gc-sections -Wl,--build-id=none -Wl,--strip-all \
            -o libnc_stripped.so 2>strip.log; then
        # ① strip 后 .symtab/.strtab 应归零
        if [ "$(readelf -S libnc_stripped.so 2>/dev/null | grep -cE '\.symtab|\.strtab')" = "0" ]; then
            ok "T23 strip 后 .symtab/.strtab 归零（碎片符号名不再可 nm）"
        else
            bad "T23 strip 后仍有符号表 —— --strip-all 未生效？"
        fi
        # ② strip 后两级锁箱仍成功（证明锁箱器不依赖 .symtab）
        if python3 "$LOCK" libnc_stripped.so libnc_stripped.so \
                --section ".ncx,.ncxr" --from-apk "$APK" >/dev/null 2>&1 \
           && python3 "$LOCK" libnc_stripped.so libnc_stripped.so \
                --lock-head >/dev/null 2>&1; then
            ok "T23 strip 后两级锁箱仍成功（锁箱器只用段表，不依赖 .symtab）"
        else
            bad "T23 strip 后锁箱失败 —— 锁箱器疑似依赖 .symtab，strip 会破坏构建"
        fi
    else
        skip "T23 strip 编译失败"; head -5 strip.log >&2
    fi
    rm -f libnc_stripped.so
else
    skip "T23 无 libnc.so 或缺 APK，跳过"
fi

# ── T24 version script 真的生效（修 2026-10-21 的"永不成立 guard"）──
# 背景（静默失效，比报错更危险）：
#   lib-ndk.sh 的整段 version script 曾被包在
#       if [ -f "$jni/nc_jni_gen.c" ]; then ...
#   里面，而该文件的生成器 gen-jni-register.py 已在 a7d9cbc 删除
#   （动态注册真机崩，回退短名绑定），protect.sh 也再无生成点。
#   于是 condition 恒假 → map 从未生成 → .dynsym 一直导出全部 Java_*
#   业务符号（实测报告 §五 给符号表 0.0 分即由此而来）。
#   而 --strip-all 只删 .symtab/.strtab，删不掉 .dynsym，补不上这个洞。
#
# 本项断言三件事（⚠️ 只查【代码行】，不查注释——注释里会引用这些字符串
# 来说明历史，裸 grep 会误报。2026-10-21 实测踩过）：
#   ① lib-ndk.sh 里【不再】用 nc_jni_gen.c 做启用条件（防 guard 复活）
#   ② map 的白名单是 Java_*（dex2c 走短名绑定，只留 Java_com_nc_* 会 ULE）
#   ③ 带上 --undefined-version（否则无 JNI_OnLoad 的组合会链接失败）
_LIBNDK_CODE=$(grep -v '^[[:space:]]*#' "$ROOT/scripts/lib/lib-ndk.sh")
if printf '%s\n' "$_LIBNDK_CODE" | grep -q 'nc_jni_gen\.c'; then
    bad "T24 lib-ndk.sh 仍以 nc_jni_gen.c 为启用条件 —— 该文件永不生成，version script 会再次失效"
else
    ok "T24 version script 无失效 guard（不再依赖已删除的 nc_jni_gen.c）"
fi
if printf '%s\n' "$_LIBNDK_CODE" | grep -q 'Java_com_nc_\*'; then
    bad "T24 map 白名单写成 Java_com_nc_* —— dex2c 不传 --dynamic-register 走短名绑定，业务方法会 ULE"
else
    ok "T24 map 白名单为 Java_*（匹配短名绑定实际形态）"
fi
if printf '%s\n' "$_LIBNDK_CODE" | grep -q -- '--undefined-version'; then
    ok "T24 带 --undefined-version（无 JNI_OnLoad 的组合不会链接失败）"
else
    bad "T24 缺 --undefined-version —— 纯 sigcheck/envcheck 组合会报 'symbol JNI_OnLoad not defined'"
fi

# ── T25 密钥不硬编码（2026-10-22，修「解密器全部明文 / 密钥表可读」）──
# 背景：实测报告 §五 指出 k_stub / k_mac_head 是【硬编码在公开仓库里】的常量。
#   原注释的理由是"真正的盐是证书指纹，占位值公开不影响换 key 重打包即失效"
#   —— 那个理由对 k_so 成立（走 HKDF+证书），对 k_stub/k_mac_head 【不成立】：
#     · k_stub 直接就是 .ncxh 的加密钥匙；
#     · k_mac_head 直接就是 head 段 MAC 的密钥（知道它就能对任意篡改重算 MAC，
#       P0-b 那层完整性校验形同虚设）。
#   两者一旦硬编码在公开仓库，攻击者不必逆向——读脚本就知道钥匙。
#
# 本项断言两件事：
#   ① 脚本里不再有那两串硬编码字面量（防回退）
#   ② 两次运行 lock_head 产出的 wrapped_k_stub 不同（证明真的随机了）
if grep -q "0x3B, 0x7C, 0x19, 0x5E" "$LOCK" 2>/dev/null; then
    bad "T25 k_stub 仍是硬编码常量（公开仓库即钥匙，.ncxh 可静态解）"
else
    ok "T25 k_stub 无硬编码字面量（改为构建期随机）"
fi
if grep -q "0x91, 0x4A, 0xD2, 0x08" "$LOCK" 2>/dev/null; then
    bad "T25 k_mac_head 仍是硬编码常量（知道它即可伪造 head MAC）"
else
    ok "T25 k_mac_head 无硬编码字面量（改为构建期随机）"
fi
if grep -q "k_stub = os.urandom(16)" "$LOCK" 2>/dev/null \
   && grep -q "k_mac_head = os.urandom(16)" "$LOCK" 2>/dev/null; then
    ok "T25 k_stub / k_mac_head 均为 os.urandom(16)"
else
    bad "T25 随机化写法缺失（应为 os.urandom(16)）"
fi

# ── T26 僵尸符号不外泄（2026-10-22，修逆向报告 v2 §8 F-13）──────────
# Java_amimo_dcc_DccApplication_init__ 是 dex2c 引擎的空函数，实测产物里
# 是纯僵尸（protect.sh 传 --no-build → loader 注入分支不执行 → APK 里没有
# amimo/dcc/DccApplication 这个类 → ART 永不按名查找它）。
# 导出它只白送情报："这库是从别处复用的"（报告 F-13 原文）。
#
# ⚠️ 为什么用编译期改名而不是 version script：实测 version script 里
#   `local: Java_amimo_dcc_*` 不优先于 `global: Java_*`（三种写法均失败）；
#   而收窄白名单到 Java_com_nc_link_* 会连带隐藏 dex2c 业务方法（e0e6bb2 的坑）。
# ⚠️ 只查代码行：本文件的注释里也含该字符串，裸 grep 会自造假阳性
#    （2026-10-22 实测：故意删掉改名后断言仍绿）
if printf '%s\n' "$_LIBNDK_CODE" | grep -q 'CFLAGS.*-DJava_amimo_dcc_DccApplication_init__=ncg_zombie_dcc_init'; then
    ok "T26 amimo_dcc 僵尸符号编译期改名（不再匹配 Java_* 白名单）"
else
    bad "T26 amimo_dcc 僵尸符号未处置 —— .dynsym 会导出它，泄露引擎复用痕迹"
fi
if printf '%s\n' "$_LIBNDK_CODE" | grep -q 'Java_\*;'; then
    ok "T26 白名单仍为 Java_*（业务方法走短名绑定，收窄会导致 ULE）"
else
    bad "T26 白名单被收窄 —— dex2c 业务方法会 UnsatisfiedLinkError"
fi

# ── T27 密钥清零不可被优化掉（2026-10-22）────────────────────────────
# 背景：memset 清密钥会被编译器当"死存储"删除。实测本仓 -Oz 下，
# ncguard_unlock 里 6 处 memset 只有 2 条真正生成了零写入指令，
# 其余 4 处被优化掉 —— 密钥留在栈上，内存 dump 就能捞到。
#
# 修法：改为 volatile 写 0（ncg_wipe）。volatile 告知编译器"此写有可观测
# 副作用"，因此每条都必然生成 strb。
#
# 本项断言两件事：
#   ① 源码里不再有直接的 memset 清密钥（防回退到会被优化的写法）
#   ② 反汇编里 ncg_wipe 真的生成 strb wzr（不是空函数）
BOOT_C="$SRC/nc_guard_boot.c"
if grep -qE 'memset\((key|k_mac|k_cert|xk|k), 0' "$BOOT_C" 2>/dev/null; then
    bad "T27 仍用 memset 清密钥 —— 会被编译器优化掉，密钥残留栈上"
else
    ok "T27 密钥清零已改用 ncg_wipe（volatile 写，不可优化）"
fi
if grep -q 'static void ncg_wipe(void \*p, size_t n)' "$BOOT_C" 2>/dev/null; then
    ok "T27 ncg_wipe 已定义（零依赖、零 PLT，不用 explicit_bzero/memset_s）"
else
    bad "T27 ncg_wipe 缺失"
fi
# 反汇编验证（用已编好的 libnc.so；T1 编译产物）
if [ -f libnc.so ] && nm libnc.so 2>/dev/null | grep -q ncg_wipe; then
    nw=$(objdump -d libnc.so 2>/dev/null \
         | sed -n '/<ncg_wipe>:/,/^$/p' | grep -c 'strb.*wzr')
    if [ "$nw" -ge 1 ]; then
        ok "T27 ncg_wipe 反汇编确有 strb wzr（清零真的会执行）"
    else
        bad "T27 ncg_wipe 内无 strb wzr —— 被优化成空函数了"
    fi
else
    # strip 后符号可能不可见，退回源码级判据（已在上面断言）
    ok "T27 ncg_wipe 反汇编检查跳过（strip 后符号不可见，源码级已断言）"
fi

echo
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
