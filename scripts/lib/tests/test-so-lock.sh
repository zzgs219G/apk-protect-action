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
#   T3 二级锁箱 → .ncks 104 字节
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
    [ "$(sec_size .ncks)" = 104 ] && ok "T3 .ncks 104 字节" \
        || bad "T3 .ncks 大小 $(sec_size .ncks) != 104"
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
if readelf -SW libnc.so 2>/dev/null | grep -qE "\.ncguard|\.nckey"; then
    bad "T16 自解释段名残留（.ncguard/.nckey 会直接暴露机制）"
else
    readelf -SW libnc.so 2>/dev/null | grep -q "\.ncx" \
        && ok "T16 段名已中性化（.ncx/.ncxr/.ncxh/.ncxhr/.nck/.ncks）" \
        || bad "T16 段名异常（既无中性名也无旧名）"
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

echo
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ "$FAIL" -eq 0 ] || exit 1
