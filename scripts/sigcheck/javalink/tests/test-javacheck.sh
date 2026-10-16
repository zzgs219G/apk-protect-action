#!/usr/bin/env bash
# test-javacheck.sh — Java 层判决式签名校验 · 宿主冒烟(非 CI 完整链路)
#
# 覆盖:py_compile / javac 语义真相源(对 android API 桩)/ AXML 夹具生成 /
#       注入 + SmaliBuilder 真汇编 + androguard 读回 / 调用点寄存器安全 /
#       幂等 / clean / 自适应命名(普通包+R8 短名包)/ nc_link.c 判决对拍
# 完整链路(dex2c 转译、ndk-build、apktool 回编、真机)由 CI workflow 闭环。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../../.." && pwd)"
[[ -f "$ROOT/AGENTS.md" ]] || { echo "❌ ROOT 定位失败"; exit 1; }
JL="$ROOT/scripts/sigcheck/javalink"
APKTOOL="$ROOT/tools/dcc/tools/apktool.jar"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
PASS=0
ok() { echo "  ✅ $1"; PASS=$((PASS + 1)); }

[[ -f "$APKTOOL" ]] || { echo "❌ apktool 不在位(先 ensure_dcc 或解压 dcc.zip)"; exit 1; }

echo "[1/9] py_compile + javac 语义真相源(对 android API 桩编译,校验 API 形态)"
python3 -m py_compile "$JL/inject-javacheck.py"
python3 -m py_compile "$JL/tests/mk_manifest.py"
mkdir -p "$T/stubs/android/content/pm" "$T/stubs/android/os" "$T/stubs/android/util" "$T/classes"
cat > "$T/stubs/android/content/Context.java" <<'EOF'
package android.content;
public class Context {
    public android.content.pm.PackageManager getPackageManager() { return null; }
    public String getPackageName() { return null; }
}
EOF
cat > "$T/stubs/android/content/pm/PackageManager.java" <<'EOF'
package android.content.pm;
public class PackageManager {
    public static final int GET_SIGNATURES = 0x40;
    public static final int GET_SIGNING_CERTIFICATES = 0x08000000;
    public PackageInfo getPackageInfo(String pkg, int flags) throws NameNotFoundException { return null; }
}
EOF
cat > "$T/stubs/android/content/pm/PackageInfo.java" <<'EOF'
package android.content.pm;
public class PackageInfo {
    public Signature[] signatures;
    public SigningInfo signingInfo;
}
EOF
cat > "$T/stubs/android/content/pm/Signature.java" <<'EOF'
package android.content.pm;
public class Signature { public byte[] toByteArray() { return null; } }
EOF
cat > "$T/stubs/android/content/pm/SigningInfo.java" <<'EOF'
package android.content.pm;
public class SigningInfo { public Signature[] getApkContentsSigners() { return null; } }
EOF
cat > "$T/stubs/android/content/pm/NameNotFoundException.java" <<'EOF'
package android.content.pm;
public class NameNotFoundException extends Exception {}
EOF
cat > "$T/stubs/android/os/Build.java" <<'EOF'
package android.os;
public class Build { public static class VERSION { public static final int SDK_INT = 28; } }
EOF
cat > "$T/stubs/android/os/Process.java" <<'EOF'
package android.os;
public class Process {
    public static int myPid() { return 0; }
    public static void killProcess(int pid) {}
}
EOF
cat > "$T/stubs/android/util/Log.java" <<'EOF'
package android.util;
public class Log {
    public static int w(String tag, String msg) { return 0; }
    public static int d(String tag, String msg) { return 0; }
    public static int e(String tag, String msg) { return 0; }
}
EOF
javac -nowarn -d "$T/classes" \
  "$T/stubs/android/content/Context.java" \
  "$T/stubs/android/content/pm/"*.java \
  "$T/stubs/android/os/"*.java \
  "$T/stubs/android/util/"*.java \
  "$JL/stub-src/NcLink.java" \
  "$JL/stub-src/NcGuard.java" \
  "$JL/stub-src/Guard.java"
ok "javac 语义真相源编译通过(Guard/NcLink 与桩 API 形态一致)"

echo "[2/9] 合成解包目录 + AXML 夹具"
mkdir -p "$T/app/smali/com/test/jc"
python3 "$JL/tests/mk_manifest.py" "$T/app/AndroidManifest.xml" >/dev/null
cat > "$T/app/smali/com/test/jc/App.smali" <<'EOF'
.class public Lcom/test/jc/App;
.super Landroid/app/Application;

.method public onCreate()V
    .locals 1
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    return-void
.end method
EOF
cat > "$T/app/smali/com/test/jc/MainActivity.smali" <<'EOF'
.class public Lcom/test/jc/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .locals 1
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method
EOF
# Secondary:两个 LAUNCHER 之一,且没有 onCreate → 覆写新建路径
cat > "$T/app/smali/com/test/jc/Secondary.smali" <<'EOF'
.class public Lcom/test/jc/Secondary;
.super Landroid/app/Activity;

.method public onStart()V
    .locals 0
    invoke-super {p0}, Landroid/app/Activity;->onStart()V
    return-void
.end method
EOF
# Big:onCreate 用 .registers 40 → p0=v38 > v15,必须被寄存器安全检查弃用
cat > "$T/app/smali/com/test/jc/Big.smali" <<'EOF'
.class public Lcom/test/jc/Big;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .registers 40
    return-void
.end method
EOF
ok "合成目录就绪(App/MainActivity/Secondary/Big + 二进制 manifest)"

echo "[3/9] 注入(确定性 --wrapper-name)"
python3 "$JL/inject-javacheck.py" "$T/app" --wrapper-name 'Lcom/test/jc/NativeGuard;'
ok "注入器退出 0"

echo "[4/9] SmaliBuilder 真汇编(语法+寄存器合法性裁决)"
javac -nowarn -cp "$APKTOOL" -d "$T/probe" "$JL/tests/AsmProbe.java"
java -cp "$T/probe:$APKTOOL" AsmProbe "$T/out.dex" \
  "$T/app/smali/com/test/jc/App.smali" \
  "$T/app/smali/com/test/jc/MainActivity.smali" \
  "$T/app/smali/com/test/jc/Secondary.smali" \
  "$T/app/smali/com/test/jc/Big.smali" \
  "$T/app/smali/com/nc/link/NcLink.smali" \
  "$T/app/smali/com/test/jc/NativeGuard.smali" > /dev/null
ok "6 个 smali 全部汇编通过(无 Invalid register / no viable alternative)"

echo "[5/9] androguard 读回(dex 层结构断言)"
python3 - "$T/out.dex" <<'PY'
import sys
sys.path.insert(0, 'tools/dcc')
from androguard.core.bytecodes.dvm import DalvikVMFormat
dvm = DalvikVMFormat(open(sys.argv[1], 'rb').read())
classes = {c.get_name(): c for c in dvm.get_classes()}
fails = []
def check(cond, msg):
    if not cond: fails.append(msg)

guard, bridge = 'Lcom/test/jc/NativeGuard;', 'Lcom/nc/link/NcLink;'
check(guard in classes and bridge in classes, '新类缺失')
g = classes[guard]; b = classes[bridge]
gmethods = {m.get_name() + m.get_descriptor(): m for m in g.get_methods()}
check('c(Landroid/content/Context;)V' in gmethods, 'Guard.c 缺失')
bmethods = {m.get_name() + m.get_descriptor(): m for m in b.get_methods()}
check('ncVerify([B)Z' in bmethods, 'NcLink.ncVerify 缺失')
check('native' in bmethods['ncVerify([B)Z'].get_access_flags_string(), 'ncVerify 非 native')
check('ensureLoaded()V' in bmethods, 'NcLink.ensureLoaded 缺失')
loaded = bmethods['ensureLoaded()V'].get_code().get_bc().get_instructions()
consts = [i.get_output() for i in loaded if i.get_name() == 'const-string']
check(any("'nc'" in o for o in consts), 'ensureLoaded 未加载 nc')

def has_call(cls_name, meth_name):
    c = classes[cls_name]
    for m in c.get_methods():
        if m.get_name() == meth_name and m.get_code():
            for ins in m.get_code().get_bc().get_instructions():
                if ins.get_name() == 'invoke-static' and 'NativeGuard;->c(' in ins.get_output():
                    return True
    return False

check(has_call('Lcom/test/jc/App;', 'onCreate'), 'App.onCreate 缺调用点')
check(has_call('Lcom/test/jc/MainActivity;', 'onCreate'), 'MainActivity.onCreate 缺调用点')
check(has_call('Lcom/test/jc/Secondary;', 'onCreate'), 'Secondary.onCreate(新建覆写)缺调用点')
check(not has_call('Lcom/test/jc/Big;', 'onCreate'), 'Big 寄存器不安全却仍被注入(p0>v15)')

gcode = gmethods['c(Landroid/content/Context;)V'].get_code()
tries = gcode.get_tries() if hasattr(gcode, 'get_tries') else []
check(len(tries) >= 1, 'Guard.c 缺 try/catch(UnsatisfiedLinkError fail-closed 依赖它)')
# 报错四十二:ensureLoaded 必须是 Guard.c 的第一条调用——so 加载先于测量。
# 旧版它排在测量链末尾:测量抛任何非 ULE Throwable → catch_skip 静默返回
# → ensureLoaded 永不执行 → so 永不加载 → constructor 永不跑,两层防线
# 静默全灭(真机实证:删净 so 自带 loadLibrary 注入点后换 key 不杀)。
first_invoke = next((i.get_output() for i in gcode.get_bc().get_instructions()
                     if i.get_name().startswith('invoke-')), None)
check(first_invoke is not None and 'ensureLoaded' in first_invoke,
      f'Guard.c 第一条调用不是 ensureLoaded(报错四十二): {first_invoke}')
# 报错四十九(2026-10-16):心跳喂食必须前置到测量链之前,与"测量是否成功"解耦。
# 旧形态放在 ncVerify 之后 → 测量抛非 ULE 异常经 :catch_skip 静默返回 → 一次不喂
# → env_watchdog 误判"壳被删" → 正常包冷启动必杀(docs/sigcheck_log.txt 实证)。
invokes = [i.get_output() for i in gcode.get_bc().get_instructions()
           if i.get_name().startswith('invoke-')]
def _idx(needle):
    return next((k for k, o in enumerate(invokes) if needle in o), -1)
i_load, i_beat, i_start, i_verify = (_idx('ensureLoaded'), _idx('heartbeat'),
                                     _idx('startHeartbeat'), _idx('ncVerify'))
check(i_beat > i_load, f'heartbeat 不在 ensureLoaded 之后(报错四十九): {invokes}')
check(i_start > i_load, f'startHeartbeat 不在 ensureLoaded 之后(报错四十九): {invokes}')
check(0 < i_verify and i_beat < i_verify,
      f'heartbeat 未前置到 ncVerify 之前,测量异常会误杀(报错四十九): {invokes}')
check(0 < i_verify and i_start < i_verify,
      f'startHeartbeat 未前置到 ncVerify 之前(报错四十九): {invokes}')
if fails:
    print('\n'.join('❌ ' + f for f in fails)); sys.exit(1)
print('  ✅ 读回断言全部通过')
PY
PASS=$((PASS + 1))

echo "[5b/9] 报错三十九回归——native onCreate 壳必须跳过(dex2c 组合场景防回编炸)"
python3 - "$JL/inject-javacheck.py" <<'PY'
import importlib.util, sys, os, tempfile
spec = importlib.util.spec_from_file_location('ij', sys.argv[1])
ij = importlib.util.module_from_spec(spec); spec.loader.exec_module(ij)

# mark-native(dex2c)抽走方法体后的 native 壳形态:无指令、无 .locals
native_stub = (
    '.class public Lcom/xixin/box/MainActivity;\n'
    '.super Landroid/app/Activity;\n'
    '\n'
    '.method public native onCreate(Landroid/os/Bundle;)V\n'
    '.end method\n')
path = os.path.join(tempfile.mkdtemp(), 'MainActivity.smali')
with open(path, 'w') as fp:
    fp.write(native_stub)
changed, note = ij.inject_call_site(path, 'Lcom/xixin/box/NativeGuard;')
assert changed is False and note == 'native-onCreate', (changed, note)
with open(path) as fp:
    assert fp.read() == native_stub, 'native 壳被改动(报错三十九回归:曾凭空造方法体)'
assert ij.CALL_MARKER not in native_stub
print('  ✅ native onCreate 壳:跳过 + 文件零改动(note=native-onCreate)')

# 对照:普通 onCreate 不回归(注入照常生效)
normal = native_stub.replace(
    '.method public native onCreate(Landroid/os/Bundle;)V\n.end method\n',
    '.method public onCreate(Landroid/os/Bundle;)V\n'
    '    .locals 2\n'
    '    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V\n'
    '    return-void\n'
    '.end method\n')
with open(path, 'w') as fp:
    fp.write(normal)
changed, note = ij.inject_call_site(path, 'Lcom/xixin/box/NativeGuard;')
assert changed is True, note
with open(path) as fp:
    body = fp.read()
assert 'invoke-static {p0}, Lcom/xixin/box/NativeGuard;->c(Landroid/content/Context;)V' in body
print('  ✅ 普通 onCreate:注入照常生效(无过度收紧)')
os.unlink(path)
PY
PASS=$((PASS + 1))

echo "[6/9] 幂等(重跑零改动)"
H1=$(find "$T/app" -type f -exec md5sum {} \; | sort | md5sum)
python3 "$JL/inject-javacheck.py" "$T/app" --wrapper-name 'Lcom/test/jc/NativeGuard;'
H2=$(find "$T/app" -type f -exec md5sum {} \; | sort | md5sum)
[[ "$H1" == "$H2" ]] && ok "目录哈希不变" || { echo "❌ 重跑产生了改动"; exit 1; }

echo "[7/9] clean(删生成类 + 摘调用点 + 再汇编仍合法)"
python3 "$JL/inject-javacheck.py" clean "$T/app"
[[ ! -f "$T/app/javacheck-components.json" ]] || { echo "❌ components json 未删"; exit 1; }
[[ ! -f "$T/app/smali/com/nc/link/NcLink.smali" ]] || { echo "❌ NcLink 未删"; exit 1; }
! grep -rq 'nc-javacheck-call' "$T/app/smali" || { echo "❌ 调用点未清"; exit 1; }
java -cp "$T/probe:$APKTOOL" AsmProbe "$T/out2.dex" \
  "$T/app/smali/com/test/jc/App.smali" \
  "$T/app/smali/com/test/jc/MainActivity.smali" \
  "$T/app/smali/com/test/jc/Secondary.smali" > /dev/null
ok "clean 后调用点归零,残留 smali 仍可汇编"

echo "[8/9] 自适应命名(普通包派生 / R8 短名包风格)"
W=$(python3 - "$T/app" <<'PY'
import importlib.util, sys, os
spec = importlib.util.spec_from_file_location('ij', 'scripts/sigcheck/javalink/inject-javacheck.py')
ij = importlib.util.module_from_spec(spec); spec.loader.exec_module(ij)
names = ij.scan_class_names(sys.argv[1])
print(ij.pick_wrapper_name(sys.argv[1], 'com.test.jc', None))
PY
)
[[ "$W" == 'Lcom/test/jc/NativeGuard;' ]] && ok "普通包 → 包名派生($W)" \
  || { echo "❌ 普通包命名异常: $W"; exit 1; }

mkdir -p "$T/obf/smali/p/q"
python3 "$JL/tests/mk_manifest.py" "$T/obf/AndroidManifest.xml" 'p.q' 'p.q.a' 'p.q.b' 'p.q.b' >/dev/null
cat > "$T/obf/smali/p/q/a.smali" <<'EOF'
.class public Lp/q/a;
.super Landroid/app/Application;
.method public onCreate()V
    .locals 0
    invoke-super {p0}, Landroid/app/Application;->onCreate()V
    return-void
.end method
EOF
cat > "$T/obf/smali/p/q/b.smali" <<'EOF'
.class public Lp/q/b;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .locals 0
    invoke-super {p0, p1}, Landroid/app/Activity;->onCreate(Landroid/os/Bundle;)V
    return-void
.end method
EOF
cp -r "$T/obf" "$T/obf2"                    # 先留一份干净副本,再分别注入(确定性对照)
python3 "$JL/inject-javacheck.py" "$T/obf" >/dev/null
python3 "$JL/inject-javacheck.py" "$T/obf2" >/dev/null
W1=$(python3 -c "import json;print(json.load(open('$T/obf/javacheck-components.json'))['wrapper'])")
W2=$(python3 -c "import json;print(json.load(open('$T/obf2/javacheck-components.json'))['wrapper'])")
[[ "$W1" == "$W2" ]] && ok "R8 短名包 → 短名风格,且命名确定($W1)" \
  || { echo "❌ 命名不确定: $W1 vs $W2"; exit 1; }

echo "[9/9] nc_link.c 判决逻辑(宿主 clang,生成侧同公式对拍)"
mkdir -p "$T/ncl" "$T/ncl0"
python3 - "$T/ncl" <<'PY'
import hashlib, sys, os
out = sys.argv[1]
fp = hashlib.sha256(b'fp-seed').digest()
salt = hashlib.sha256(b'salt-seed').digest()[:16]
t1 = hashlib.sha256(fp).digest()
stored = bytes(t1[i] ^ salt[i % 16] ^ ((i * 0x9E) & 0xFF) for i in range(32))
def emit(path, stored):
    def arr(b): return ',\n    '.join(', '.join(f'0x{x:02x}' for x in b[i:i+8]) for i in range(0, len(b), 8))
    with open(os.path.join(path, 'sig_hash.h'), 'w') as f:
        f.write(f"""#ifndef _SIG_HASH_H_
#define _SIG_HASH_H_
#define SIG_HASH_LEN 32
#define SIG_SALT_LEN 16
static const unsigned char SIG_SALT[SIG_SALT_LEN] = {{
    {arr(salt)}
}};
static const unsigned char SIG_HASH_STORED[SIG_HASH_LEN] = {{
    {arr(stored)}
}};
#endif
""")
emit(out, stored)
open(os.path.join(out, 'good.bin'), 'wb').write(t1)
bad = bytearray(t1); bad[0] ^= 1
open(os.path.join(out, 'bad.bin'), 'wb').write(bytes(bad))
emit(out + '0', bytes(32))
PY
cp "$ROOT/scripts/sigcheck/src/nc_link.c" "$T/ncl/"   # 引号包含优先搜源文件目录,须就位编译
clang -O1 -DNCLINK_HOST_TEST -I"$T/ncl" \
  "$T/ncl/nc_link.c" "$JL/tests/test-nclink.c" -o "$T/ncl/test"
"$T/ncl/test" "$T/ncl/good.bin" "$T/ncl/bad.bin"
cp "$ROOT/scripts/sigcheck/src/nc_link.c" "$T/ncl0/"
clang -O1 -DNCLINK_HOST_TEST -I"$T/ncl0" \
  "$T/ncl0/nc_link.c" "$JL/tests/test-nclink.c" -o "$T/ncl/test0"
"$T/ncl/test0" "$T/ncl/good.bin" "$T/ncl/good.bin" debug-skip
ok "判决对拍:python 生成侧 == C 校验侧(含调试模式)"

echo ""
echo "══════════════════════════════════════"
echo "✅ test-javacheck 全部通过(共 $PASS 大项)"
echo "══════════════════════════════════════"
