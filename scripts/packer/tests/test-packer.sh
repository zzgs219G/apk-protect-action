#!/usr/bin/env bash
# packer.sh 契约测试（不依赖真 dpt / 真 APK）
#
# A. 产物提取链路（stub 替换 java）：
#   ① 正常路径 exit 0
#   ② 输入绝对路径透传
#   ③ 规则表透传给 dpt（-r 指向包内模板）
#   ④ -x 不签名
#   ⑤ 产物唯一时落盘 OUT
#   ⑥ dpt 的 cwd = tools/executable（getExecutablePath() 布局前提）
#   ⑦ packer.sh 自身对 runner 可执行（protect.sh 无 bash 前缀直接调用）
#   ⑧⑨ 产物缺失 → fail-fast 且不落半成品
#   ⑩⑪ 产物多个 → fail-fast 且不瞎猜
#   ⑫ 输入缺失 → fail-fast
#
# B. 编排与 schema 契约：
#   ⑬ --packer 走完整流水线不被占位拦截
#   ⑭ packer 拿到的是已对齐包（aligned.apk，非回编原包）
#   ⑮⑯ schema 里有 packer 条目且 arg 为 --packer
#   ⑰ 勾选 packer → resolve-config 吐 --packer
#   ⑱ 旧 App 快照无 packer 键 → 视为 disabled 不报错（向后兼容）
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PACKER="$ROOT/scripts/packer/packer.sh"
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
fail=0

check() { if [[ "$2" == "$3" ]]; then echo "  ✅ $1"; else echo "  ❌ $1  期望[$3] 实际[$2]"; fail=1; fi; }

echo "== packer.sh 产物提取链路冒烟 =="

# ── stub java：按 STUB_MODE 造出不同产物形态，并把收到的参数写盘 ──
mkdir -p "$STUB_DIR/bin"
cat > "$STUB_DIR/bin/java" <<'STUB'
#!/usr/bin/env bash
out=""; inp=""; rules=""; no_sign=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -f) inp="$2"; shift 2 ;;
    -r) rules="$2"; shift 2 ;;
    -x) no_sign=1; shift ;;
    *) shift ;;
  esac
done
printf 'IN=%s\nRULES=%s\nNO_SIGN=%s\nCWD=%s\n' "$inp" "$rules" "$no_sign" "$PWD" > "$ARGS_FILE"
mkdir -p "$out"
case "$STUB_MODE" in
  one)   : > "$out/com.test.app_unsign.apk" ;;
  none)  : ;;
  multi) : > "$out/a_unsign.apk"; : > "$out/b_unsign.apk" ;;
esac
STUB
chmod +x "$STUB_DIR/bin/java"

run_stub() {  # run_stub <mode> <in> <out>
  ARGS_FILE="$STUB_DIR/args.txt" STUB_MODE="$1" \
    PATH="$STUB_DIR/bin:$PATH" bash "$PACKER" "$2" "$3" >"$STUB_DIR/log.txt" 2>&1
}

echo "" # 正常路径
: > "$STUB_DIR/in.apk"
run_stub one "$STUB_DIR/in.apk" "$STUB_DIR/o.apk"; rc=$?
check "①正常路径 exit 0" "$rc" "0"
check "②输入绝对路径透传" "$(grep -c "^IN=$STUB_DIR/in.apk" "$STUB_DIR/args.txt")" "1"
check "③规则表指向包内模板" \
  "$(grep -c '^RULES=.*/tools/executable/dpt-exclude-classes-template.rules$' "$STUB_DIR/args.txt")" "1"
check "④带 -x 不签名" "$(grep -c '^NO_SIGN=1$' "$STUB_DIR/args.txt")" "1"
check "⑤产物已落盘 OUT" "$([[ -f "$STUB_DIR/o.apk" ]] && echo yes || echo no)" "yes"
# dpt 的 getExecutablePath() = jar 所在目录 → cwd 必须是 tools/executable。
# 这条断言曾缺失：module_cd_run 被误改或 zip 顶层多套一层 executable/ 时，
# 整套测试照样全绿，而真实 dpt 会因找不到 shell-files/ 失败。
check "⑥dpt 在 tools/executable 下运行(shell-files 可寻址)" \
  "$(grep -c "^CWD=$ROOT/tools/executable$" "$STUB_DIR/args.txt")" "1"
# protect.sh 是无 bash 前缀直接调用 packer.sh 的 → 文件必须对 runner 可执行。
# 曾因本地 umask 产生 0700，CI 非 owner 身份会 Permission denied，而整套
# stub 测试因「要么 chmod +x 要么整体覆盖」完全看不到这一条。
check "⑦packer.sh 对 CI runner 可执行(mode 含 x 位)" \
  "$([[ -x "$PACKER" ]] && echo exec || echo noexec)" "exec"

echo ""
echo "" # 产物缺失
rm -f "$STUB_DIR/o.apk"
run_stub none "$STUB_DIR/in.apk" "$STUB_DIR/o.apk"; rc=$?
check "⑧产物缺失 exit!=0" "$([[ $rc -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check "⑨产物缺失时不落盘半成品" "$([[ -f "$STUB_DIR/o.apk" ]] && echo yes || echo no)" "no"

echo ""
echo "" # 产物多个
run_stub multi "$STUB_DIR/in.apk" "$STUB_DIR/o.apk"; rc=$?
check "⑩产物多个 exit!=0" "$([[ $rc -ne 0 ]] && echo nonzero || echo zero)" "nonzero"
check "⑪产物多个不瞎猜(不落盘)" "$([[ -f "$STUB_DIR/o.apk" ]] && echo yes || echo no)" "no"

echo ""
echo "" # 输入缺失
run_stub one "$STUB_DIR/nope.apk" "$STUB_DIR/o.apk"; rc=$?
check "⑫输入缺失 exit!=0" "$([[ $rc -ne 0 ]] && echo nonzero || echo zero)" "nonzero"

echo ""
echo "" # ⑬⑭ 编排：protect.sh 接受 --packer，占位报错已下线
: > "$STUB_DIR/pin.txt"
: > "$STUB_DIR/pout.txt"
STUB_P="$STUB_DIR/java"
cat > "$STUB_P" <<'STUB'
#!/usr/bin/env bash
apktool=0; out=""; mode=""; prev=""
for a in "$@"; do
  [[ "$prev" == "-jar" ]] && [[ "$a" == *apktool.jar ]] && apktool=1
  [[ "$prev" == "-o" ]] && out="$a"
  case "$a" in d) mode="d" ;; b) mode="b" ;; esac
  prev="$a"
done
[[ $apktool -eq 1 ]] || exit 0
if [[ -n "$out" ]]; then
  if [[ "$mode" == "d" ]]; then
    mkdir -p "$out/smali"; printf 'x' > "$out/AndroidManifest.xml"
  elif [[ "$mode" == "b" ]]; then
    python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("AndroidManifest.xml","x"); z.writestr("classes.dex","dex"); z.close()' "$out"
  fi
fi
exit 0
STUB
chmod +x "$STUB_P"
# 记录 packer.sh 入参的替身。
# ⚠️ 必须在 finally 语义上把真脚本还回去（restore 先 mv 再 rm）：一旦中断，
# 宁可让工作区留下桩，也要保证 restore 有机会跑；且桩里不 copy 回真脚本，
# 避免用过期内容覆盖此后对 packer.sh 的真实修改（自查抓到的测试反模式）。
cat > "$STUB_DIR/record-packer.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$1" > "$PACKER_IN_FILE"
printf '%s\n' "$2" > "$PACKER_OUT_FILE"
: > "$2"
STUB
chmod 755 "$STUB_DIR/record-packer.sh"
mv "$ROOT/scripts/packer/packer.sh" "$STUB_DIR/packer-real.sh"
cp "$STUB_DIR/record-packer.sh" "$ROOT/scripts/packer/packer.sh"
restore() {
  [[ -f "$STUB_DIR/packer-real.sh" ]] || return 0
  mv -f "$STUB_DIR/packer-real.sh" "$ROOT/scripts/packer/packer.sh"
  chmod 755 "$ROOT/scripts/packer/packer.sh"
}
trap 'restore; rm -rf "$STUB_DIR"' EXIT

python3 - "$STUB_DIR/in2.apk" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("AndroidManifest.xml", "x")
    z.writestr("classes.dex", "dex")
PY
mkdir -p "$STUB_DIR/bin" && cp "$STUB_P" "$STUB_DIR/bin/java"
ARGS_FILE="$STUB_DIR/args.txt" STUB_MODE="one" PACKER_IN_FILE="$STUB_DIR/pin.txt" \
  PACKER_OUT_FILE="$STUB_DIR/pout.txt" PATH="$STUB_DIR/bin:$PATH" \
  bash "$ROOT/scripts/pipelines/protect.sh" "$STUB_DIR/in2.apk" "$STUB_DIR/o3.apk" \
  --packer >"$STUB_DIR/log3.txt" 2>&1
rc=$?
check "⑬--packer 走完整流水线不被占位拦截" "$rc" "0"
check "⑭packer 拿到的是已对齐包(非回编原包)" \
  "$([[ "$(cat "$STUB_DIR/pin.txt" 2>/dev/null)" != *unsigned.apk ]] && echo yes || echo no)" "yes"
restore

echo "" # schema → 参数 端到端契约
SCHEMA="$ROOT/configs/v1/config-schema.json"
check "⑮schema 含 packer 条目" \
  "$(grep -c '"key": "packer"' "$SCHEMA")" "1"
check "⑯schema packer arg 为 --packer" \
  "$(grep -c '"arg": "--packer"' "$SCHEMA")" "1"

RESOLVE_ROOT="$STUB_DIR/rr"
mkdir -p "$RESOLVE_ROOT/configs/v1"
cp "$SCHEMA" "$RESOLVE_ROOT/configs/v1/"
# §10.5：GITHUB_WORKSPACE 优先于 __file__ 推算 → 产物落在 RESOLVE_ROOT 下
(cd "$RESOLVE_ROOT" && INPUT_PROTECT_CONFIG='{"schema_version":1,"packer":true}' \
  GITHUB_WORKSPACE="$RESOLVE_ROOT" python3 "$ROOT/scripts/actions/resolve-config.py" \
  >"$STUB_DIR/resolve.log" 2>&1)
check "⑰勾选 packer → 吐 --packer" \
  "$(grep -cx -- '--packer' "$RESOLVE_ROOT/schema_rules/args.txt" 2>/dev/null || echo 0)" "1"

(cd "$RESOLVE_ROOT" && INPUT_PROTECT_CONFIG='{"schema_version":1,"sigcheck":true}' \
  GITHUB_WORKSPACE="$RESOLVE_ROOT" python3 "$ROOT/scripts/actions/resolve-config.py" \
  >"$STUB_DIR/resolve2.log" 2>&1)
check "⑱旧 App 快照无 packer 键 → 不报错(向后兼容)" \
  "$(grep -c -- '--packer' "$RESOLVE_ROOT/schema_rules/args.txt" 2>/dev/null | head -1)" "0"

echo ""
[[ $fail -eq 0 ]] && echo "packer 冒烟全绿" || echo "packer 冒烟有失败"
exit $fail