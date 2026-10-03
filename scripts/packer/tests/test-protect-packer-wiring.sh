#!/usr/bin/env bash
# protect.sh 的 --packer 编排冒烟（不依赖 NDK / apktool / dpt）
#
# 用 stub 顶替 java/apktool/ndk-build 与 packer.sh，验证编排层契约：
#   ① --packer 不再被"尚未接入"拦截（占位报错已下线）
#   ② 勾加壳时 packer.sh 确实被调用到
#   ③ packer 拿到的是"已对齐的包"（aligned.apk），而非回编原包 unsigned.apk
#   ④ 勾加壳时产物直接落 OUT，且不对壳包二次 finish_apk
#   ⑤⑥ 不勾加壳时不调用 packer、产物仍落 OUT（与接入前完全一致）
#
# ⚠️ 本测试与 test-packer.sh 都要把 scripts/packer/packer.sh 换成桩，
#    **两个测试必须串行执行**。
set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
PROTECT="$ROOT/scripts/pipelines/protect.sh"
STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
fail=0
check() { if [[ "$2" == "$3" ]]; then echo "  ✅ $1"; else echo "  ❌ $1  期望[$3] 实际[$2]"; fail=1; fi; }

echo "== protect.sh --packer 编排冒烟 =="

# 记录 packer.sh 的入参
cat > "$STUB_DIR/record-packer.sh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "$1" > "$PACKER_IN_FILE"
printf '%s\n' "$2" > "$PACKER_OUT_FILE"
# 落一个有辨识度的标记：若 protect.sh 在加壳后又对 OUT 跑了一次 finish_apk，
# 这个标记会被 zipalign 覆盖掉，断言 ④ 就能抓到"二次 finish_apk"。
printf 'PACKER_OUTPUT_MARKER' > "$2"
STUB
chmod 755 "$STUB_DIR/record-packer.sh"

# 顶替 packer.sh：模块本体已由 scripts/packer/tests/test-packer.sh 覆盖，
# 这里只验证编排层把什么喂给了它。
# ⚠️ 备份放在仓库外的 $STUB_DIR，不在 scripts/packer/ 里建 .stub-tmp：
# 中途被杀会把临时目录留在工作区，且 mv 回来的副本可能带上桩的权限位。
# ⚠️ 本测试与 test-packer.sh 争抢同一个 scripts/packer/packer.sh（都要把它换成
# 桩来记录入参），**两个测试必须串行执行**，不许并行跑。
mv "$ROOT/scripts/packer/packer.sh" "$STUB_DIR/packer-real.sh"
cp "$STUB_DIR/record-packer.sh" "$ROOT/scripts/packer/packer.sh"
restore() {
  [[ -f "$STUB_DIR/packer-real.sh" ]] || return 0
  mv -f "$STUB_DIR/packer-real.sh" "$ROOT/scripts/packer/packer.sh"
  chmod 755 "$ROOT/scripts/packer/packer.sh"
}
trap 'restore; rm -rf "$STUB_DIR"' EXIT

# 顶替 java：apktool 解包/回编都走这里。
#   解包：apktool d -o <outdir> → 造出最小解包目录（manifest + smali）
#   回编：apktool b -o <file> <dir> → 落盘未对齐标记包
mkdir -p "$STUB_DIR/bin"
cat > "$STUB_DIR/bin/java" <<'STUB'
#!/usr/bin/env bash
# 只顶替 apktool：参数里带 apktool.jar 的才是解包/回编调用。
# patch-dex-version.py 用真 python3 + androguard 解析 APK，要求产物是真 zip，
# 故回编产物用 python 写一个最小合法 zip（不能写文本占位）。
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
    mkdir -p "$out/smali"
    printf 'x' > "$out/AndroidManifest.xml"
  elif [[ "$mode" == "b" ]]; then
    python3 -c 'import sys,zipfile; z=zipfile.ZipFile(sys.argv[1],"w"); z.writestr("AndroidManifest.xml","x"); z.writestr("classes.dex","dex"); z.close()' "$out"
  fi
fi
exit 0
STUB
chmod +x "$STUB_DIR/bin/java"

# 输入必须是真 zip：patch-dex-version.py 会用 zipfile 打开它（报错十八的 save 步骤）
python3 - "$STUB_DIR/in.apk" <<'PY'
import sys, zipfile
with zipfile.ZipFile(sys.argv[1], "w") as z:
    z.writestr("AndroidManifest.xml", "x")
    z.writestr("classes.dex", "dex")
PY

printf 'com.test.**\n' > "$STUB_DIR/rules.txt"

echo ""
echo "" # ① 占位报错已下线：--packer 能被解析
PACKER_IN_FILE="$STUB_DIR/pin.txt" PACKER_OUT_FILE="$STUB_DIR/pout.txt" \
PATH="$STUB_DIR/bin:$PATH" bash "$PROTECT" "$STUB_DIR/in.apk" "$STUB_DIR/out1.apk" \
  --anti-diff --packer >"$STUB_DIR/log1.txt" 2>&1
rc=$?
check "①--packer 不再被占位拦截" "$([[ $rc -ne 0 ]] && echo nonzero || echo zero)" "zero"
check "②packer.sh 被调用到" "$([[ -f "$STUB_DIR/pin.txt" ]] && echo yes || echo no)" "yes"
check "③packer 拿到的是非回编原包" \
  "$([[ "$(cat "$STUB_DIR/pin.txt" 2>/dev/null)" != *unsigned.apk ]] && echo yes || echo no)" "yes"
# 加壳后 protect.sh 不得再对 OUT 跑 finish_apk：桩落的是纯文本标记，
# 任何后续 zipalign 都会把它改写掉 → 标记仍在即证明产物是 packer 的原始输出。
check "④packer 产物直接作为最终输出(无二次 finish_apk)" \
  "$(grep -qx 'PACKER_OUTPUT_MARKER' "$STUB_DIR/out1.apk" 2>/dev/null && echo intact || echo touched)" \
  "intact"

echo ""
echo "" # ⑤⑥ 不勾加壳：packer 不应被调用
rm -f "$STUB_DIR/pin.txt" "$STUB_DIR/out2.apk"
PACKER_IN_FILE="$STUB_DIR/pin.txt" PACKER_OUT_FILE="$STUB_DIR/pout.txt" \
PATH="$STUB_DIR/bin:$PATH" bash "$PROTECT" "$STUB_DIR/in.apk" "$STUB_DIR/out2.apk" \
  --anti-diff >"$STUB_DIR/log2.txt" 2>&1
check "⑤不勾加壳时不调用 packer" "$([[ -f "$STUB_DIR/pin.txt" ]] && echo yes || echo no)" "no"
check "⑥不勾加壳时产物仍落 OUT" "$([[ -f "$STUB_DIR/out2.apk" ]] && echo yes || echo no)" "yes"

echo ""
[[ $fail -eq 0 ]] && echo "编排冒烟全绿" || echo "编排冒烟有失败"
exit $fail