#!/usr/bin/env bash
# lib-repack.sh — apktool 解包/注入/重打包公共库（source 使用，不直接执行）
#
# 抽取自旧 protect-sigcheck.sh / protect-sigcheck-only.sh / protect-dcc.sh 三处
# 几乎相同的"解包 → 放 so → 改 extractNativeLibs → 回编 → zipalign"逻辑
# （2025-09 三总控已合并为 protect.sh，本库继续为其唯一解包/回编实现）。
#
# 依赖：ROOT（仓库根，绝对路径）、MODULE_TAG 已由调用方设置。
# 历次报错教训固定在代码里：
#   - apktool d 不带 --force-manifest（报错五：文本 manifest 回编成灰包）
#   - --no-debug-info（报错八：剥离 debug_info，dex 缩小约 1.8MB）
#   - 二进制 AXML 用 patch-extractnativelibs.py 原位改写（报错五）
#   - apktool.jar 固定路径在开工前 require_file（空目录不被 git 跟踪的教训）

_lib_repack_guard() {
  if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "❌ lib-repack.sh 是公共库，请用 source 引入" >&2
    exit 1
  fi
  : "${ROOT:?使用 lib-repack.sh 前必须设置 ROOT 为仓库根目录}"
}
_lib_repack_guard

# apktool.jar 随 dcc 分发包(dcc.zip)携带:dcc 改为 tools/dcc.zip 分发后,
# jar 从解压产物取。ensure_dcc 幂等,重复调用零开销。
ensure_dcc >/dev/null
APKTOOL_JAR="$ROOT/build/dcc/dcc/tools/apktool.jar"

# repack_require_tools — 开工前校验 apktool.jar 存在
repack_require_tools() {
  require_file "$APKTOOL_JAR" "apktool.jar（dcc.zip 解压产物，缺了先跑 ensure_dcc）"
}

# repack_unpack <输出目录> <输入.apk>
repack_unpack() {
  local out="$1" apk="$2"
  java -jar "$APKTOOL_JAR" d -r -f --no-debug-info -o "$out" "$apk"
  # 报错十八: 回编会把各 dex 版本全部降成 035(原始信息丢失),解包后先记录
  python3 "$ROOT/scripts/repack/patch-dex-version.py" save "$apk" "$out"
}

# repack_install_so <解包目录> <libs根目录> — 把编译产物里所有 ABI 的 .so 拷进解包目录
repack_install_so() {
  local decompiled="$1" libs_root="$2"
  local abi_dir abi
  for abi_dir in "$libs_root"/*; do
    [[ -d "$abi_dir" ]] || continue
    abi="$(basename "$abi_dir")"
    mkdir -p "$decompiled/lib/$abi"
    find "$abi_dir" -maxdepth 1 -name '*.so' -exec cp {} "$decompiled/lib/$abi/" \;
  done
}

# repack_force_extractnativelibs <解包目录> — 二进制 AXML 原位改写 extractNativeLibs=true
repack_force_extractnativelibs() {
  local decompiled="$1"
  python3 "$ROOT/scripts/repack/patch-extractnativelibs.py" "$decompiled/AndroidManifest.xml"
}

# repack_build <解包目录> <输出未对齐.apk>
repack_build() {
  local decompiled="$1" out="$2"
  java -jar "$APKTOOL_JAR" b -o "$out" "$decompiled"
  # 报错十八: 回编后按解包时记录的原始版本逐 dex 恢复(只升不降,
  # max(原版本, minSdk 推导下限)),对任意 App/minSdk 组合通用
  python3 "$ROOT/scripts/repack/patch-dex-version.py" restore "$out" "$decompiled"
}
