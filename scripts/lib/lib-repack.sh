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

# apktool.jar 独立放 tools/apktool.jar（2026-10-21 从 dcc.zip 原样提取，
# sha256 与 zip 内文件逐字节一致）。dcc 引擎连同 dcc.zip 已退役删除——
# apktool 是解包/回编核心链路，不该寄居在已下架引擎的分发包里，
# 且 15MB 的 jar 藏在 zip 里导致每次构建都要解压整个 dcc（23MB）。
# 现为 git 跟踪的独立文件，不再依赖任何解压步骤。
APKTOOL_JAR="$ROOT/tools/apktool.jar"

# repack_require_tools — 开工前校验 apktool.jar 存在
repack_require_tools() {
  require_file "$APKTOOL_JAR" "apktool.jar（tools/ 根下，git 跟踪）"
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

# repack_force_debuggable_off <解包目录> — 强制 debuggable=false
#
# 为什么必须做（逆向分析报告 v2 §8 F-11）：
#   实测测试 APK 的 Manifest 写着 debuggable=true。带这个标记的 release 包：
#     · `run-as <pkg>` 可进应用私有目录，读写文件、dump 内存
#     · 调试器可直接 attach —— 我们那套 ptrace(TRACEME) / PR_SET_DUMPABLE
#       全部建立"不许被调试"的前提，debuggable=true 等于从系统层面给开了后门
#     · `am set-debug-app` 等工具链全线可用
#
# ⚠️ 与 extractNativeLibs 不同：debuggable 属性【可能不存在】。
#   不存在时的语义就是 false（Android 默认），所以脚本对"属性不存在"
#   返回成功而非报错 —— 绝大多数正常 App 本来就不写这个属性，
#   若照搬 extractNativeLibs 的"缺则报错"，会让绝大多数包构建失败。
repack_force_debuggable_off() {
  local decompiled="$1"
  local mf="$decompiled/AndroidManifest.xml"
  # 解包可能产出二进制 AXML（-r 模式），也可能被 apktool 转成文本 XML。
  # 文本形态下 patche 方式不同 —— 先探测，避免把文本 XML 喂给二进制解析器。
  if [ ! -f "$mf" ]; then
    log_warn "AndroidManifest.xml 不存在，跳过 debuggable 处理"
    return 0
  fi
  if head -c 4 "$mf" | od -An -tx1 | tr -d ' \n' | grep -q '^03000800$'; then
    python3 "$ROOT/scripts/repack/patch-debuggable.py" "$mf"
  else
    # 文本 XML：apktool 未加 -r 时会解码成文本。用属性替换处理。
    if grep -q 'android:debuggable="true"' "$mf"; then
      sed -i 's/android:debuggable="true"/android:debuggable="false"/g' "$mf"
      log_info "debuggable → false（文本 XML）"
    else
      log_info "debuggable 已是 false 或未设置（文本 XML），跳过"
    fi
  fi
}
