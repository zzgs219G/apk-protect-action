#!/usr/bin/env bash
# protect.sh — 唯一加固总控（勾选式合并版，取代旧三个 pipeline 总控 + run-modules.sh）
#
# 模块契约：<输入.apk> <输出_unsigned.apk> [--sigcheck] [--dex2c [规则文件]]
#           [--stringenc 规则文件] [--envcheck] [--packer] [--packer-smaller] [--anti-diff]
#   - 输入/输出/规则路径一律 normalize 成绝对路径（报错三教训：dex2c 运行时要切目录，
#     相对输出路径会被写进 dex2c 目录）
#   - 主进程 cwd 全程不漂移：dex2c 的 dcc.py 在子 shell 里运行（module_cd_run）
#   - 无论勾选多少模块，apktool 解包/回编只做一次（旧联合方案要两次，这是本次合并
#     的额外收益，对产物无行为差异——sig_check.c 以 constructor 方式并入同一 so）。
#
# 行为对齐（与旧脚本逐一等价）：
#   只 --sigcheck        → 提取指纹 → sig_check.c + nc_link.c 单独成 so → inject-loadlib.py
#                          双保险插桩（<clinit> + onCreate）→ Java 层判决式签名
#                          联动注入(§3.11,判决在 so/杀在 Java,so 缺失即 fail-closed)→ 回编
#   只 --dex2c [规则]      → 规则转 filter → 转译 → mark-native.py 壳替换 → 回编
#   只 --stringenc 规则  → 规则转正则 → 字符串加密(注入 Java 解密桩) → 回编
#   --sigcheck --dex2c       → 提取指纹 → 转译 → sig_check.c 合入同一 NDK 工程 →
#                          mark-native.py 壳替换（不插 loadLibrary：onCreate 已抽进 so，
#                          删 <clinit> 的 loadLibrary 会让 native 壳直接自爆）→ 回编
#   --envcheck           → 环境检测(Frida/Xposed/调试器/libc内存CRC/常驻复查)并入 libnc.so(可与其余模块任意组合)
#   --packer             → 基础加壳(dpt-shell)：必须最后跑，作用于回编并 zipalign
#   --packer-smaller     → 随 --packer 的子选项(体积优化)：dpt --smaller，填料改统一 0x0e
#   --dpt-extra-args 文本 → 通用 dpt 参数通道(空格分隔,随加壳生效;只构成打包参数注入面)
#   --exclude-abi 值      → 带值参数标准件(报错四十四):剔除 ABI 的 so 目录,经环境变量传 packer.sh
#                          之后的成品包；勾了加壳则跳过本脚本的 finish_apk，
#                          由 packer.sh 的产物直接作为最终输出(加壳包不能二次 zipalign)
#
# 转译引擎(2026-10-14 接入;2026-12 旧引擎 dcc 下线,dex2c 成为唯一引擎):
#   --dex2c  引擎 tools/dex2c.zip(源码在父目录 ../Dex2C/,自研 fork 可查;
#            APKEditor 1.4.7 解包、构造函数守卫、Termux/Linux/Windows 跨平台)
#   产出工程包(jni/nc/*.cpp + compiled_methods.txt),mark-native/stringenc 等下游消费方不变
#
# 转译类名来源决策(规则优先,修复联合勾选无视用户规则的 bug):
#   提供了规则(无论是否联合勾选) → 用户规则(rules-to-filter.py)
#   未提供规则 + 联合勾选 sigcheck → 自动抽主类(make-filter-from-apk.py)
#   未提供规则 + 未勾 sigcheck   → 报错退出(fail-fast,无类名来源)
#
# --stringenc [规则文件]   → dex 层字符串常量加密(与 dex2c 同款规则语法,内部复用
#   rules-to-filter.py 的 class_rule_to_filter 做类匹配)。规则必填(没有"自动抽
#   主类"的兜底:字符串加密必须明确范围,否则可能误伤)。加密对象 = const-string
#   字面量 + R8 折叠的 static final String 字段常量;系统类/框架依赖类按硬编码
#   名单排除,规则写 ** 也不突破。产物侧用纯 Java 解密桩 Lcom/nc/strdec/StrDec; 解,
#   不依赖 so。
#
# 固定执行顺序（与勾选顺序无关）：sigcheck → dex2c → stringenc → anti-diff → packer
#
# 前置依赖（由 workflow 安装）: python3 + dex2c requirements、JDK 17、Android NDK、apktool
set -euo pipefail

# ── 解析勾选（勾选顺序无关，执行顺序由下面 STEP 区硬编码） ────────────
usage() {
  # 打印文件头部的注释块(第 2 行起、到第一条非注释行/代码前为止),
  # 用 awk 动态界定范围 —— 头部注释增删行后不必再改数字(此前写死 2,32p 已踩坑)
  awk 'NR>=2 { if ($0 !~ /^#/) exit; sub(/^# ?/, ""); print }' "$0"
  exit 1
}

[[ $# -ge 2 ]] || usage
IN_APK="$1"
OUT_APK="$2"
shift 2
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"    # apk-protect-action 根目录
MODULE_TAG="protect"
# shellcheck source=../lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=../lib/lib-repack.sh
source "$ROOT/scripts/lib/lib-repack.sh"
# shellcheck source=../lib/lib-ndk.sh
source "$ROOT/scripts/lib/lib-ndk.sh"

DEX2C_DIR=""                                  # dex2c 工具目录(--dex2c 勾选时经 ensure_dex2c 解压填充)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

WANT_SIGCHECK=0; WANT_DEX2C=0; WANT_PACKER=0; WANT_ENVCHECK=0; DEX2C_RULES=""
PACKER_SMALLER=0   # 报错四十三:--packer-smaller(体积优化)→ 环境变量传 packer.sh
DPT_EXTRA_ARGS_TEXT=""  # 通用 dpt 参数通道(报错四十三后方向调整):自由文本,空格分隔
EXCLUDE_ABI=""          # 带值参数标准件(报错四十四):--exclude-abi 的值,经环境变量传 packer.sh
WANT_STRINGENC=0; STRING_RULES=""
WANT_ANTIDIFF=0
WANT_DEX2C_STUB=0     # 联动子复选框:把解密桩内核 dn() 也抽进 dex2c(见 STEP2 顺序手术)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sigcheck) WANT_SIGCHECK=1; shift ;;
    --dex2c)    WANT_DEX2C=1; shift
                # 规则文件可选(联合勾选 sigcheck 时可省略 → 自动抽主类)
                if [[ $# -ge 1 && "$1" != --* ]]; then
                  DEX2C_RULES="$(normalize_path "$1")"; shift
                fi ;;
    --stringenc) WANT_STRINGENC=1; shift
                # 规则文件必填(字符串加密必须明确范围,不做"自动抽主类"兜底)
                if [[ $# -ge 1 && "$1" != --* ]]; then
                  STRING_RULES="$(normalize_path "$1")"; shift
                fi ;;
    --envcheck) WANT_ENVCHECK=1; shift ;;
    --packer)   WANT_PACKER=1; shift ;;
    --packer-smaller) WANT_PACKER=1; PACKER_SMALLER=1; shift ;;
    --exclude-abi)
      # 带值参数标准件(报错四十四):schema arg_value 子项的值(x86,x86_64),
      # 单 token 无空白(resolver 已校验,此处防御性再验)。经环境变量传 packer.sh。
      if [[ $# -ge 2 ]]; then
        EXCLUDE_ABI="$2"; shift 2
        [[ "$EXCLUDE_ABI" =~ ^[A-Za-z0-9_,.\-]+$ ]] || { log_err "--exclude-abi 值非法: $EXCLUDE_ABI"; exit 1; }
      else
        log_err "--exclude-abi 缺值"; exit 1
      fi ;;
    --dpt-extra-args)
      # 通用 dpt 参数通道:值无条件取下一 token(dpt 参数本身合法地以 -- 开头,
      # 不能套 --stringenc 的 "$1" != --* 守卫);缺值视为空(不附加)。
      # 安全边界:自由文本只构成打包参数注入面,最坏打包失败;secrets 不经此路径。
      if [[ $# -ge 2 ]]; then DPT_EXTRA_ARGS_TEXT="$2"; shift 2; else shift; fi ;;

    --anti-diff) WANT_ANTIDIFF=1; shift ;;
    --dex2c-stub) WANT_DEX2C_STUB=1; shift ;;
    *)          log_err "未知参数: $1"; usage ;;
  esac
done

TOTAL=$((WANT_SIGCHECK + WANT_DEX2C + WANT_PACKER + WANT_ENVCHECK + WANT_STRINGENC + WANT_ANTIDIFF))
if [[ $TOTAL -eq 0 ]]; then
  log_err "未勾选任何模块（--sigcheck / --dex2c [规则] / --stringenc 规则 / --envcheck / --anti-diff / --packer）"
  exit 1
fi

# 联动子复选框的依赖校验(防呆):--dex2c-stub 单独勾选没有意义 ——
# 它只是"把桩也交给 dex2c 转译"的修饰,必须同时有 stringenc(产出桩)
# 与 dex2c(消费桩)。缺任何一个都是配置错误,fail-fast 说人话。
if [[ $WANT_DEX2C_STUB -eq 1 ]]; then
  if [[ $WANT_STRINGENC -eq 0 ]]; then
    log_err "--dex2c-stub 必须与 --stringenc 同时勾选(没有字符串加密就没有解密桩可抽)"
    exit 1
  fi
  if [[ $WANT_DEX2C -eq 0 ]]; then
    log_err "--dex2c-stub 必须与 --dex2c 同时勾选(桩要交给 dex2c 转译)"
    exit 1
  fi
fi

# 转译层统一变量:唯一引擎,共用同一套规则来源决策与 STEP3+ 下游(引擎无关)
WANT_TRANSPILE=$WANT_DEX2C
TRANSPILE_RULES="$DEX2C_RULES"

# ── 入口契约校验：所有环境假设在开工前 fail-fast ────────────────────
IN_APK="$(normalize_path "$IN_APK")"
OUT_APK="$(normalize_path "$OUT_APK")"
require_file "$IN_APK" "输入 APK"
repack_require_tools
if [[ $WANT_TRANSPILE -eq 1 ]]; then
    DEX2C_DIR="$(ensure_dex2c)"             # 从 tools/dex2c.zip 解压(幂等)并取得 Dex2C 目录
    require_dir "$DEX2C_DIR" "dex2c 工具目录"
  # 规则文件:提供了就必须非空;没提供且未联合 sigcheck → 无类名来源,fail-fast
  if [[ -n "$TRANSPILE_RULES" ]]; then
    require_nonempty_file "$TRANSPILE_RULES" "dex2c 规则文件"
  elif [[ $WANT_SIGCHECK -eq 0 ]]; then
    log_err "--dex2c 未提供规则文件且未勾选 --sigcheck,没有类名来源"
    log_err "     (提供规则文件: --dex2c rules.txt;或联合 --sigcheck 自动抽取主类)"
    exit 1
  fi
fi
if [[ $WANT_STRINGENC -eq 1 ]]; then
  if [[ -z "$STRING_RULES" ]]; then
    log_err "--stringenc 必须提供类名规则文件（字符串加密不做自动抽主类的兜底）"
    log_err "     规则语法: com.test.** / com.test.* / 精确类名 /"
    log_err "     activity*(需 --classes) / !com.test.libs.** 排除 / # 注释"
    exit 1
  fi
  require_nonempty_file "$STRING_RULES" "stringenc 规则文件"
fi

log "勾选 $TOTAL 个模块，按固定顺序执行: sigcheck → dex2c → stringenc → anti-diff → packer"

# ── STEP 1: 提取证书指纹，生成 sig_hash.h + sig_guard2.h（仅 --sigcheck） ──
# 2026-10 双线:同时生成第二份【独立】标准答案(sig_guard2.h),供
# sig_guard2.c 使用 —— 两条线的 salt/派生公式/处置路径全独立,
# 攻击者 patch 第一线的 delayed_kill 后,第二线照常判定。
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  log_step 1 6 "提取证书指纹"
  "$ROOT/scripts/sigcheck/hash/make-sig-hash.sh" "$IN_APK" \
      "$WORK/sig_hash.h" "$WORK/sig_guard2.h"
fi

# ── STEP 2: dex2c 转译（--dex2c 勾选时；--no-build 只产出工程包） ─────────
# 联动(stringenc↔dex2c)的顺序手术:
#   dex2c 从【APK】里读 dex(tools/Dex2C/dcc.py compile_dex→auto_vm→androguard),
#   而解密桩是 stringenc 在 STEP5 才注入 smali 的 —— 正常顺序下 STEP2 时
#   APK 里根本没有桩类,filter 写任何名字都转不到它。
#   故勾选 --dex2c-stub 时,先在 STEP2 之前跑一轮 stringenc(解包→加密+注桩
#   →回编成 APK'),dex2c 转译 APK' 就能命中桩;STEP5 再跳过一次 stringenc。
#   代价:apktool 解包/回编从 1 次变 2 次(旧三总控合并时消除过的开销,
#   为联动加回来;dex 8MB 量级约 +30~60s)。
LINK_STUB=0
if [[ $WANT_DEX2C -eq 1 && $WANT_STRINGENC -eq 1 && $WANT_DEX2C_STUB -eq 1 ]]; then
  LINK_STUB=1
fi
if [[ $LINK_STUB -eq 1 ]]; then
  log_step 2 6 "字符串加密前置（联动：桩须先于 dex2c 进 APK）"
  repack_unpack "$WORK/pre" "$IN_APK"
  # activity* 需要 Activity 类列表 → 从 Manifest 动态提取(同 STEP5 侧做法)
  if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$STRING_RULES"; then
    log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
      "$WORK/.placeholder_pre.txt" --classes "$WORK/activity_classes.txt" \
      --on-fail skip || true
  fi
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" clean "$WORK/pre"
  PRE_ENC_ARGS=()
  [[ -f "$WORK/activity_classes.txt" ]] && PRE_ENC_ARGS+=(--classes "$WORK/activity_classes.txt")
  # 关键差异:前置轮【不传 --exclude-methods】—— 此刻 dex2c 还没跑,
  # 不知道哪些方法会被抽走。后果仅体积(被抽方法里的字符串白加密后随方法
  # 变 native 壳),正确性无碍;STEP5 主轮仍按 compiled_methods 精确跳过。
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
    "$WORK/pre" "$STRING_RULES" "${PRE_ENC_ARGS[@]}" \
    --emit-stub-filter "$WORK/stub_filter.txt"
  # 联动前提校验:桩必须真的存在(零加密 + 无旧桩 = 联动空转,fail-fast
  # 而非让用户以为生效)。encrypt-strings 在无桩时写空文件。
  if [[ ! -s "$WORK/stub_filter.txt" ]]; then
    log_err "--dex2c-stub 联动生效前提不成立:本轮 stringenc 没有注入解密桩"
    log_err "     (规则零命中且无旧桩 → 无桩可抽;请检查规则是否命中业务类)"
    exit 1
  fi
  log_info "联动 filter: $(cat "$WORK/stub_filter.txt")"
  repack_build "$WORK/pre" "$WORK/pre-encrypted.apk"
  LINK_APK="$WORK/pre-encrypted.apk"
else
  LINK_APK="$IN_APK"
fi

if [[ $WANT_TRANSPILE -eq 1 ]]; then
  log_step 2 6 "核心方法转 C（dex2c）"
  # 类名来源决策(规则优先,修复:联合勾选 sigcheck 时无视用户规则的 bug):
  #   1) 提供了用户规则 → 一律走用户规则(无论是否联合勾选)
  #   2) 未提供规则 + 联合勾选 sigcheck → Manifest 动态解析 LAUNCHER 自动生成 filter
  if [[ -n "$TRANSPILE_RULES" ]]; then
    log_info "filter 来源: 用户规则 $TRANSPILE_RULES"
    python3 "$ROOT/scripts/filter/rules-to-filter.py" "$TRANSPILE_RULES" \
      "$WORK/dcc_filter.txt" --classes "$WORK/activity_classes.txt"
    # activity* 需要 Activity 类列表 → 从 Manifest 动态提取
    if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$TRANSPILE_RULES"; then
      log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
      python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$LINK_APK" \
        "$WORK/.placeholder_filter.txt" --classes "$WORK/activity_classes.txt" \
        --on-fail skip || true
    fi
    # 全量规则防呆(2026-10-15 排查教训): ** 会被 rules-to-filter.py 转成
    # L.*;.*(全 App 转译)。上游引擎对全量转译明确不支持——混淆过的大方法会
    # 生成引用未声明变量的坏 C,报错形态是 NDK 编译期 undeclared identifier,
    # 极难归因。在源头拦下,报人话(上游 dcc.py 内置护栏只拦字面 .*,拦不住
    # L.*;.*,必须在流水线层补)。
    if grep -qE '^L\.\*;\.\*$|^\.\*$' "$WORK/dcc_filter.txt"; then
      log_err "检测到全量转译规则(**): 会把整个 App 的所有方法抽进 so,上游明确不支持"
      log_err "     (混淆过的大方法会生成坏 C 代码,报错是难排查的 undeclared identifier)"
      log_err "     正确姿势: ①规则留空+勾选签名校验 → 自动抽主类; ②定向规则,如 com.xixin.box.**"
      exit 1
    fi
    DCC_FILTER="$WORK/dcc_filter.txt"
  elif [[ $WANT_SIGCHECK -eq 1 ]]; then
    log_info "filter 来源: 未提供规则,自动抽取主类(make-filter-from-apk)"
    # 动态解析 Manifest 里的 LAUNCHER activity → 自动生成 filter（一行一个类）
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$LINK_APK" \
      "$WORK/auto_filter.txt" --classes "$WORK/activity_classes.txt" --on-fail error
    # auto_filter.txt 已是 dcc filter 正则格式(见 make-filter-from-apk.py),
    # 直接使用,不要二次转换 —— 曾经二次转换产生畸形正则导致 no compiled methods
    DCC_FILTER="$WORK/auto_filter.txt"
  fi

  # 只联 --dex2c(唯一引擎):桩名每包随机,规则由 stringenc 前置轮的 --emit-stub-filter 反向产出。
  if [[ $LINK_STUB -eq 1 ]]; then
    cp "$DCC_FILTER" "$WORK/dcc_filter_linked.txt"
    cat "$WORK/stub_filter.txt" >> "$WORK/dcc_filter_linked.txt"
    DCC_FILTER="$WORK/dcc_filter_linked.txt"
    log_info "联动:桩内核已追加进 dex2c filter（$(grep -c . "$WORK/stub_filter.txt") 条: dn/mix64/keyByte）"
  fi

  # dex2c 的 dcc.py 要在自身目录运行 → 子 shell 隔离，主进程 cwd 不漂移。
  # CLI: -i/-o 旗标式且 -o 必填(no-build 下 -o 不落地产物,传哑值),
  # 另传 --allow-global 对齐规则语义、--disable-signing 防御性关签名(no-build 下本就不执行)。
  module_cd_run "$DEX2C_DIR" python3 dcc.py -i "$LINK_APK" -o "$WORK/dex2c-no-build.apk" \
    --project-archive "$WORK/dcc-project.zip" \
    --no-build \
    --disable-signing \
    --allow-global \
    --filter "$DCC_FILTER"

  require_file "$WORK/dcc-project.zip" "dex2c 工程包（filter 可能未命中任何方法）"
fi

# ── STEP 3: 组装 NDK 工程 → 编译 libnc.so ───────────────────────────
# 报错二十三:stringenc 是纯 dex 层模块,不产出/不依赖任何 so。
# 只勾 stringenc(或未来其它纯 dex 组合)时,STEP 3/4 必须整体跳过 ——
# 否则 ndk_write_mk 会往一个从未创建的 jni/ 目录里 cat > Application.mk,
# 报 "No such file or directory"(报错信息里的 tmp.XXX/project/jni 路径即此)。
# 有 so 需求的组合:sigcheck / 转译(--dex2c) / envcheck 任一勾选。
if [[ $WANT_SIGCHECK -eq 1 || $WANT_TRANSPILE -eq 1 || $WANT_ENVCHECK -eq 1 ]]; then
log_step 3 6 "组装 NDK 工程"
mkdir -p "$WORK/project"

# 中文流程日志文案表(2026-11 用户需求):扫描 sig_check.c/env_check.c 的
# LSG 标记注释生成 sig_log_data.h(XOR 密文,strings 不泄语义)。
# 勾 sigcheck 或 envcheck 时需要;生成失败 fail-fast(文案缺失=编译必炸,早炸早定位)
if [[ $WANT_SIGCHECK -eq 1 || $WANT_ENVCHECK -eq 1 ]]; then
  python3 "$ROOT/scripts/sigcheck/log/make-sig-log.py" \
    "$ROOT/scripts/sigcheck/src/sig_check.c" "$ROOT/scripts/sigcheck/src/env_check.c" \
    "$WORK/sig_log_data.h"
fi

if [[ $WANT_TRANSPILE -eq 1 ]]; then
  unzip -q "$WORK/dcc-project.zip" -d "$WORK/project"
fi
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  # 联合时并入 dcc 工程 jni/nc/；单独时放 jni/ 根 —— ndk_write_mk 的两级
  # wildcard 都收（报错十一/十三教训），两种布局等价
  # nc_link.c = Java 层判决式联动(§3.11):标准值比对在 so 内,零新头文件依赖
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    mkdir -p "$WORK/project/jni/nc"
    cp "$ROOT/scripts/sigcheck/src/sig_check.c" "$WORK/project/jni/nc/"
    cp "$ROOT/scripts/sigcheck/src/nc_link.c"   "$WORK/project/jni/nc/"
    cp "$ROOT/scripts/sigcheck/src/sig_guard2.c" "$WORK/project/jni/nc/"
    cp "$WORK/sig_hash.h"               "$WORK/project/jni/nc/"
    cp "$WORK/sig_guard2.h"             "$WORK/project/jni/nc/"
    cp "$WORK/sig_log_data.h"           "$WORK/project/jni/nc/"
  else
    mkdir -p "$WORK/project/jni"
    cp "$ROOT/scripts/sigcheck/src/sig_check.c" "$WORK/project/jni/"
    cp "$ROOT/scripts/sigcheck/src/nc_link.c"   "$WORK/project/jni/"
    cp "$ROOT/scripts/sigcheck/src/sig_guard2.c" "$WORK/project/jni/"
    cp "$WORK/sig_hash.h"               "$WORK/project/jni/"
    cp "$WORK/sig_guard2.h"             "$WORK/project/jni/"
    cp "$WORK/sig_log_data.h"           "$WORK/project/jni/"
  fi
fi
if [[ $WANT_ENVCHECK -eq 1 ]]; then
  # 环境检测(Frida/Xposed/调试器):与 sigcheck 同型并入同一 libnc.so(constructor 天然共存)
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    mkdir -p "$WORK/project/jni/nc"
    cp "$ROOT/scripts/sigcheck/src/env_check.c" "$WORK/project/jni/nc/"
  else
    mkdir -p "$WORK/project/jni"
    cp "$ROOT/scripts/sigcheck/src/env_check.c" "$WORK/project/jni/"
  fi
  # envcheck 未勾 sigcheck 时也要有文案表(仅勾 envcheck 的组合)
  if [[ $WANT_SIGCHECK -ne 1 ]]; then
    if [[ $WANT_TRANSPILE -eq 1 ]]; then
      cp "$WORK/sig_log_data.h" "$WORK/project/jni/nc/"
    else
      cp "$WORK/sig_log_data.h" "$WORK/project/jni/"
    fi
  fi
fi
# so 静态加固(2026-10-18 自解谜版):开箱代码进 NDK 工程
#
# ⚠️ 本轮改动：nc_guard_unlock.c → nc_guard_boot.c（零冻结路线）
#   unlock.c 仍是冻结资产、保留在仓库，但【不再进 NDK 工程】。
#   boot.c 承接运行期职责：明文 stub(.text) + unlock 本体(.ncguard_head 密文)。
#   理由：把"开锁器"也锁进箱子，否则 unlock.c 整份逻辑在 .text 明文可读
#   （外部逆向报告 docs/so层防御/简盒-06 §6.2 的实测结论）。
#   不改 unlock.c 本身 = 不动冻结纪律；它以历史存档形式留存。
#
# ndk_write_mk 的两级 wildcard 已收 *.c，放 jni/nc/ 或 jni/ 根都能编入。
# ⚠️ nc_guard_key.c 必须一起拷：boot.c 的 unlock 本体 include 了
#    nc_guard_key.h 并调 khmac_sha256()（HMAC 校验）。漏拷 = ndk-build 就红
#    （fail-fast 反而是好事，比运行期 SIGILL 好定位）。
if [[ -d "$WORK/project/jni/nc" ]]; then
  cp "$ROOT/scripts/sigcheck/src/nc_guard_boot.c"  "$WORK/project/jni/nc/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_probe.c" "$WORK/project/jni/nc/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_jni.c"   "$WORK/project/jni/nc/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_key.c"   "$WORK/project/jni/nc/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_key.h"   "$WORK/project/jni/nc/"
else
  cp "$ROOT/scripts/sigcheck/src/nc_guard_boot.c"  "$WORK/project/jni/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_probe.c" "$WORK/project/jni/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_jni.c"   "$WORK/project/jni/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_key.c"   "$WORK/project/jni/"
  cp "$ROOT/scripts/sigcheck/src/nc_guard_key.h"   "$WORK/project/jni/"
fi
ndk_write_mk "$WORK/project/jni" nc   # mk 模板唯一来源（报错十一），模块名固定 nc

# ── 通用段标记（2026-10 设施化第2层）──────────────────────────────
# 让 dex2c 转译产物吃上 .ncguard 加密：用规则把 JNI 函数打进加密段。
# 位置必须在 ndk_build 【之前】——标记器改的是源码，编译后才跑就晚了。
#
# 为什么要单独一层：sigcheck/envcheck 的探针是手写 __attribute__ 的
# （env_check.c 冻结，只追加）；dex2c 产物由引擎生成，不该为它改冻结的
# 引擎。有了标记器，加一个消费者 = 加一条规则，谁也不写自己的防御。
# 详见 docs/流程文档.md §3.12 的三层设施说明。
if [[ $WANT_TRANSPILE -eq 1 ]]; then
  echo "[mark] 段标记：dex2c 转译产物 → .ncguard"

  # 先数一下源码里到底有多少 JNI 函数头（用于判定"静默失防"）
  JNI_HDRS=$(grep -rlE 'JNIEXPORT[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]+JNICALL' \
             "$WORK/project/jni" --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null | wc -l)

  python3 "$ROOT/scripts/lib/so_section_mark.py" "$WORK/project/jni" \
    --rule dex2c-jni --exclude nc_guard_jni.c -v 2>&1 | sed 's/^/  [mark] /' || {
    echo "❌ 段标记失败——dex2c 转译产物未吃上加密（用户明确要求）" >&2
    exit 1
  }

  # 静默失防检测：有 JNI 头却没标上任何一个 → 规则与产物形态脱节
  # （例如 writer.py 改了函数头格式）。此时不能放行——那等于"以为防了
  # 其实没防"，正是本机制最该避免的假绿。
  MARKED=$(grep -rc 'section(".ncguard")' "$WORK/project/jni" \
           --include='*.cpp' --include='*.cc' --include='*.c' 2>/dev/null \
           | awk -F: '{s+=$2} END {print s+0}')
  if [[ $JNI_HDRS -gt 0 && $MARKED -eq 0 ]]; then
    echo "❌ 检出 $JNI_HDRS 个含 JNIEXPORT 的源文件，但段标记命中 0" >&2
    echo "   → dex2c 的 writer.py 可能改了函数头格式，规则已脱节" >&2
    echo "   → 修 scripts/lib/so_section_mark.py 的 dex2c-jni 规则，不许静默放行" >&2
    exit 1
  fi
  echo "[mark] 完成：$MARKED 处 .ncguard 标记（含探针与转译函数）"
fi

log_step 4 6 "NDK 编译"
ndk_build "$WORK/project"
fi   # 有 so 需求的组合才执行 STEP 3/4(报错二十三:纯 stringenc 组合跳过)

# ── STEP 5: 解包 → smali 处理 → 放 so → 回编（全组合只做这一次） ────
# ── STEP 5: 解包 → smali 处理 → 放 so → 回编（全组合只做这一次） ────
# 联动路径(stringenc↔dex2c)必须解【前置加密后的 APK'】而非原始 IN_APK ——
# stringenc 已在 STEP2 前跑完并回编成 APK',解原始包会把密文+桩全部丢掉,
# 只剩 mark-native 把 dn() 改壳后指向一个不存在的桩类 → UnsatisfiedLinkError。
STEP5_APK="$IN_APK"
if [[ $LINK_STUB -eq 1 ]]; then
  STEP5_APK="$WORK/pre-encrypted.apk"
fi
log_step 5 6 "解包注入重打包"
repack_unpack "$WORK/decompiled" "$STEP5_APK"

# ── so 静态加固(2026-12):把 .ncguard 段锁成密文（构建期"锁箱"）──────
# 位置在 STEP5 解包后：so 已编译完但【还没进 APK】→ 锁的是即将打包的产物。
# 运行期由 nc_guard_boot.c 的明文 stub 解出 unlock 本体，再由本体解
# .ncguard；磁盘上 IDA 读到的 .ncguard 是 RC4 密文（现为 4012/2750 字节的
# 12 个 env_check 探针 + dex2c 转译产物）。
# 抄自 XopProtector 的 .bitcode 自解密机制。
# cert 与 package 都由 so-section-lock.py 从 $IN_APK 自己提（定点读 Signing
# Block + AXML 解析），protect.sh 不重复实现 —— 单一职责。
# 换 key 重打包 → cert 变 → k_so 变 → 密文解不开（fail-closed）。
if [[ -d "$WORK/project/libs" ]]; then
  for so in "$WORK"/project/libs/*/libnc.so; do
    [[ -f "$so" ]] || continue
    # 一级锁箱：.ncguard 业务段（k_so 由证书 HKDF 派生）
    python3 "$ROOT/scripts/lib/so-section-lock.py" "$so" "$so" \
      --section .ncguard --from-apk "$IN_APK" \
      2>&1 | sed 's/^/  [lock] /' || {
      echo "❌ .ncguard 锁箱失败（段未标记？cert/包名提取失败？）——so 静态加固未生效" >&2
      exit 1
    }
    # 二级锁箱（2026-10-18 自解谜）：把 unlock 本体也锁进 .ncguard_head。
    # ⚠️ 顺序有依赖：必须先跑一级再跑二级。原因是一级会改 .ncguard 内容，
    #    而二级要锁的 .ncguard_head 是另一个段，本无先后；但若二级先跑，
    #    unlock 本体已变密文，此时一级锁箱器本身不依赖 unlock（纯 Python
    #    读盘），所以其实可交换 —— 但保持"先业务后本体"更易读。
    # ⚠️ 二级失败必须 fail-fast：stub 见 slot 无 magic 会静默放行，
    #    head 段保持明文 → 自解谜没发生 → 静态攻击者照旧读 unlock 本体。
    #    那种"以为防了其实没防"的静默降级正是本机制最该避免的。
    python3 "$ROOT/scripts/lib/so-section-lock.py" "$so" "$so" --lock-head \
      2>&1 | sed 's/^/  [lock2] /' || {
      echo "❌ 二级锁箱失败（.ncguard_head 未标记？符号被 strip？）——unlock 本体仍可静态读取" >&2
      exit 1
    }
  done
fi

if [[ $WANT_TRANSPILE -eq 1 ]]; then
  # native 化：把已抽进 so 的方法在 smali 里改成 native 壳，并插 System.loadLibrary("nc")
  # （dcc 原版只在自带重打包路径里做壳替换且不插 loadLibrary，纯成品 APK 后处理必须自动补齐）
  python3 "$ROOT/scripts/repack/mark-native.py" \
    "$WORK/project/jni/nc/compiled_methods.txt" "$WORK/decompiled"
elif [[ $WANT_SIGCHECK -eq 1 ]]; then
  # 单独签名校验：loadLibrary("nc") 双保险插桩:<clinit> + onCreate 各一份
  # —— 没有 dex2c 的 native 壳保护,攻击者删掉 <clinit> 即可绕过校验;
  #    onCreate 里再插一份,要删两处才失效（联合方案不插：onCreate 已抽进 so,
  #    删 <clinit> 的 loadLibrary 会让 native 壳直接自爆）。幂等:按方法体分别检查。
  # manifest 是二进制 AXML → inject-loadlib 内部走 androguard AXMLPrinter 解析
  python3 "$ROOT/scripts/inject/inject-loadlib.py" "$WORK/decompiled" \
    --launcher --entrypoints --so-name nc
fi

# ── Java 层判决式签名联动(§3.11,随 --sigcheck 自动生效,无独立勾选) ──
# 两套独立真校验之一:Java 只"量"(PackageManager)并执行杀,标准值与比对全在
# so(nc_link.c) —— 指纹永不过境进 dex;so 缺失 → fail-closed 杀,loadLibrary
# 由"可删开关"变"承重墙"(修复 sigcheck-only 删开关静默绕过的最大缺口)。
# 必须在插桩/loadLibrary 之后、stringenc 之前:新类常量可被 stringenc 顺带加密。
if [[ $WANT_SIGCHECK -eq 1 ]]; then
  python3 "$ROOT/scripts/sigcheck/javalink/inject-javacheck.py" \
    "$WORK/decompiled" --so-name nc
fi

# ── 字符串加密（dex 层，与 so 无关；必须在 mark-native 之后） ──────
# 放在 native 化之后的原因:被 dex2c 抽走的方法此时已是 native 壳、没有方法体,
# 字符串加密自然扫不到它们(省体积);同时用 compiled_methods.txt 做精确跳过,
# 避免 dcc 与 mark-native 之间的时序差异导致误加密(报错十三式的布局假设错误)。
#
# 【重要】直接把【用户规则文件】交给 encrypt-strings.py,不要先转成 dcc filter:
# 该脚本内部复用 rules-to-filter.py 的 class_rule_to_filter 做类匹配,输入必须
# 是用户规则(点号通配符)。若喂 rules-to-filter.py 的产物(dcc filter 正则)
# 会被二次转换产生畸形正则(LLcom/.../),filter 那侧的同类坑见流程文档 §2 步骤 3。
if [[ $WANT_STRINGENC -eq 1 && $LINK_STUB -eq 1 ]]; then
  # 联动路径:stringenc 已在 STEP2 前跑完(桩必须先进 APK 才能被 dex2c 转译)。
  # STEP5 再跑一次会二次加密(同一明文被包两层密文)→ 整包乱码,必须跳过。
  log_info "字符串加密已在 STEP2 前置完成（联动路径，此处跳过避免二次加密）"
else
if [[ $WANT_STRINGENC -eq 1 ]]; then
  # activity* 需要 Activity 类列表 → 从 Manifest 动态提取(同 dex2c 侧做法)
  if grep -q '^[[:space:]]*activity\*[[:space:]]*$' "$STRING_RULES"; then
    log_info "检测到 activity* 规则,从 Manifest 提取 Activity 列表"
    python3 "$ROOT/scripts/filter/make-filter-from-apk.py" "$IN_APK" \
      "$WORK/.placeholder_string_activity.txt" --classes "$WORK/activity_classes.txt" \
      --on-fail skip || true
  fi

  # 残留清理(幂等):上一轮若留下解密桩但本次一条都没加密,不能把旧桩带进产物
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" clean "$WORK/decompiled"

  STRING_ENC_ARGS=()
  if [[ -f "$WORK/activity_classes.txt" ]]; then
    STRING_ENC_ARGS+=(--classes "$WORK/activity_classes.txt")
  fi
  if [[ $WANT_TRANSPILE -eq 1 ]]; then
    # 被抽进 so 的方法跳过 —— 它们的字符串会在 so 里,dex 侧没必要再加密
    STRING_ENC_ARGS+=(--exclude-methods "$WORK/project/jni/nc/compiled_methods.txt")
  fi
  python3 "$ROOT/scripts/string-enc/encrypt-strings.py" \
    "$WORK/decompiled" "$STRING_RULES" "${STRING_ENC_ARGS[@]}"
fi
fi

# ── 防对比混淆（dex 层，最后做：等 dcc/stringenc 的改动落定后再上结构噪声） ──
# 放在 stringenc 之后的原因:stringenc 会给选中类插入解密桩并改写 const-string,
# 若 anti-diff 先做、stringenc 后做,stringenc 的改动会让 anti-diff 的"已处理"
# 标记附近继续出现新差异,削弱防对比效果;最后做 anti-diff,全量 smali 一次性
# 盖上标签重命名/块重排/入口垃圾指令噪声,diff 视角即"整包重编译"。
# anti-diff 自带跳过:native 方法(dcc 壳)、<init>/<clinit>(sigcheck/dcc 依赖)。
if [[ $WANT_ANTIDIFF -eq 1 ]]; then
  # 变换 F（shl⇄mul 恒等重编码）已并入模块本体固定开启——原 antidiff.reencode
  # 子复选框（--anti-diff-f）已从 schema 下线（v1.2 回退），此处无条件传 --enable-f
  python3 "$ROOT/scripts/anti-diff/anti-diff.py" "$WORK/decompiled" --enable-f
fi

if [[ $WANT_SIGCHECK -eq 1 || $WANT_TRANSPILE -eq 1 || $WANT_ENVCHECK -eq 1 ]]; then
  repack_install_so "$WORK/decompiled" "$WORK/project/libs"
  # 强制解压 so 加载（本方案唯一允许的 Manifest 修改）——只在有 so 的组合执行;
  # 纯 dex 组合(仅 stringenc)没有 libnc.so,manifest 无需改写(报错二十三)
  repack_force_extractnativelibs "$WORK/decompiled"
fi
repack_build "$WORK/decompiled" "$WORK/unsigned.apk"

# ── 输出 ────────────────────────────────────────────────────────────
# 先把回编产物对齐好，再决定加壳是否接手最后一步（全程不签名，签名由开发者完成）。
#   - 勾加壳：dpt 吃的是"已对齐的成品包"。dpt 内部虽自带 zipalign，但它同时会
#     重写 dex/so/Manifest —— 与其让它对着未对齐的包做一次全量重写，不如先
#     对齐再交壳，失败时也更接近"哪一步坏的"（报错八的定位纪律）。
#   - 不勾加壳：与接入 packer 之前完全一致（finish_apk 直接落到 OUT_APK），
#     保证既有组合零行为变更。
if [[ $WANT_PACKER -eq 1 ]]; then
  ALIGNED="$WORK/aligned.apk"
  finish_apk "$WORK/unsigned.apk" "$ALIGNED"
  log_step 6 6 "基础加壳（dpt-shell）"
  # packer.sh 产物直接作为最终输出：加壳包不能在本脚本再叠一次 finish_apk
  # （加壳已重写 dex/so/Manifest，二次 zipalign 属二次改写）
  # 体积优化(报错四十三):schema 子复选框 packer.smaller → dpt --smaller
  # (方法体填料改统一 0x0e,产物更小);经环境变量传入,packer.sh 两参契约不变
  # 通用通道:--dpt-extra-args 自由文本同经环境变量 DPT_EXTRA_ARGS 传入
  PACKER_SMALLER="$PACKER_SMALLER" DPT_EXTRA_ARGS="$DPT_EXTRA_ARGS_TEXT" \
    EXCLUDE_ABI="$EXCLUDE_ABI" \
    "$ROOT/scripts/packer/packer.sh" "$ALIGNED" "$OUT_APK"
  log_done "完成 ✅ 共 $TOTAL 个模块，产物: $OUT_APK（已加壳，未签名，开发者需自行 apksigner 重签）"
else
  finish_apk "$WORK/unsigned.apk" "$OUT_APK"
  log_done "完成 ✅ 共 $TOTAL 个模块，产物: $OUT_APK（未签名，开发者需自行 apksigner 重签）"
fi
