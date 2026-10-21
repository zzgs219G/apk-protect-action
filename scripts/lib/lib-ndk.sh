#!/usr/bin/env bash
# lib-ndk.sh — NDK 编译公共库（source 使用，不直接执行）
#
# 抽取自三个 pipeline 中重复的 "Application.mk 模板 + ndk-build" 逻辑。
# 依赖：MODULE_TAG 已由调用方设置；ANDROID_NDK_HOME 由 workflow 传入。

_lib_ndk_guard() {
  if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    echo "❌ lib-ndk.sh 是公共库，请用 source 引入" >&2
    exit 1
  fi
}
_lib_ndk_guard

# ndk_require — 校验 NDK 环境变量
ndk_require() {
  require_env ANDROID_NDK_HOME "指向 NDK 根目录，由 workflow 的 setup-ndk 提供"
}

# ndk_write_mk <jni目录> [模块名=nc] — 写入统一的 Application.mk / Android.mk
# Android.mk wildcard 收 jni 目录下 *.cpp/*.c（sigcheck-only 原本自包含的 mk 逻辑）
ndk_write_mk() {
  local jni="$1" mod="${2:-nc}"
  cat > "$jni/Application.mk" <<'EOF'
APP_STL := c++_static
# NC_GUARD_SECTIONED: 让判决核心（nc_verify_t1）与签名表进 .ncx 加密段。
# 为什么是显式宏而不是 __ANDROID__ 自动判断：宿主端任何一次"想验证段布局"
# 的编译都会因为"标了段却没人解锁"而读到密文 → 假红。见 nc_link.c 的注释。
APP_CPPFLAGS += -fvisibility=hidden -fno-ident -Oz -ffunction-sections -fdata-sections
# ⚠️ 2026-10-21 加固 flag 补齐（白嫖清单）：
#   · -fstack-protector-strong：NDK 默认弱版（只护含 char 数组的函数），
#     strong 版把取用栈地址的函数全护上——密钥处理函数全是 uint8_t[]
#     栈缓冲，恰是溢出靶面。
#   · -mbranch-protection=standard（arm64 专用，见下方 TARGET 条件）：
#     ARM64 PAC/BTI 硬件防御（armv8.3+/Android 12+）。PAC=返回地址签名
#     （ROP 直接崩），BTI=分支目标认证（跳函数中间=SIGILL）。
#     实测编入 54 条 paciasp/bti 指令，解锁链全通过。
APP_CFLAGS   := -fvisibility=hidden -fno-ident -Oz -ffunction-sections -fdata-sections \
                -fstack-protector-strong \
                -DNC_GUARD_SECTIONED
APP_CFLAGS.arm64 += -mbranch-protection=standard
APP_PLATFORM := android-21
APP_ABI := armeabi-v7a arm64-v8a
EOF
  cat > "$jni/Android.mk" <<EOF
LOCAL_PATH := \$(call my-dir)

include \$(CLEAR_VARS)
LOCAL_MODULE    := $mod
LOCAL_LDLIBS    := -llog

# 必须同时收根目录与 nc/ 子目录(报错十三):联合方案里 dcc 产出的
# Dex2C.cpp / well_known_classes.cpp / 各方法 .cpp 与 sig_check.c 全在
# jni/nc/ 下,sigcheck-only 的源文件在 jni/ 根下 —— 两级都要 wildcard,
# 只写一级必然产出"空壳 so" → 运行时 UnsatisfiedLinkError
SOURCES := \$(wildcard \$(LOCAL_PATH)/*.cpp) \$(wildcard \$(LOCAL_PATH)/*.c) \
           \$(wildcard \$(LOCAL_PATH)/nc/*.cpp) \$(wildcard \$(LOCAL_PATH)/nc/*.c)
LOCAL_C_INCLUDES := \$(LOCAL_PATH) \$(LOCAL_PATH)/nc

LOCAL_SRC_FILES := \$(SOURCES:\$(LOCAL_PATH)/%=%)
EOF
  # so 加固:链接期丢弃未引用段(-ffunction/data-sections 配套),并 strip 符号表
  #
  # ⚠️⚠️ 2026-10-20：--strip-all 是【本次才真正加上的】。
  #   本注释与下方 mk 注释一直都写着"strip 符号表"，但 LOCAL_LDFLAGS 里
  #   从来没有对应参数——注释承诺了一件没做的事。后果（已实测复现）：
  #     产物 .symtab 24KB / 957 个符号，`ncg_frag_a/b/c/d`（XOR_KEY 四碎片）
  #     与 `NCG_XOR_FRAG`（重组查表）的名字都在里面。
  #     攻击者 `nm` 一条命令即知"哪个是碎片、哪个是表"，15 行 Python 就能
  #     静态重组出完整 XOR_KEY（7e31a50dc8924bf6），进而
  #       slot[8:24] ^ XOR_KEY → k_stub → 解 .ncxh → unlock 本体 → 解 .ncx
  #     全程不需要运行、不需要真机、不需要证书。
  #   也就是说：碎片化确实把连续 8 字节密钥从 .rodata 里消掉了，但每个
  #   碎片都贴着名字，"提高重组成本"这一点并未兑现。
  #
  # 为什么可以放心 strip：锁箱器（so-section-lock.py 的 lock/lock_head）
  # 全程只用 section header table 的 sh_addr/sh_size，不碰 .symtab
  # （见该文件 853-859 行注释）。strip 只删 .symtab/.strtab，
  # 段名表 .shstrtab 与段表本身不动，锁箱/开箱契约不受影响。
  #
  # 反向纪律：绝不能为了"保留符号方便排查"而去掉 --strip-all ——
  # 那会把 frida_port_probe / xposed_maps_probe 等探针名暴露进符号表，
  # 等于免费送检测意图清单（protect.sh:519 与历史教训同向）。
  cat >> "$jni/Android.mk" <<EOF

# so 加固(lib-ndk.sh 2026-10):丢弃未引用段 + 去符号表
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--build-id=none \\
                 -Wl,--strip-all \
                 -Wl,-z,separate-code
EOF

  # ── JNI 符号隐藏（2026-10-21 重建，修「从未生效」的静默失效）────────
  #
  # ⚠️⚠️ 本节此前的形态是一个【永不成立的 guard】：
  #     if [ -f "$jni/nc_jni_gen.c" ]; then ... 整段 version script 全在它里面，
  #   而 nc_jni_gen.c 的生成器 gen-jni-register.py 已在 a7d9cbc 删除
  #   （动态注册真机会崩，回退短名绑定），protect.sh 里也再无任何生成点。
  #   后果：version script 自 a7d9cbc 起从未生效过，.dynsym 一直导出全部
  #   Java_* 业务符号。--strip-all 只删 .symtab/.strtab，删不掉 .dynsym，
  #   所以补不上这个洞。实测报告（docs/so层防御/libnc_so_加密强度分析.md
  #   §五「致命：符号表完全未处理」）给符号表打 0.0 分即由此而来。
  #
  # ── 白名单为什么是 Java_* 而不是 Java_com_nc_* ──────────────────
  #   这里曾有一轮误判（e0e6bb2）：它断言「dex2c 产物本来就是动态注册的，
  #   所以可以只保留 Java_com_nc_*」，实测证明【不成立】：
  #     · protect.sh 调 dcc.py 时【不传】-d/--dynamic-register
  #       （grep dynamic-register protect.sh = 0 命中）
  #     · dcc.py 的 dynamic_register 默认 False（argparse default=False）
  #     · writer.py:106 的 if/else → 走 else 分支，产出
  #       `extern "C" JNIEXPORT ... JNICALL Java_xxx`（短名绑定！）
  #   即 dex2c 产物靠 ART dlsym 按名查找，只保留 Java_com_nc_* 会让
  #   全部业务方法 UnsatisfiedLinkError。实测对照（本机 clang + lld）：
  #     hide.map  (Java_com_nc_*) → 只剩 NcLink_selftest，MainActivity_k 消失
  #     hide2.map (Java_*)        → 两者都保留
  #
  # ── 必须带 --undefined-version ─────────────────────────────────
  #   version script 声明了 JNI_OnLoad，但并非每个组合都定义它
  #   （纯 sigcheck/envcheck 组合没有 dex2c 的 Dex2C.cpp；测试工程也没有）。
  #   lld 对这种「声明了却不存在」的符号是【硬错误】而不是忽略：
  #       ld.lld: error: version script assignment of 'global' to symbol
  #               'JNI_OnLoad' failed: symbol not defined
  #   实测：不加该 flag，无 JNI_OnLoad 的工程直接链接失败（CI 会红）。
  #   加上后行为：存在的就按规则处理，不存在的不报错。
  #
  # ── 语义变化（如实记录）──────────────────────────────────────
  #   Java_* 导出是 JNI 短名绑定的【硬要求】，隐藏它 = ULE。
  #   所以本 map 的实际收益只有一条：把非 JNI 的内部符号（ncg_* /
  #   dex2c 辅助函数 / nc_jni_*）挡在 .dynsym 外。这已是当前架构下
  #   能做到的上限——想藏业务方法名只有动态注册，而动态注册在 so
  #   加载时机（Application 初始化中）会崩（a7d9cbc 真机实证）。
  #   「隐藏 JNI 符号」与「短名绑定」二者不可兼得，此处选了先能跑。
  echo "  [mk] JNI 符号隐藏已启用（version-script：Java_* 导出，其余 local）"
  # ── 排除 dex2c 引擎的僵尸符号（2026-10-22，修逆向报告 v2 §8 F-13）────
  # Java_amimo_dcc_DccApplication_init__ 是 dex2c 引擎自带的一个空函数：
  #
  #     extern "C" { JNIEXPORT void JNICALL
  #     Java_amimo_dcc_DccApplication_init__(JNIEnv *env, jobject thiz) { } }
  #
  # 实测确认它在产物里是【纯僵尸】：
  #   · dcc.py:997 的 loader 注入（把 DccApplication.smali 塞进 APK）只在
  #     `if is_apk(apkfile) and outapk:` 分支里跑；
  #   · 而 protect.sh 传的是 --no-build，outapk 为空 → 该分支不执行；
  #   · 实测 APK 的 6 个 dex 里【没有】amimo/dcc/DccApplication 这个类。
  # 所以 ART 永远不会按名 dlsym 它，导出它只是白送情报：
  # 逆向报告 v2 F-13 原文："泄露『这库是从别处复用』的痕迹，且无功能价值"。
  #
  # 处置：不动 tools/Dex2C/（那是引擎分发版，改了下游 dex2c.zip 就对不上），
  # 用【编译期改名】把它改成非 Java_ 前缀的符号 —— 于是不匹配 version script
  # 的 `Java_*` 白名单，被 `local: *` 收走，不再出现在 .dynsym。
  #
  # ⚠️ 为什么不用 version script 的 local 精确匹配：实测无效。
  #   `global: Java_*; local: Java_amimo_dcc_*; *;` 里具体的 local 条目
  #   【不会】优先于 global 的通配（ld 的匹配规则是同段内先匹配者胜，
  #   跨段时 global 段先被扫描）。三种写法实测均仍导出该符号。
  #   而改用精确白名单 `global: Java_com_nc_link_*` 会连带隐藏 dex2c 的
  #   业务方法 —— 那正是 e0e6bb2 踩过的坑（业务方法走短名绑定，隐藏即 ULE）。
  #   编译期改名是唯一既能摘掉僵尸符号、又不影响业务符号的办法。
  #
  # 若将来真启用 loader 注入（去掉 --no-build），删掉下面那行 -D 即可恢复。
  cat > "$jni/nc_hide.map" <<'MAPEOF'
{
  global:
    JNI_OnLoad;
    Java_*;
  local:
    *;
};
MAPEOF
  cat >> "$jni/Android.mk" <<'EOF'
LOCAL_CFLAGS   += -DJava_amimo_dcc_DccApplication_init__=ncg_zombie_dcc_init
LOCAL_CPPFLAGS += -DJava_amimo_dcc_DccApplication_init__=ncg_zombie_dcc_init
EOF
  cat >> "$jni/Android.mk" <<EOF
LOCAL_LDFLAGS += -Wl,--version-script=\$(LOCAL_PATH)/nc_hide.map
LOCAL_LDFLAGS += -Wl,--undefined-version
EOF

  # ⚠️ include $(BUILD_SHARED_LIBRARY) 必须放在【所有 LOCAL_* 赋值之后】。
  # 2026-10-19 CI 实证：此前 include 写在中间，后面追加的
  # LOCAL_CFLAGS/LOCAL_CPPFLAGS 全部无效 —— 因为 ndk-build 在 include
  # 那一刻就把 LOCAL_* 读走了，之后再改不回写。
  # 症状极具迷惑性：编译正常、链接报 `undefined symbol: nc_jni_*`
  # （因为 -DNC_JNI_DYNAMIC_REG 没生效，走的是旧的短名分支）。
  cat >> "$jni/Android.mk" <<'EOF'

# 必须最后 include：ndk-build 在此刻快照 LOCAL_* 变量
include $(BUILD_SHARED_LIBRARY)
EOF
}

# ndk_build <工程根目录> — 执行 ndk-build，产物在 <工程根>/libs/<abi>/
ndk_build() {
  local project="$1"
  ndk_require
  PATH="$ANDROID_NDK_HOME:$PATH" ndk-build -j"$(nproc)" -C "$project"
}
