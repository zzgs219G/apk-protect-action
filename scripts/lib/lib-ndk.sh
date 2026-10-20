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

  # ── JNI 符号隐藏（2026-10-19，修实测报告 §1/§7.1）────────────────
  # 实测报告用 `nm -D` 一条命令拿到 7 个 JNI 入口名 + 精确大小
  # （`MainActivity.k` 21692 B），等于免费送业务复杂度地图。
  #
  # 做法：version script 只导出 JNI_OnLoad，其余（含 dex2c 的 Java_xxx）
  # 全部 local。配合 protect.sh 生成的 RegisterNatives 表 + 编译期改名宏，
  # Java 侧仍能正常调用（走运行期注册，不靠符号名）。
  #
  # ⚠️ 只在有注册表时才启用：没有 nc_jni_gen.c 就没有运行期注册，
  #    隐藏符号会让 Java 侧 UnsatisfiedLinkError。
  if [ -f "$jni/nc_jni_gen.c" ]; then
    # 2026-10-19：这几行 echo 是加来防"静默跳过"的。
    # CI 39174771703 的四个失败里，根因是 ndk_write_mk 在注册表生成之前
    # 就跑完了，导致 `if [ -f nc_jni_gen.c ]` 恒假、flags 全没写。
    # 而 ndk_write_mk 当时【一行日志都不打】—— 日志里只能看到
    # "[jni-reg] 生成注册表" 在 "Compile nc_jni_gen.c" 之前，
    # 看不出 mk 其实更早写完。现在把决策打出来，顺序问题一眼可见。
    echo "  [mk] JNI 符号隐藏已启用（version-script + 动态注册）"
    # ⚠️ 2026-10-19 两轮实证后的最终形态（这是第三次修正）：
    #
    #   第一轮 `local: *`（全隐藏）
    #     → ART dlsym 找不到 Java_xxx → UnsatisfiedLinkError。错。
    #
    #   第二轮 `global: Java_*`（全保留）
    #     → 能跑，但 dex2c 的业务方法名与精确大小照旧泄露
    #       （`nm -D` 一条命令拿到 `MainActivity.k = 21692 B`）。对但不够。
    #
    #   第三轮 `global: Java_com_nc_*`（只保留手写入口）← 现在这版
    #     → 依据：dex2c 产物【本来就是动态注册的】
    #       （Dex2C.cpp 的 JNI_OnLoad 里调 dynamic_register_compile_methods），
    #        不靠 dlsym 按名查找 → 隐藏它们不影响调用。
    #       而我们手写的三个入口（NcLink.selftest/ncVerify/heartbeat）
    #       走 JNI 短名绑定，ART 靠 dlsym 按名找 → 必须导出。
    #
    #   实测验证：t2.so 里 Java_com_x_MainActivity_k 被隐藏、
    #   Java_com_nc_link_NcLink_selftest 保留，各得其所。
    #
    #   ⚠️ 动态注册手写入口这条路已试过并回退（a7d9cbc）：
    #      constructor 里 FindClass 在 so 加载时机不安全，真机起不来。
    #      所以手写入口只能短名绑定，只能保留符号名。
    cat > "$jni/nc_hide.map" <<'MAPEOF'
{
  global:
    JNI_OnLoad;
    Java_com_nc_*;
  local:
    *;
};
MAPEOF
    cat >> "$jni/Android.mk" <<EOF
LOCAL_LDFLAGS += -Wl,--version-script=\$(LOCAL_PATH)/nc_hide.map
EOF
    # 改名宏：把 Java_xxx 在编译期映射成 ncg_d2c_N（符号不出 .dynsym）
    if [ -s "$jni/nc_jni_rename.mk" ]; then
      cat >> "$jni/Android.mk" <<EOF
LOCAL_CFLAGS += \$(shell cat \$(LOCAL_PATH)/nc_jni_rename.mk)
LOCAL_CPPFLAGS += \$(shell cat \$(LOCAL_PATH)/nc_jni_rename.mk)
EOF
    fi
  else
    # 这条日志同样关键：说明"JNI 符号隐藏没启用"，以及为什么。
    # 静默跳过是 CI 上最难查的一类问题（报错五十二的同型教训）。
    echo "  [mk] ⚠️ 未发现 nc_jni_gen.c → JNI 符号隐藏未启用" \
         "（注册表生成是否晚于 ndk_write_mk？）" >&2
  fi

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
