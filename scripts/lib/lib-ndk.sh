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
# NC_GUARD_SECTIONED: 让判决核心（nc_verify_t1）与签名表进 .ncguard 加密段。
# 为什么是显式宏而不是 __ANDROID__ 自动判断：宿主端任何一次"想验证段布局"
# 的编译都会因为"标了段却没人解锁"而读到密文 → 假红。见 nc_link.c 的注释。
APP_CPPFLAGS += -fvisibility=hidden -fno-ident -Oz -ffunction-sections -fdata-sections
APP_CFLAGS   := -fvisibility=hidden -fno-ident -Oz -ffunction-sections -fdata-sections \
                -DNC_GUARD_SECTIONED
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
  cat >> "$jni/Android.mk" <<EOF

# so 加固(lib-ndk.sh 2026-10):丢弃未引用段 + 去符号表
LOCAL_LDFLAGS := -Wl,--gc-sections -Wl,--build-id=none
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
    cat > "$jni/nc_hide.map" <<'MAPEOF'
{
  global:
    JNI_OnLoad;
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
    # NC_JNI_DYNAMIC_REG：让 nc_guard_jni/nc_link 的实现函数走 hidden 可见性
    # NC_HAS_D2C_REG：有 dex2c 注册表时启用（JNI_OnLoad 里调用它）
    cat >> "$jni/Android.mk" <<'EOF'
LOCAL_CFLAGS += -DNC_JNI_DYNAMIC_REG
LOCAL_CPPFLAGS += -DNC_JNI_DYNAMIC_REG
EOF
    if grep -q 'nc_jni_gen_register' "$jni/nc_jni_gen.c" 2>/dev/null; then
      cat >> "$jni/Android.mk" <<'EOF'
LOCAL_CFLAGS += -DNC_HAS_D2C_REG
LOCAL_CPPFLAGS += -DNC_HAS_D2C_REG
EOF
    fi
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
