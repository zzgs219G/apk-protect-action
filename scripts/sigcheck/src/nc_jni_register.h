#pragma once
/* nc_jni_register.h — JNI 动态注册的对外契约（2026-10-19）
 *
 * 只有一件事要对外说清楚：**JNI 实现函数改成了 static，名字也不再是
 * `Java_<pkg>_<Class>_<method>`**。任何新增 JNI 入口都必须：
 *   1. 在实现文件里写成 static（不出符号表）
 *   2. 在本头文件里声明 nc_jni_xxx
 *   3. 在 nc_jni_register.c 的 RegisterNatives 表里加一行
 * 三步缺一，Java 侧就是 UnsatisfiedLinkError。
 *
 * 为什么要这么麻烦：实测报告 §1 用 `nm -D` 一条命令就拿到了全部 JNI
 * 入口名与精确大小（`MainActivity.k` 21692 B 这类数字等于免费送业务
 * 复杂度地图）。JNIEXPORT 自带 default 可见性，-fvisibility=hidden
 * 对它无效，只有动态注册能把名字从 .dynsym 里拿掉。
 */
#include <jni.h>

/* ⚠️ 只在【启用动态注册】时声明这三个实现函数供 nc_jni_register.c 取地址。
 *    未启用时它们走短名绑定（JNIEXPORT + Java_xxx），本来就是外部符号，
 *    此处再声明会造成 "static declaration follows non-static declaration"
 *    （实测踩过）。 */
/* ⚠️ 用 visibility("hidden") 而非 static：static 无法跨文件取地址，
 *    而 RegisterNatives 正需要函数指针。hidden 保证不进 .dynsym（外部
 *    看不到名字），同时链接期仍可被 nc_jni_register.c 引用。
 *    实测：`nm -D` 里查不到，`nm` 里是本地符号 t。 */
#if defined(NC_JNI_DYNAMIC_REG)
__attribute__((visibility("hidden")))
jint     nc_jni_selftest(JNIEnv *env, jobject thiz);
__attribute__((visibility("hidden")))
jboolean nc_jni_ncVerify(JNIEnv *env, jclass clazz, jbyteArray measured);
__attribute__((visibility("hidden")))
void     nc_jni_heartbeat(JNIEnv *env, jclass clazz);
#endif
