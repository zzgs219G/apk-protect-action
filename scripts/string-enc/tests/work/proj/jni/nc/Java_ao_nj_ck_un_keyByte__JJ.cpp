#include "Dex2C.h"

/* Lao/nj/ck/un;->keyByte(JJ)I */
extern "C" JNIEXPORT jint JNICALL
Java_ao_nj_ck_un_keyByte__JJ(JNIEnv *env, jobject thiz, jlong p4, jlong p6){
jlong v0;
jlong v1;
jlong v2;
jlong v3;
jlong v4;
jint v5;
jint v6;
jclass cls0 = NULL;
jmethodID mth0 = NULL;
v0 = (jlong)p4;
v1 = (jlong)p6;
L0:
v2 = 3;
LOGD("2:ushr-long \x76\x30\x2c\x20\x76\x36\x2c\x20\x76\x30");
v2 = ((uint64_t) v1) >> (v2 & 0x3f);
v3 = -7046029254386353131;
LOGD("10:mul-long/2addr \x76\x30\x2c\x20\x76\x32");
v2 = (v2 * v3);
LOGD("12:add-long/2addr \x76\x34\x2c\x20\x76\x30");
v0 = (v0 + v2);
LOGD("14:invoke-static \x76\x34\x2c\x20\x76\x35\x2c\x20\x4c\x61\x6f\x2f\x6e\x6a\x2f\x63\x6b\x2f\x75\x6e\x3b\x2d\x3e\x6d\x69\x78\x36\x34\x28\x4a\x29\x4a");
{
#define EX_HANDLE EX_UnwindBlock
jclass &clz = cls0;
jmethodID &mid = mth0;
D2C_RESOLVE_STATIC_METHOD(clz, mid, "ao/nj/ck/un", "mix64", "(J)J");
jvalue args[] = {{.j = (jlong) v0}};
v4 = (jlong) env->CallStaticLongMethodA(clz, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("1a:move-result-wide \x76\x34");
v0 = (jlong) v4;
v2 = 7;
LOGD("20:and-long/2addr \x76\x36\x2c\x20\x76\x30");
v1 = (v1 & v2);
v2 = 8;
LOGD("26:mul-long/2addr \x76\x36\x2c\x20\x76\x30");
v1 = (v1 * v2);
v5 = (jint)(v1);
LOGD("2a:ushr-long/2addr \x76\x34\x2c\x20\x76\x36");
v0 = ((uint64_t) v0) >> (v5 & 0x3f);
v1 = 255;
LOGD("30:and-long/2addr \x76\x34\x2c\x20\x76\x36");
v0 = (v0 & v1);
v6 = (jint)(v0);
return (jint) v6;
EX_UnwindBlock: return (jint)0;
}
