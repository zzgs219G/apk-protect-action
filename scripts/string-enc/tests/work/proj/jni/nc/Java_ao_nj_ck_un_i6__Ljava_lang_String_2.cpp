#include "Dex2C.h"

/* Lao/nj/ck/un;->i6(Ljava/lang/String;)Ljava/lang/String; */
extern "C" JNIEXPORT jstring JNICALL
Java_ao_nj_ck_un_i6__Ljava_lang_String_2(JNIEnv *env, jobject thiz, jstring p0){
jobject v0 = NULL;
jobject v1 = NULL;
jthrowable exception;
jclass cls0 = NULL;
jmethodID mth0 = NULL;
v0 = (jobject)env->NewLocalRef(p0);
L0:
LOGD("0:invoke-static \x76\x30\x2c\x20\x4c\x61\x6f\x2f\x6e\x6a\x2f\x63\x6b\x2f\x75\x6e\x3b\x2d\x3e\x64\x6e\x28\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x29\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b");
{
#define EX_HANDLE EX_LandingPad_0
jclass &clz = cls0;
jmethodID &mid = mth0;
D2C_RESOLVE_STATIC_METHOD(clz, mid, "ao/nj/ck/un", "dn", "(Ljava/lang/String;)Ljava/lang/String;");
jvalue args[] = {{.l = v0}};
v1 = (jstring) env->CallStaticObjectMethodA(clz, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
L1:
LOGD("6:move-result-object \x76\x30");
if (v0) {
LOGD("env->DeleteLocalRef(%p):v0", v0);
env->DeleteLocalRef(v0);
}
v0 = (jobject) v1;
L2:
return (jstring) v0;

EX_LandingPad_0:
D2C_GET_PENDING_EX
if(d2c_is_instance_of(env, exception, "java/lang/Throwable")) {
goto L2;
}
D2C_GOTO_UNWINDBLOCK
EX_UnwindBlock: return NULL;
}
