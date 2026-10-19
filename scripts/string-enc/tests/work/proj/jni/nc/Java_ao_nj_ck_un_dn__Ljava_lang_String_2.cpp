#include "Dex2C.h"

/* Lao/nj/ck/un;->dn(Ljava/lang/String;)Ljava/lang/String; */
extern "C" JNIEXPORT jstring JNICALL
Java_ao_nj_ck_un_dn__Ljava_lang_String_2(JNIEnv *env, jobject thiz, jstring p14){
jobject v0 = NULL;
jobject v1 = NULL;
jobject v2 = NULL;
jint v3;
jobject v4 = NULL;
jint v5;
jint v6;
jlong v7;
jlong v8;
jint v9;
jint v10;
jlong v11;
jobject v12 = NULL;
jlong v13;
jlong v14;
jlong v15;
jlong v16;
jint v17;
jint v18;
jint v19;
jint v20;
jclass cls0 = NULL,cls1 = NULL,cls2 = NULL,cls3 = NULL,cls4 = NULL;
jfieldID fld0 = NULL;
jmethodID mth0 = NULL, mth1 = NULL, mth2 = NULL, mth3 = NULL, mth4 = NULL, mth5 = NULL;
v0 = (jobject)env->NewLocalRef(p14);
L0:
LOGD("0:sget-object \x76\x30\x2c\x20\x4c\x61\x6f\x2f\x6e\x6a\x2f\x63\x6b\x2f\x75\x6e\x3b\x2d\x3e\x43\x41\x43\x48\x45\x20\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x63\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x2f\x43\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x48\x61\x73\x68\x4d\x61\x70\x3b");
{
#define EX_HANDLE EX_UnwindBlock
if (v1) {
LOGD("env->DeleteLocalRef(%p):v1", v1);
env->DeleteLocalRef(v1);
}
jclass &clz = cls0;
jfieldID &fld = fld0;
D2C_RESOLVE_STATIC_FIELD(clz, fld, "ao/nj/ck/un", "CACHE", "Ljava/util/concurrent/ConcurrentHashMap;");
v1 = (jobject) env->GetStaticObjectField(clz,fld);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("4:invoke-virtual \x76\x30\x2c\x20\x76\x31\x34\x2c\x20\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x63\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x2f\x43\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x48\x61\x73\x68\x4d\x61\x70\x3b\x2d\x3e\x67\x65\x74\x28\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x29\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v1);
jclass &clz = cls1;
jmethodID &mid = mth0;
D2C_RESOLVE_METHOD(clz, mid, "java/util/concurrent/ConcurrentHashMap", "get", "(Ljava/lang/Object;)Ljava/lang/Object;");
jvalue args[] = {{.l = v0}};
v2 = (jobject) env->CallObjectMethodA(v1, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("a:move-result-object \x76\x30");
if (v1) {
LOGD("env->DeleteLocalRef(%p):v1", v1);
env->DeleteLocalRef(v1);
}
v1 = (jobject) v2;
LOGD("c:check-cast \x76\x30\x2c\x20\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b");
{
#define EX_HANDLE EX_UnwindBlock
jclass &clz = cls2;
D2C_RESOLVE_CLASS(clz,"java/lang/String");
D2C_CHECK_CAST(v1, clz, "java/lang/String");
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("10:if-eqz \x76\x30\x2c\x20\x2b\x33");
if(v1 == NULL){
goto L2;
}
else {
goto L1;
}
L1:
return (jstring) v1;
L2:
v3 = 2;
v3 = 2;
LOGD("18:invoke-static \x76\x31\x34\x2c\x20\x76\x30\x2c\x20\x4c\x61\x6e\x64\x72\x6f\x69\x64\x2f\x75\x74\x69\x6c\x2f\x42\x61\x73\x65\x36\x34\x3b\x2d\x3e\x64\x65\x63\x6f\x64\x65\x28\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x20\x49\x29\x5b\x42");
{
#define EX_HANDLE EX_UnwindBlock
jclass &clz = cls3;
jmethodID &mid = mth1;
D2C_RESOLVE_STATIC_METHOD(clz, mid, "android/util/Base64", "decode", "(Ljava/lang/String;I)[B");
jvalue args[] = {{.l = v0},{.i = v3}};
v2 = (jarray) env->CallStaticObjectMethodA(clz, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("1e:move-result-object \x76\x31");
if (v4) {
LOGD("env->DeleteLocalRef(%p):v4", v4);
env->DeleteLocalRef(v4);
}
v4 = (jobject) v2;
LOGD("20:array-length \x76\x32\x2c\x20\x76\x31");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
v5 = env->GetArrayLength((jarray) v4);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
v6 = 4;
LOGD("24:if-ge \x76\x32\x2c\x20\x76\x33\x2c\x20\x2b\x33");
if(v5 >= v6) {
goto L4;
}
else {
goto L3;
}
L3:
return (jstring) v0;
L4:
v5 = 0;
v5 = 0;
LOGD("2c:aget-byte \x76\x33\x2c\x20\x76\x31\x2c\x20\x76\x32");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
{jbyte val;env->GetByteArrayRegion((jbyteArray) v4, (jint) v5, 1, &val);v6 = val;}
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("30:and-int/lit16 \x76\x33\x2c\x20\x76\x33\x2c\x20\x32\x35\x35");
v6 = (v6 & 255);
v7 = (jlong)(v6);
v8 = 16;
LOGD("3a:shl-long/2addr \x76\x33\x2c\x20\x76\x35");
v7 = (v7) << (v8 & 0x3f);
v9 = 1;
LOGD("3e:aget-byte \x76\x35\x2c\x20\x76\x31\x2c\x20\x76\x35");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
{jbyte val;env->GetByteArrayRegion((jbyteArray) v4, (jint) v9, 1, &val);v9 = val;}
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("42:and-int/lit16 \x76\x35\x2c\x20\x76\x35\x2c\x20\x32\x35\x35");
v9 = (v9 & 255);
v8 = (jlong)(v9);
v10 = 8;
v11 = 8;
LOGD("4c:shl-long/2addr \x76\x35\x2c\x20\x76\x37");
v8 = (v8) << (v11 & 0x3f);
LOGD("4e:or-long/2addr \x76\x33\x2c\x20\x76\x35");
v7 = (v7 | v8);
LOGD("50:aget-byte \x76\x30\x2c\x20\x76\x31\x2c\x20\x76\x30");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
{jbyte val;env->GetByteArrayRegion((jbyteArray) v4, (jint) v3, 1, &val);v3 = val;}
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("54:and-int/lit16 \x76\x30\x2c\x20\x76\x30\x2c\x20\x32\x35\x35");
v3 = (v3 & 255);
v8 = (jlong)(v3);
LOGD("5a:or-long/2addr \x76\x33\x2c\x20\x76\x35");
v7 = (v7 | v8);
LOGD("5c:array-length \x76\x30\x2c\x20\x76\x31");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
v3 = env->GetArrayLength((jarray) v4);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
v8 = 3;
v9 = 3;
LOGD("60:sub-int/2addr \x76\x30\x2c\x20\x76\x35");
v3 = (v3 - v9);
LOGD("62:new-array \x76\x36\x2c\x20\x76\x30\x2c\x20\x5b\x42");
{
#define EX_HANDLE EX_UnwindBlock
if (v3 < 0) {
d2c_throw_exception(env, "java/lang/NegativeArraySizeException", "negative array size");
goto EX_HANDLE;
}
if (v12) {
LOGD("env->DeleteLocalRef(%p):v12", v12);
env->DeleteLocalRef(v12);
}
v12 = (jarray) env->NewByteArray((jint) v3);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
L5:
LOGD("66:if-ge \x76\x32\x2c\x20\x76\x30\x2c\x20\x2b\x33\x34");
if(v5 >= v3) {
goto L10;
}
else {
goto L6;
}
L6:
v13 = (jlong)(v5);
LOGD("6c:add-long/2addr \x76\x38\x2c\x20\x76\x33");
v13 = (v13 + v7);
LOGD("6e:ushr-long \x76\x31\x30\x2c\x20\x76\x38\x2c\x20\x76\x35");
v14 = ((uint64_t) v13) >> (v8 & 0x3f);
v15 = -7046029254386353131;
LOGD("7c:mul-long/2addr \x76\x31\x30\x2c\x20\x76\x31\x32");
v14 = (v14 * v15);
v15 = 81985529216486895;
LOGD("88:add-long/2addr \x76\x31\x30\x2c\x20\x76\x31\x32");
v14 = (v14 + v15);
LOGD("8a:invoke-static \x76\x31\x30\x2c\x20\x76\x31\x31\x2c\x20\x4c\x61\x6f\x2f\x6e\x6a\x2f\x63\x6b\x2f\x75\x6e\x3b\x2d\x3e\x6d\x69\x78\x36\x34\x28\x4a\x29\x4a");
{
#define EX_HANDLE EX_UnwindBlock
jclass &clz = cls0;
jmethodID &mid = mth2;
D2C_RESOLVE_STATIC_METHOD(clz, mid, "ao/nj/ck/un", "mix64", "(J)J");
jvalue args[] = {{.j = (jlong) v14}};
v16 = (jlong) env->CallStaticLongMethodA(clz, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("90:move-result-wide \x76\x31\x30");
v14 = (jlong) v16;
v15 = 7;
LOGD("96:and-long/2addr \x76\x38\x2c\x20\x76\x31\x32");
v13 = (v13 & v15);
v17 = (jint)(v13);
L7:
LOGD("9a:if-ge \x76\x38\x2c\x20\x76\x37\x2c\x20\x2d\x31\x61");
if(v17 >= v10) {
goto L5;
}
else {
goto L8;
}
L8:
LOGD("9e:if-ge \x76\x32\x2c\x20\x76\x30\x2c\x20\x2d\x31\x63");
if(v5 >= v3) {
goto L5;
}
else {
goto L9;
}
L9:
LOGD("a2:mul-int/lit8 \x76\x39\x2c\x20\x76\x38\x2c\x20\x38");
v18 = (v17 * 8);
LOGD("a6:ushr-long \x76\x31\x32\x2c\x20\x76\x31\x30\x2c\x20\x76\x39");
v15 = ((uint64_t) v14) >> (v18 & 0x3f);
v18 = (jint)(v15);
LOGD("ac:add-int/lit8 \x76\x31\x32\x2c\x20\x76\x32\x2c\x20\x33");
v19 = (v5 + 3);
LOGD("b0:aget-byte \x76\x31\x32\x2c\x20\x76\x31\x2c\x20\x76\x31\x32");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
{jbyte val;env->GetByteArrayRegion((jbyteArray) v4, (jint) v19, 1, &val);v19 = val;}
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("b4:and-int/lit16 \x76\x31\x32\x2c\x20\x76\x31\x32\x2c\x20\x32\x35\x35");
v19 = (v19 & 255);
LOGD("b8:and-int/lit16 \x76\x39\x2c\x20\x76\x39\x2c\x20\x32\x35\x35");
v18 = (v18 & 255);
LOGD("bc:xor-int/2addr \x76\x39\x2c\x20\x76\x31\x32");
v18 = (v18 ^ v19);
v18 = (jbyte)(v18);
LOGD("c0:aput-byte \x76\x39\x2c\x20\x76\x36\x2c\x20\x76\x32");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v12);
{jbyte val = v18;env->SetByteArrayRegion((jbyteArray) v12, (jint) v5, 1, &val);}
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("c4:add-int/lit8 \x76\x38\x2c\x20\x76\x38\x2c\x20\x31");
v17 = (v17 + 1);
LOGD("c8:add-int/lit8 \x76\x32\x2c\x20\x76\x32\x2c\x20\x31");
v5 = (v5 + 1);
goto L7;
L10:
LOGD("ce:new-instance \x76\x30\x2c\x20\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b");
{
#define EX_HANDLE EX_UnwindBlock
if (v1) {
LOGD("env->DeleteLocalRef(%p):v1", v1);
env->DeleteLocalRef(v1);
}
jclass &clz = cls2;
D2C_RESOLVE_CLASS(clz,"java/lang/String");
v1 = (jstring) env->AllocObject(clz);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("d2:const-string \x76\x31\x2c\x20\x27\x55\x54\x46\x2d\x38\x27");
if (v4) {
LOGD("env->DeleteLocalRef(%p):v4", v4);
env->DeleteLocalRef(v4);
}
v4 = (jstring) env->NewStringUTF("\x55\x54\x46\x2d\x38");
LOGD("d6:invoke-direct \x76\x30\x2c\x20\x76\x36\x2c\x20\x76\x31\x2c\x20\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x2d\x3e\x3c\x69\x6e\x69\x74\x3e\x28\x5b\x42\x20\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x29\x56");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v1);
jclass &clz = cls2;
jmethodID &mid = mth3;
D2C_RESOLVE_METHOD(clz, mid, "java/lang/String", "<init>", "([BLjava/lang/String;)V");
jvalue args[] = {{.l = v12},{.l = v4}};
env->CallVoidMethodA(v1, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("dc:sget-object \x76\x31\x2c\x20\x4c\x61\x6f\x2f\x6e\x6a\x2f\x63\x6b\x2f\x75\x6e\x3b\x2d\x3e\x43\x41\x43\x48\x45\x20\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x63\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x2f\x43\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x48\x61\x73\x68\x4d\x61\x70\x3b");
{
#define EX_HANDLE EX_UnwindBlock
if (v4) {
LOGD("env->DeleteLocalRef(%p):v4", v4);
env->DeleteLocalRef(v4);
}
jclass &clz = cls0;
jfieldID &fld = fld0;
D2C_RESOLVE_STATIC_FIELD(clz, fld, "ao/nj/ck/un", "CACHE", "Ljava/util/concurrent/ConcurrentHashMap;");
v4 = (jobject) env->GetStaticObjectField(clz,fld);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("e0:invoke-virtual \x76\x31\x2c\x20\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x63\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x2f\x43\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x48\x61\x73\x68\x4d\x61\x70\x3b\x2d\x3e\x73\x69\x7a\x65\x28\x29\x49");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
jclass &clz = cls1;
jmethodID &mid = mth4;
D2C_RESOLVE_METHOD(clz, mid, "java/util/concurrent/ConcurrentHashMap", "size", "()I");
jvalue args[] = {};
v20 = (jint) env->CallIntMethodA(v4, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
LOGD("e6:move-result \x76\x32");
v5 = (jint) v20;
v6 = 30000;
LOGD("ec:if-ge \x76\x32\x2c\x20\x76\x33\x2c\x20\x2b\x35");
if(v5 >= v6) {
goto L12;
}
else {
goto L11;
}
L11:
LOGD("f0:invoke-virtual \x76\x31\x2c\x20\x76\x31\x34\x2c\x20\x76\x30\x2c\x20\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x63\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x2f\x43\x6f\x6e\x63\x75\x72\x72\x65\x6e\x74\x48\x61\x73\x68\x4d\x61\x70\x3b\x2d\x3e\x70\x75\x74\x28\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x20\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x29\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b");
{
#define EX_HANDLE EX_UnwindBlock
D2C_NOT_NULL(v4);
jclass &clz = cls1;
jmethodID &mid = mth5;
D2C_RESOLVE_METHOD(clz, mid, "java/util/concurrent/ConcurrentHashMap", "put", "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
jvalue args[] = {{.l = v0},{.l = v1}};
v2 = (jobject) env->CallObjectMethodA(v4, mid, args);
D2C_CHECK_PENDING_EX;
#undef EX_HANDLE
}
if (v2) {
LOGD("env->DeleteLocalRef(%p):v2", v2);
env->DeleteLocalRef(v2);
}
L12:
return (jstring) v1;
EX_UnwindBlock: return NULL;
}
