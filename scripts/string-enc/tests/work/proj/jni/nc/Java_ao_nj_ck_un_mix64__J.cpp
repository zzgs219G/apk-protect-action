#include "Dex2C.h"

/* Lao/nj/ck/un;->mix64(J)J */
extern "C" JNIEXPORT jlong JNICALL
Java_ao_nj_ck_un_mix64__J(JNIEnv *env, jobject thiz, jlong p2){
jlong v0;
jlong v1;
v0 = (jlong)p2;
L0:
v1 = 30;
LOGD("4:ushr-long \x76\x30\x2c\x20\x76\x32\x2c\x20\x76\x30");
v1 = ((uint64_t) v0) >> (v1 & 0x3f);
LOGD("8:xor-long/2addr \x76\x32\x2c\x20\x76\x30");
v0 = (v0 ^ v1);
v1 = -4658895280553007687;
LOGD("14:mul-long/2addr \x76\x32\x2c\x20\x76\x30");
v0 = (v0 * v1);
v1 = 27;
LOGD("1a:ushr-long \x76\x30\x2c\x20\x76\x32\x2c\x20\x76\x30");
v1 = ((uint64_t) v0) >> (v1 & 0x3f);
LOGD("1e:xor-long/2addr \x76\x32\x2c\x20\x76\x30");
v0 = (v0 ^ v1);
v1 = -7723592293110705685;
LOGD("2a:mul-long/2addr \x76\x32\x2c\x20\x76\x30");
v0 = (v0 * v1);
v1 = 31;
LOGD("30:ushr-long \x76\x30\x2c\x20\x76\x32\x2c\x20\x76\x30");
v1 = ((uint64_t) v0) >> (v1 & 0x3f);
LOGD("34:xor-long/2addr \x76\x32\x2c\x20\x76\x30");
v0 = (v0 ^ v1);
return (jlong) v0;
EX_UnwindBlock: return (jlong)0;
}
