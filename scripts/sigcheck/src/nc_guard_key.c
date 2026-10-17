/* nc_guard_key.c — .ncguard 密钥派生（证书绑定）
 *
 * 照抄 XopProtector 的 key ladder（crypto/key_ladder.cpp + crypto/sha256.cpp
 * 的 hkdf_sha256 + crypto/apk_sign.cpp 的定点读证书），剥离其对
 * protector::sys_* / std::vector 的依赖，只保留四件事：
 *   1. sha256（自带精简实现，避免依赖 sig_check.c/sig_guard2.c 的 static 版）
 *   2. hmac_sha256
 *   3. hkdf_sha256（RFC 5869）
 *   4. apk 第一签名者证书 DER 的定点读（只读 EOCD/CD/Signing Block，几十 KB）
 *
 * 为什么做证书绑定（威胁模型）：
 *   原实现 K_so 由 --cert-hex 传入或落默认值，而 so-section-lock.py 就在仓库里、
 *   派生逻辑公开 → 攻击者自己跑一遍脚本就能解出密钥，4012 字节密文秒变明文。
 *   证书绑定后 K_so = HKDF(master, SHA256(certDER), pkg)：换 key 重打包 →
 *   cert 变 → K_so 变 → 密文解不开。这是 Xop 的原设计，我们照抄。
 *
 * 与 so-section-lock.py 的契约（两侧必须逐字节一致）：
 *   label = "nc-so-v1" + package          （Xop 用 "xop-so-v1"+package）
 *   salt  = SHA256(certDER)
 *   ikm   = master（32 字节，构建期与运行期同源）
 *   out   = 16 字节
 */
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

#include "nc_guard_key.h"

/* ── SHA-256（FIPS 180-4）───────────────────────────────────────────
 * 照抄 scripts/sigcheck/src/sig_check.c:239-305 的已验证实现
 * （test-sig-guard2.sh 与 test-lsgs-strings.sh 6/6 对拍钉死）。
 * 不自己另写——我自己写的那版 block 压缩有错，NIST 向量全错
 * （"abc" 应 ba7816bf...，实得 554144d9...）。教训：密码学原语
 * 必须复用仓内已验证实现，不重造轮子。 */
#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z)  (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

struct ksha_ctx_s {
    uint32_t state[8];
    uint8_t data[64];
    size_t datalen;
    unsigned long long bitlen;
};

static const uint32_t K256[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

static void k_sha_transform(ksha_ctx *ctx, const uint8_t *data) {
    uint32_t m[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        m[i] = (uint32_t)data[i*4] << 24 | (uint32_t)data[i*4+1] << 16 |
               (uint32_t)data[i*4+2] << 8 | (uint32_t)data[i*4+3];
    for (; i < 64; i++)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e,f,g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void ksha_init(ksha_ctx *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
}

void ksha_update(ksha_ctx *ctx, const uint8_t *data, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            k_sha_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void ksha_final(ksha_ctx *ctx, uint8_t *out) {
    unsigned long long bits = ctx->bitlen + (unsigned long long)ctx->datalen * 8;
    unsigned char tail[128];
    size_t padlen, i;

    padlen = (ctx->datalen < 56) ? (56 - ctx->datalen) : (120 - ctx->datalen);
    memset(tail, 0, sizeof(tail));
    memcpy(tail, ctx->data, ctx->datalen);
    tail[ctx->datalen] = 0x80;
    for (i = 0; i < 8; i++)
        tail[ctx->datalen + padlen + i] = (unsigned char)(bits >> (56 - i*8));

    if (ctx->datalen + padlen + 8 == 64) {
        k_sha_transform(ctx, tail);
    } else {
        k_sha_transform(ctx, tail);
        k_sha_transform(ctx, tail + 64);
    }
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >> 8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

/* ── HMAC-SHA256（RFC 2104，照抄 Xop crypto/sha256.cpp:123）──────── */
void khmac_sha256(const uint8_t *key,size_t key_len,
                  const uint8_t *msg,size_t msg_len,uint8_t out[32]){
    uint8_t k0[64],ipad[64],opad[64],inner[32]; ksha_ctx c; size_t i;
    memset(k0,0,64);
    if(key_len>64){ksha_ctx t; ksha_init(&t);ksha_update(&t,key,key_len);ksha_final(&t,k0);}
    else memcpy(k0,key,key_len);
    for(i=0;i<64;i++){ipad[i]=k0[i]^0x36;opad[i]=k0[i]^0x5c;}
    ksha_init(&c);ksha_update(&c,ipad,64);ksha_update(&c,msg,msg_len);ksha_final(&c,inner);
    ksha_init(&c);ksha_update(&c,opad,64);ksha_update(&c,inner,32);ksha_final(&c,out);
}

/* ── HKDF-SHA256（RFC 5869，extract-then-expand）───────────────────
 * 与 so-section-lock.py 的 hkdf_sha256() 逐字节同算法：
 *   prk = HMAC(salt, ikm)
 *   okm = T(1)||T(2)||... , T(i)=HMAC(prk, T(i-1)||info||i)
 */
void khkdf_sha256(const uint8_t *ikm,size_t ikm_len,
                  const uint8_t *salt,size_t salt_len,
                  const uint8_t *info,size_t info_len,
                  uint8_t *out,size_t out_len){
    /* RFC 5869 expand：T(i) = HMAC(prk, T(i-1) || info || i)。
     * ⚠️ info 严禁截断——我第一版写了 `if(info_len>32) info_len=32`，
     * RFC 测试向量因此全错（34104666... vs 3cb25f25...）。info 极短
     * （label+pkg < 64B）但语义上必须完整传入。 */
    uint8_t prk[32],t[32]; size_t done=0; uint8_t counter=1;
    uint8_t msg[96]; size_t msglen;
    khmac_sha256(salt,salt_len,ikm,ikm_len,prk);
    memset(t,0,sizeof t);
    while(done<out_len){
        size_t n=0;
        if(counter>1){ memcpy(msg,t,32); n=32; }
        if(info_len){ size_t cp=info_len; if(cp>sizeof msg-1) cp=sizeof msg-1;
                      memcpy(msg+n,info,cp); n+=cp; }
        msg[n++]=counter;
        msglen=n;
        khmac_sha256(prk,32,msg,msglen,t);
        { size_t take=out_len-done; if(take>32)take=32; memcpy(out+done,t,take); done+=take; }
        counter++;
    }
    memset(prk,0,sizeof prk);
}

/* ── APK 第一签名者证书 DER 的定点读 ─────────────────────────────
 * 照抄 Xop crypto/apk_sign.cpp 的 parse_apk：只读 EOCD 尾区 + Signing
 * Block，不读整个 APK（4.6MB → 几十 KB）。v3 优先，回退 v2。
 * 与 sig_guard2.c 的 g2_extract_cert 同逻辑，但此处自带以免依赖 static 符号。 */
static int rd_at(int fd,uint64_t off,void *buf,size_t n){
    return pread(fd,buf,n,(off_t)off)==(ssize_t)n?0:-1;
}
static uint32_t le32(const uint8_t*p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static uint64_t le64(const uint8_t*p){uint64_t v=0;int i;for(i=7;i>=0;i--)v=v<<8|p[i];return v;}

/* v2/v3 scheme block 里第一个 certificate 的 DER */
static int first_cert_der(const uint8_t *p,size_t n,const uint8_t **der,uint32_t *der_len){
    size_t i=8;                     /* scheme block 前 8 字节是 length 字段 */
    while(i+12<=n){
        uint32_t sl=le32(p+i); i+=4;
        if(i+(size_t)sl>n) break;
        if(sl>=4){                  /* signed data length prefix */
            uint32_t certs=le32(p+i+sl-4);
            if(certs>0&&certs<n&&i+sl+4<=n){
                uint32_t cl=le32(p+i+sl);
                if((size_t)cl<=n-i-sl-4){*der=p+i+sl+4;*der_len=cl;return 0;}
            }
        }
        i+=sl;
    }
    return -1;
}

int ncg_apk_first_cert_der(const char *apk_path,uint8_t *der,size_t der_cap,size_t *der_len){
    int fd=open(apk_path,O_RDONLY);
    if(fd<0) return -1;
    struct stat st; if(fstat(fd,&st)!=0||st.st_size<64){close(fd);return -1;}
    uint64_t fsize=(uint64_t)st.st_size;

    /* 1) EOCD：从尾部前 64KB 内反向找 PK\x05\x06 */
    uint64_t search=fsize>65557?fsize-65557:0; uint64_t pos=fsize-22; uint8_t eocd[22];
    for(;pos>=search;pos--){ if(rd_at(fd,pos,eocd,22)!=0){close(fd);return -1;}
        if(eocd[0]==0x50&&eocd[1]==0x4b&&eocd[2]==0x05&&eocd[3]==0x06)break; }
    if(pos<search){close(fd);return -1;}
    uint64_t cd_off=le32(eocd+16);
    if(cd_off<32||cd_off>=fsize){close(fd);return -1;}

    /* 2) Signing Block footer：cd_off-24 处 size+magic
     * 照抄 XopProtector crypto/apk_sign.cpp:21-22：
     *   kMagicLo = 0x20676953204b5041 ("APK Sig ")
     *   kMagicHi = 0x3234206b636f6c42 ("Block 42")
     * ⚠️ 我第一版凭印象编了 0x342e726f6e6f632e / 0x2e706f6f6c，小端解出来是
     * ".conor.4" / "loop." —— magic 永不匹配，真 APK 提取必失败。 */
    uint8_t footer[24];
    if(rd_at(fd,cd_off-24,footer,24)!=0){close(fd);return -1;}
    if(le64(footer+8)!=0x20676953204b5041ULL||le64(footer+16)!=0x3234206b636f6c42ULL){
        close(fd);return -1;
    }
    uint64_t block_size=le64(footer);
    if(block_size<24||block_size+8>cd_off){close(fd);return -1;}
    uint64_t total=block_size+8, block_off=cd_off-total;
    if(total>der_cap+4096){close(fd);return -1;}     /* 防御性上限 */

    /* 3) 只把 block 读进栈缓冲，再在其中找 v3/v2 的 id-value 对 */
    static uint8_t blk[65536];
    if(total>sizeof blk){close(fd);return -1;}
    if(rd_at(fd,block_off,blk,(size_t)total)!=0){close(fd);return -1;}
    if(le64(blk)!=block_size){close(fd);return -1;}

    /* id-value 对遍历：APK Sig Block v2=0x7109871a, v3=0xf05368c0 */
    const uint8_t *v3=NULL,*v2=NULL; size_t v3n=0,v2n=0;
    {   size_t i=8;
        while(i+12<=total){
            uint64_t pl=le64(blk+i); i+=8;
            if(pl<4||i+pl>total) break;
            uint32_t id=le32(blk+i);
            const uint8_t *val=blk+i+4; size_t vn=(size_t)pl-4;
            if(id==0xf05368c0U){v3=val;v3n=vn;}
            else if(id==0x7109871aU){v2=val;v2n=vn;}
            i+=pl;
        }
    }
    const uint8_t *cd=NULL; uint32_t cl=0;
    if(v3&&first_cert_der(v3,v3n,&cd,&cl)==0) ;
    else if(v2&&first_cert_der(v2,v2n,&cd,&cl)==0) ;
    else {close(fd);return -1;}
    if((size_t)cl>der_cap){close(fd);return -1;}
    memcpy(der,cd,cl); *der_len=cl;
    close(fd);
    return 0;
}

/* ── 派生 K_so（与 so-section-lock.py 的 derive_app_keys['so'] 一致）──
 * k_so = HKDF-SHA256(ikm=master, salt=SHA256(certDER), info="nc-so-v1"+pkg, 16) */
int ncg_derive_k_so(const uint8_t master[32],const uint8_t cert_sha256[32],
                    const char *pkg,uint8_t out[16]){
    if(!master||!cert_sha256||!pkg||!pkg[0]||!out) return -1;
    uint8_t info[128]; size_t n=0;
    memcpy(info,"nc-so-v1",8); n=8;
    { size_t l=strlen(pkg); if(l>sizeof info-9) l=sizeof info-9; memcpy(info+n,pkg,l); n+=l; }
    khkdf_sha256(master,32,cert_sha256,32,info,n,out,16);
    return 0;
}
