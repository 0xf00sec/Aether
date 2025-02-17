#ifndef AETHER_X86_H
#define AETHER_X86_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

typedef enum {
    X86_OP_NONE = 0,
    /* Data movement */
    X86_OP_MOV,
    X86_OP_MOVZX,
    X86_OP_MOVSX,
    X86_OP_LEA,
    X86_OP_XCHG,
    X86_OP_CMOV,       /* CMOVcc */
    X86_OP_PUSH,
    X86_OP_POP,
    /* Arithmetic */
    X86_OP_ADD,
    X86_OP_SUB,
    X86_OP_ADC,
    X86_OP_SBB,
    X86_OP_INC,
    X86_OP_DEC,
    X86_OP_NEG,
    X86_OP_IMUL,
    X86_OP_MUL,
    X86_OP_IDIV,
    X86_OP_DIV,
    /* Logical */
    X86_OP_AND,
    X86_OP_OR,
    X86_OP_XOR,
    X86_OP_NOT,
    X86_OP_TEST,
    /* Shift/rotate */
    X86_OP_SHL,
    X86_OP_SHR,
    X86_OP_SAR,
    X86_OP_ROL,
    X86_OP_ROR,
    /* Compare */
    X86_OP_CMP,
    /* Branches */
    X86_OP_JMP,
    X86_OP_JCC,         /* Jcc (conditional) */
    X86_OP_CALL,
    X86_OP_RET,
    X86_OP_LOOP,
    /* Set */
    X86_OP_SETcc,
    /* Bit */
    X86_OP_BT,
    X86_OP_BTS,
    X86_OP_BTR,
    X86_OP_BSF,
    X86_OP_BSR,
    X86_OP_POPCNT,
    X86_OP_LZCNT,
    X86_OP_TZCNT,
    /* String */
    X86_OP_REP,
    /* System */
    X86_OP_NOP,
    X86_OP_SYSCALL,
    X86_OP_INT,
    X86_OP_HLT,
    X86_OP_UD2,
    /* SIMD (opaque) */
    X86_OP_SIMD,
    /* Misc */
    X86_OP_CQO,        /* CQO/CDQ/CWD */
    X86_OP_LAHF,
    X86_OP_SAHF,
} x86_op_t;

/* x86 condition codes (for Jcc, CMOVcc, SETcc) */
typedef enum {
    X86_CC_O = 0, X86_CC_NO, X86_CC_B, X86_CC_AE,
    X86_CC_E, X86_CC_NE, X86_CC_BE, X86_CC_A,
    X86_CC_S, X86_CC_NS, X86_CC_P, X86_CC_NP,
    X86_CC_L, X86_CC_GE, X86_CC_LE, X86_CC_G,
} x86_cc_t;

/* Register IDs */
#define X86_REG_RAX  0
#define X86_REG_RCX  1
#define X86_REG_RDX  2
#define X86_REG_RBX  3
#define X86_REG_RSP  4
#define X86_REG_RBP  5
#define X86_REG_RSI  6
#define X86_REG_RDI  7
#define X86_REG_R8   8
#define X86_REG_R9   9
#define X86_REG_R10  10
#define X86_REG_R11  11
#define X86_REG_R12  12
#define X86_REG_R13  13
#define X86_REG_R14  14
#define X86_REG_R15  15
#define X86_REG_NONE 0xFF

/* System V ABI volatility */
static const bool x86_volatile[16] = {
    true,  /* rax */ true,  /* rcx */ true,  /* rdx */ false, /* rbx */
    false, /* rsp */ false, /* rbp */ true,  /* rsi */ true,  /* rdi */
    true,  /* r8  */ true,  /* r9  */ true,  /* r10 */ true,  /* r11 */
    false, /* r12 */ false, /* r13 */ false, /* r14 */ false, /* r15 */
};

/* Addressing mode */
typedef enum {
    X86_ADDR_NONE = 0,
    X86_ADDR_REG,          /* mod=3: register direct */
    X86_ADDR_MEM,          /* [base + index*scale + disp] */
    X86_ADDR_RIP,          /* [RIP + disp32] */
} x86_addr_mode_t;

typedef struct {
    uint8_t raw[15];
    uint8_t len;
    x86_op_t op;

    uint8_t reg;           
    uint8_t rm;            
    uint8_t index;        
    uint8_t scale;         

    int64_t imm;           /* Immediate value */
    int64_t disp;          
    int64_t target;       

    /* Encoding details */
    uint8_t opcode[3];
    uint8_t opcode_len;
    uint8_t modrm;
    uint8_t sib;
    uint8_t rex;
    uint8_t prefix_count;
    uint8_t disp_size;
    uint8_t imm_size;

    /* Flags */
    bool is_64bit;         
    bool sets_flags;       /* Modifies RFLAGS */
    bool reads_flags;     
    bool valid;
    bool is_control_flow;
    bool is_privileged;    
    bool has_modrm;
    bool has_sib;
    bool has_imm;
    bool rip_relative;
    bool is_simd;
    bool has_lock;
    bool has_rep;

    x86_cc_t cc;

    /* Addressing */
    x86_addr_mode_t addr_mode;
    uint8_t access_size;   /* Memory access size in bytes */

    /* Register tracking for liveness */
    uint8_t regs_read[6];
    uint8_t regs_written[4];
    uint8_t num_regs_read;
    uint8_t num_regs_written;
} x86_inst_t;

/* Decode one x86-64 instruction. Returns false on failure. */
bool x86_decode(const uint8_t *code, size_t max_len, x86_inst_t *out);

static inline uint8_t x86_modrm_mod(uint8_t m) { return (m >> 6) & 3; }
static inline uint8_t x86_modrm_reg(uint8_t m) { return (m >> 3) & 7; }
static inline uint8_t x86_modrm_rm(uint8_t m)  { return m & 7; }
static inline uint8_t x86_sib_scale(uint8_t s)  { return (s >> 6) & 3; }
static inline uint8_t x86_sib_index(uint8_t s)  { return (s >> 3) & 7; }
static inline uint8_t x86_sib_base(uint8_t s)   { return s & 7; }

#endif /* AETHER_X86_H */
