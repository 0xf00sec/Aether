#ifndef AETHER_ARM64_H
#define AETHER_ARM64_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* Operation types */
typedef enum {
    ARM_OP_NONE = 0,
    /* Branches */
    ARM_OP_B,
    ARM_OP_BL,
    ARM_OP_B_COND,
    ARM_OP_CBZ,
    ARM_OP_CBNZ,
    ARM_OP_TBZ,
    ARM_OP_TBNZ,
    ARM_OP_BR,
    ARM_OP_BLR,
    ARM_OP_RET,
    /* Arithmetic */
    ARM_OP_ADD,
    ARM_OP_ADDS,
    ARM_OP_SUB,
    ARM_OP_SUBS,
    ARM_OP_ADC,
    ARM_OP_SBC,
    ARM_OP_NEG,
    /* Logical */
    ARM_OP_AND,
    ARM_OP_ANDS,
    ARM_OP_ORR,
    ARM_OP_ORN,
    ARM_OP_EOR,
    ARM_OP_EON,
    ARM_OP_BIC,
    /* Move */
    ARM_OP_MOV_REG,
    ARM_OP_MOV_IMM,
    ARM_OP_MOVK,
    ARM_OP_MVN,
    /* Compare */
    ARM_OP_CMP,
    ARM_OP_CMN,
    ARM_OP_TST,
    ARM_OP_CCMP,
    ARM_OP_CCMN,
    /* Conditional select */
    ARM_OP_CSEL,
    ARM_OP_CSINC,
    ARM_OP_CSINV,
    ARM_OP_CSNEG,
    /* Multiply */
    ARM_OP_MUL,
    ARM_OP_MADD,
    ARM_OP_MSUB,
    ARM_OP_SMULL,
    ARM_OP_UMULL,
    ARM_OP_SMULH,
    ARM_OP_UMULH,
    /* Divide */
    ARM_OP_UDIV,
    ARM_OP_SDIV,
    /* Shift */
    ARM_OP_LSL,
    ARM_OP_LSR,
    ARM_OP_ASR,
    ARM_OP_ROR,
    /* Bitfield */
    ARM_OP_SBFM,
    ARM_OP_BFM,
    ARM_OP_UBFM,
    ARM_OP_EXTR,
    /* PC-relative */
    ARM_OP_ADRP,
    ARM_OP_ADR,
    /* Load/Store */
    ARM_OP_LDR,
    ARM_OP_LDRB,
    ARM_OP_LDRH,
    ARM_OP_LDRSB,
    ARM_OP_LDRSH,
    ARM_OP_LDRSW,
    ARM_OP_STR,
    ARM_OP_STRB,
    ARM_OP_STRH,
    ARM_OP_LDP,
    ARM_OP_STP,
    ARM_OP_LDXR,
    ARM_OP_STXR,
    ARM_OP_LDAR,
    ARM_OP_STLR,
    /* System */
    ARM_OP_SVC,
    ARM_OP_MRS,
    ARM_OP_MSR,
    ARM_OP_NOP,
    ARM_OP_DMB,
    ARM_OP_DSB,
    ARM_OP_ISB,
    ARM_OP_BRK,
    /* PAC */
    ARM_OP_PACIASP,
    ARM_OP_AUTIASP,
    ARM_OP_RETAA,
    /* SIMD/FP (opaque) */
    ARM_OP_SIMD,
} arm_op_t;

/* Condition codes */
typedef enum {
    COND_EQ = 0, COND_NE, COND_CS, COND_CC,
    COND_MI, COND_PL, COND_VS, COND_VC,
    COND_HI, COND_LS, COND_GE, COND_LT,
    COND_GT, COND_LE, COND_AL, COND_NV
} arm_cond_t;

/* Addressing mode for load/store */
typedef enum {
    ADDR_NONE = 0,    
    ADDR_OFFSET,       
    ADDR_PRE_INDEX,    
    ADDR_POST_INDEX,  
    ADDR_REG_OFFSET,   
    ADDR_LITERAL,      /* PC-relative literal load */
} addr_mode_t;

/* Decoded instruction */
typedef struct {
    uint32_t raw;
    arm_op_t op;

    uint8_t rd;
    uint8_t rn;
    uint8_t rm;
    uint8_t ra;            

    int64_t imm;           
    int64_t target;       
    uint8_t bit_pos;       

    /* Flags */
    bool is_64bit;         
    bool sets_flags;       
    bool reads_flags;     
    bool valid;
    bool is_control_flow;  
    bool is_privileged;    /* SVC, MRS, MSR, PAC */
    bool rn_is_sp;         /* true when Rn=31 means SP (not XZR) */

    /* Shift/extend on Rm */
    uint8_t shift_type;    /* 0=LSL 1=LSR 2=ASR 3=ROR */
    uint8_t shift_amount;

    /* Load/store specifics */
    addr_mode_t addr_mode;
    uint8_t access_size;   /* 1/2/4/8 bytes */

    /* Condition (B.cond, CSEL, CCMP) */
    arm_cond_t cond;

    /* Register tracking for liveness */
    uint8_t regs_read[4];
    uint8_t regs_written[2];
    uint8_t num_regs_read;
    uint8_t num_regs_written;
} arm64_inst_t;

/* Decode one 4-byte ARM64 instruction */
bool arm64_decode(const uint8_t *code, arm64_inst_t *out);

#endif /* AETHER_ARM64_H */
