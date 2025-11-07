#ifndef DECODER_ARM64_H
#define DECODER_ARM64_H

/* 
 * ARM64 Architecture
 */
#define ARM64_REG_X0   0
#define ARM64_REG_X1   1
#define ARM64_REG_X2   2
#define ARM64_REG_X3   3
#define ARM64_REG_X4   4
#define ARM64_REG_X5   5
#define ARM64_REG_X6   6
#define ARM64_REG_X7   7
#define ARM64_REG_X8   8
#define ARM64_REG_X9   9
#define ARM64_REG_X10  10
#define ARM64_REG_X11  11
#define ARM64_REG_X12  12
#define ARM64_REG_X13  13
#define ARM64_REG_X14  14
#define ARM64_REG_X15  15
#define ARM64_REG_X16  16  /* IP0 */
#define ARM64_REG_X17  17  /* IP1 */
#define ARM64_REG_X18  18 
#define ARM64_REG_X19  19
#define ARM64_REG_X20  20
#define ARM64_REG_X21  21
#define ARM64_REG_X22  22
#define ARM64_REG_X23  23
#define ARM64_REG_X24  24
#define ARM64_REG_X25  25
#define ARM64_REG_X26  26
#define ARM64_REG_X27  27
#define ARM64_REG_X28  28
#define ARM64_REG_X29  29  /* FP */
#define ARM64_REG_X30  30  /* LR */
#define ARM64_REG_SP   31  /* SP */
#define ARM_REG_PC     32  /* PC */

/* ARM64 callee-saved registers (AAPCS64) */
static const uint8_t arm64_callee_saved[] = { 
    ARM64_REG_X19, ARM64_REG_X20, ARM64_REG_X21, ARM64_REG_X22, 
    ARM64_REG_X23, ARM64_REG_X24, ARM64_REG_X25, ARM64_REG_X26, 
    ARM64_REG_X27, ARM64_REG_X28, ARM64_REG_X29 
};

/* ARM64 caller-saved registers (volatile) */
static const uint8_t arm64_caller_saved[] = {
    ARM64_REG_X0, ARM64_REG_X1, ARM64_REG_X2, ARM64_REG_X3, 
    ARM64_REG_X4, ARM64_REG_X5, ARM64_REG_X6, ARM64_REG_X7, 
    ARM64_REG_X8, ARM64_REG_X9, ARM64_REG_X10, ARM64_REG_X11, 
    ARM64_REG_X12, ARM64_REG_X13, ARM64_REG_X14, ARM64_REG_X15, 
    ARM64_REG_X16, ARM64_REG_X17, ARM64_REG_X18
};

/* ARM64 register volatility (true = caller-saved/volatile) */
static const bool arm64_vols[32] = {
    true,  /* x0 */
    true,  /* x1 */
    true,  /* x2 */
    true,  /* x3 */
    true,  /* x4 */
    true,  /* x5 */
    true,  /* x6 */
    true,  /* x7 */
    true,  /* x8 */
    true,  /* x9 */
    true,  /* x10*/
    true,  /* x11*/
    true,  /* x12*/
    true,  /* x13*/
    true,  /* x14*/
    true,  /* x15*/
    true,  /* x16 - IP0 */
    true,  /* x17 - IP1 */
    true,  /* x18 - platform register */
    false, /* x19 */
    false, /* x20 */
    false, /* x21 */
    false, /* x22 */
    false, /* x23 */
    false, /* x24 */
    false, /* x25 */
    false, /* x26 */
    false, /* x27 */
    false, /* x28 */
    false, /* x29 frame pointer */
    false, /* x30 link register */
    false  /* x31/SP stack pointer */
};

#define ARM64_PATCH_B_BL     1  
#define ARM64_PATCH_B_COND  2 
#define ARM64_PATCH_CBZ      3  /* CBZ or CBNZ */
#define ARM64_PATCH_TBZ      4  /* TBZ or TBNZ */
#define ARM64_PATCH_BR       5  

typedef struct {
    size_t off;           /* Offset in new buffer */
    size_t blki;          /* Original block index */
    int typ;              /* Patch type (ARM64_PATCH_*) */
    uint64_t abs_target; 
    size_t inst_len;      
    bool is_call;        
    uint8_t condition;   
    uint8_t bit_pos;      
    uint32_t raw_insn;    /* Original instruction for rollback */
} arm64_patch_t;

#endif /* DECODER_ARM64_H */
