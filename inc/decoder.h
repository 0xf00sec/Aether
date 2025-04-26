#pragma once
/**
 * @file decoder.h
 * Self-Explanatory
 */
    #include <wisp.h>

#if defined(ARCH_X86)
typedef enum {
    OP_NONE, OP_REG, OP_MEM, OP_IMM
} op_type;

typedef struct {
    op_type type;
    uint8_t size;
    union {
        uint8_t reg;
        struct {
            uint8_t base, index, scale;
            int64_t disp;
        } mem;
        uint64_t imm;
    };
} operand;

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
    operand ops[3];
} x86_instruction_t;

typedef uint8_t (*mem_read_fn)(uintptr_t addr);

bool decode_x86(const uint8_t *code, uintptr_t ip, x86_instruction_t *inst, mem_read_fn mem_read);

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
