#ifndef DECODER_X86_H
#define DECODER_X86_H

/* 
 * X86-64 Architecture
 */
#define REG_RAX 0
#define REG_RCX 1
#define REG_RDX 2
#define REG_RBX 3
#define REG_RSP 4
#define REG_RBP 5
#define REG_RSI 6
#define REG_RDI 7
#define REG_R8  8
#define REG_R9  9
#define REG_R10 10
#define REG_R11 11
#define REG_R12 12
#define REG_R13 13
#define REG_R14 14
#define REG_R15 15

/* System V ABI */
static const bool arch_vols[16] = {
    true,  /* rax - volatile */
    true,  /* rcx - volatile */
    true,  /* rdx - volatile */
    false, /* rbx - callee-saved */
    false, /* rsp - callee-saved (stack pointer) */
    false, /* rbp - callee-saved (frame pointer) */
    true,  /* rsi - volatile */
    true,  /* rdi - volatile */
    true,  /* r8  - volatile */
    true,  /* r9  - volatile */
    true,  /* r10 - volatile */
    true,  /* r11 - volatile */
    false, /* r12 - callee-saved */
    false, /* r13 - callee-saved */
    false, /* r14 - callee-saved */
    false  /* r15 - callee-saved */
};

/* Inline */
static inline uint8_t modrm_reg(uint8_t m) { return (m >> 3) & 7; }
static inline uint8_t modrm_rm(uint8_t m)  { return m & 7; }
static inline uint8_t modrm_mod(uint8_t m) { return (m >> 6) & 3; }

#endif /* DECODER_X86_H */
