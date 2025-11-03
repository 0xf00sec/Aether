#ifndef FORGE_H
#define FORGE_H

#include <aether.h>

static void write_rel32(uint8_t *p, int32_t v) {memcpy(p, &v, sizeof(v));}
static void write_u64(uint8_t *p, uint64_t v) {memcpy(p, &v, sizeof(v));}

#if defined(ARCH_ARM)
static inline uint8_t random_arm_reg(chacha_state_t *rng) {
    if (!rng) return 0;
    
    const uint8_t cool_regs[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28
    };
    const size_t num_clear = sizeof(cool_regs) / sizeof(cool_regs[0]);
    
    return cool_regs[chacha20_random(rng) % num_clear];
}
#endif

__attribute__((always_inline)) inline void forge_ghost_x86(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;
    
    /* Use only volatile/scratch reg, avoid RSP(4) and RBP(5) */
    const uint8_t cool_regs[] = {0, 1, 2, 6, 7}; /*  RAX, RCX, RDX, RSI, RDI */
    const size_t num_clear = sizeof(cool_regs) / sizeof(cool_regs[0]);
    
    /* try random selection */
    uint32_t variant_seed = chacha20_random(rng) ^ value;
    
    uint8_t reg1 = cool_regs[chacha20_random(rng) % num_clear]; 
    uint8_t reg2 = cool_regs[chacha20_random(rng) % num_clear];
    uint8_t reg3 = cool_regs[chacha20_random(rng) % num_clear];
    while (reg2 == reg1) reg2 = cool_regs[chacha20_random(rng) % num_clear];
    while (reg3 == reg1 || reg3 == reg2) reg3 = cool_regs[chacha20_random(rng) % num_clear];

    uint8_t imm8 = chacha20_random(rng) & 0xFF;
    uint64_t imm64 = ((uint64_t)chacha20_random(rng) << 32) | chacha20_random(rng);

    switch (variant_seed % 12) {
        case 0: { /* XOR + TEST + JZ - always zero, always jumps */
            buf[0] = 0x48; buf[1] = 0x31; buf[2] = 0xC0 | (reg1 << 3) | reg1; /*  xor reg1, reg1 */
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1; /*  test reg1, reg1 */
            buf[6] = 0x0F; buf[7] = 0x84;                                      /*  jz (always taken) */
            write_rel32(buf + 8, 0); /*  Jump to next instruction (dead code) */
            /*  Dead code that will never execute */
            buf[12] = 0x48; buf[13] = 0x83; buf[14] = 0xC0 | reg1; buf[15] = imm8;
            buf[16] = 0x48; buf[17] = 0x83; buf[18] = 0xE8 | reg1; buf[19] = imm8;
            *len = 20;
            break;
        }
        case 1: { /* MOV + XOR + TEST + JNZ */
            buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xC0 | (reg2 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x31; buf[5] = 0xC0 | (reg2 << 3) | reg2;
            buf[6] = 0x48; buf[7] = 0x85; buf[8] = 0xC0 | (reg2 << 3) | reg2;
            buf[9] = 0x0F; buf[10] = 0x85;
            write_rel32(buf + 11, 12);
            buf[15] = 0x68; write_rel32(buf + 16, (uint32_t)imm64);
            buf[20] = 0x48; buf[21] = 0x81; buf[22] = 0xC0 | reg2; write_rel32(buf + 23, (uint32_t)imm64);
            buf[27] = (uint8_t)(0x58 + reg2);
            *len = 28;
            break;
        }
        case 2: { /* LEA + CMP + JE */
            buf[0] = 0x48; buf[1] = 0x8D; buf[2] = 0x05 | (reg1 << 3); write_rel32(buf + 3, 12);
            buf[7] = 0x48; buf[8] = 0x39; buf[9] = 0xC0 | (reg1 << 3) | reg1;
            buf[10] = 0x0F; buf[11] = 0x84;
            write_rel32(buf + 12, 8);
            buf[16] = 0x48; buf[17] = 0x83; buf[18] = 0xC0 | reg1; buf[19] = imm8;
            buf[20] = 0x48; buf[21] = 0x83; buf[22] = 0xE8 | reg1; buf[23] = imm8;
            *len = 24;
            break;
        }
        case 3: { /* SUB + TEST + JZ */
            buf[0] = 0x48; buf[1] = 0x29; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            write_rel32(buf + 8, 12);
            buf[12] = 0x48; buf[13] = 0x81; buf[14] = 0xC0 | reg1; write_rel32(buf + 15, (uint32_t)imm64);
            buf[19] = 0x48; buf[20] = 0x81; buf[21] = 0xE8 | reg1; write_rel32(buf + 22, (uint32_t)imm64);
            *len = 26;
            break;
        }
        case 4: { /* AND + TEST + JZ */
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xE0 | reg1; buf[3] = imm8;
            buf[4] = 0x48; buf[5] = 0x85; buf[6] = 0xC0 | (reg1 << 3) | reg1;
            buf[7] = 0x0F; buf[8] = 0x84;
            write_rel32(buf + 9, 14);
            buf[13] = 0x48; buf[14] = 0x87; buf[15] = 0xC0 | (reg1 << 3) | reg3;
            buf[16] = 0x48; buf[17] = 0x87; buf[18] = 0xC0 | (reg3 << 3) | reg1;
            buf[19] = 0x48; buf[20] = 0x83; buf[21] = 0xC0 | reg1; buf[22] = imm8;
            *len = 23;
            break;
        }
        case 5: { /* PUSH + POP + TEST + JZ */
            buf[0] = (uint8_t)(0x50 | reg1);
            buf[1] = (uint8_t)(0x58 | reg1);
            buf[2] = 0x48; buf[3] = 0x85; buf[4] = 0xC0 | (reg1 << 3) | reg1;
            buf[5] = 0x0F; buf[6] = 0x84;
            write_rel32(buf + 7, 10);
            buf[11] = 0x48; buf[12] = 0x83; buf[13] = 0xC0 | reg1; buf[14] = imm8;
            buf[15] = 0x48; buf[16] = 0x83; buf[17] = 0xE8 | reg1; buf[18] = imm8;
            *len = 19;
            break;
        }
        case 6: { /* XCHG + TEST + JZ */
            buf[0] = 0x48; buf[1] = 0x87; buf[2] = 0xC0 | (reg1 << 3) | reg2;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            write_rel32(buf + 8, 11);
            buf[12] = 0x48; buf[13] = 0x87; buf[14] = 0xC0 | (reg1 << 3) | reg2;
            buf[15] = 0x48; buf[16] = 0x83; buf[17] = 0xC0 | reg1; buf[18] = imm8;
            buf[19] = 0x48; buf[20] = 0x83; buf[21] = 0xE8 | reg1; buf[22] = imm8;
            *len = 23;
            break;
        }
        case 7: { /* ADD + SUB + TEST + JZ */
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xC0 | reg1; buf[3] = imm8;
            buf[4] = 0x48; buf[5] = 0x83; buf[6] = 0xE8 | reg1; buf[7] = imm8;
            buf[8] = 0x48; buf[9] = 0x85; buf[10] = 0xC0 | (reg1 << 3) | reg1;
            buf[11] = 0x0F; buf[12] = 0x84;
            write_rel32(buf + 13, 14);
            buf[17] = 0x68; write_rel32(buf + 18, (uint32_t)imm64);
            buf[22] = 0x48; buf[23] = 0x81; buf[24] = 0xC0 | reg2; write_rel32(buf + 25, (uint32_t)imm64);
            buf[29] = (uint8_t)(0x58 + reg2);
            *len = 30;
            break;
        }
        case 8: { /* MOV + ADD + CMP + JNE */
            buf[0] = 0x48; buf[1] = 0xB8 | reg1;
            write_u64(buf + 2, imm64);
            buf[10] = 0x48; buf[11] = 0x83; buf[12] = 0xC0 | reg1; buf[13] = imm8;
            buf[14] = 0x48; buf[15] = 0x3B; buf[16] = 0xC0 | (reg1 << 3) | reg1;
            buf[17] = 0x0F; buf[18] = 0x85;
            write_rel32(buf + 19, 6);
            buf[23] = 0x48; buf[24] = 0x83; buf[25] = 0xE8 | reg1; buf[26] = imm8;
            buf[27] = 0x48; buf[28] = 0x83; buf[29] = 0xC0 | reg1; buf[30] = imm8;
            *len = 31;
            break;
        }
        case 9: { /* OR + TEST + JNZ */
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xC8 | reg1; buf[3] = imm8;
            buf[4] = 0x48; buf[5] = 0x85; buf[6] = 0xC0 | (reg1 << 3) | reg1;
            buf[7] = 0x0F; buf[8] = 0x85;
            write_rel32(buf + 9, 10);
            buf[13] = 0x48; buf[14] = 0x83; buf[15] = 0xE0 | reg1; buf[16] = ~imm8;
            buf[17] = 0x48; buf[18] = 0x83; buf[19] = 0xC8 | reg1; buf[20] = imm8;
            *len = 21;
            break;
        }
        case 10: { /* NEG + TEST + JZ */
            buf[0] = 0x48; buf[1] = 0xF7; buf[2] = 0xD8 | reg1;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            write_rel32(buf + 8, 10);
            buf[12] = 0x48; buf[13] = 0xF7; buf[14] = 0xD8 | reg1;
            buf[15] = 0x48; buf[16] = 0x83; buf[17] = 0xC0 | reg1; buf[18] = imm8;
            buf[19] = 0x48; buf[20] = 0x83; buf[21] = 0xE8 | reg1; buf[22] = imm8;
            *len = 23;
            break;
        }
        default: { /* Complex multi-register sequence */
            buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xC0 | (reg2 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x89; buf[5] = 0xC0 | (reg3 << 3) | reg2;
            buf[6] = 0x48; buf[7] = 0x31; buf[8] = 0xC0 | (reg1 << 3) | reg1;
            buf[9] = 0x48; buf[10] = 0x85; buf[11] = 0xC0 | (reg1 << 3) | reg1;
            buf[12] = 0x0F; buf[13] = 0x84;
            write_rel32(buf + 14, 16);
            buf[18] = 0x48; buf[19] = 0x83; buf[20] = 0xC0 | reg1; buf[21] = imm8;
            buf[22] = 0x48; buf[23] = 0x83; buf[24] = 0xE8 | reg1; buf[25] = imm8;
            buf[26] = 0x48; buf[27] = 0x89; buf[28] = 0xC0 | (reg1 << 3) | reg2;
            buf[29] = 0x48; buf[30] = 0x89; buf[31] = 0xC0 | (reg2 << 3) | reg3;
            *len = 32;
            break;
        }
    }
}

/* Generate ARM64 opaque predicates always-taken/never-taken branches with dead code */
__attribute__((always_inline)) inline void forge_ghost_arm(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;
    
    uint32_t variant_seed = chacha20_random(rng) ^ value;
    
    uint8_t reg1 = random_arm_reg(rng);
    uint8_t reg2 = random_arm_reg(rng);
    uint8_t reg3 = random_arm_reg(rng);
    
    while (reg2 == reg1) reg2 = random_arm_reg(rng);
    while (reg3 == reg1 || reg3 == reg2) reg3 = random_arm_reg(rng);
    
    int32_t skip_offset = 2;
    uint32_t branch_imm = (skip_offset & 0x7FFFF) << 5;
    
    /* Pure random selection - no determinism, full entropy */
    switch(variant_seed % 10) {
        case 0: {
            *(uint32_t*)buf = 0xD2800000 | (1u << 31) | reg1;
            *(uint32_t*)(buf + 4) = 0xB4000000 | (1u << 31) | reg1 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD2800000 | (1u << 31) | reg2 | (0xFF << 5);
            *(uint32_t*)(buf + 12) = 0x91000000 | (1u << 31) | reg2 | (reg2 << 5) | (1 << 10);
            *len = 16;
            break;
        }
        case 1: {
            *(uint32_t*)buf = 0xEB000000 | (1u << 31) | 31 | (reg1 << 5) | (reg1 << 16);
            *(uint32_t*)(buf + 4) = 0x54000000 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD503201F;
            *(uint32_t*)(buf + 12) = 0xD503201F;
            *len = 16;
            break;
        }
        case 2: {
            *(uint32_t*)buf = 0xCA000000 | (1u << 31) | reg1 | (reg2 << 5) | (reg2 << 16);
            *(uint32_t*)(buf + 4) = 0x54000000 | branch_imm;
            *(uint32_t*)(buf + 8) = 0x91000000 | (1u << 31) | reg1 | (reg1 << 5) | (0xFF << 10);
            *len = 12;
            break;
        }
        case 3: {
            *(uint32_t*)buf = 0x72000000 | (1u << 31) | 31 | (reg1 << 5);
            *(uint32_t*)(buf + 4) = 0x54000001 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD503201F;
            *len = 12;
            break;
        }
        case 4: {
            *(uint32_t*)buf = 0xCB000000 | (1u << 31) | reg1 | (reg2 << 5) | (reg2 << 16);
            *(uint32_t*)(buf + 4) = 0xB4000000 | (1u << 31) | reg1 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD2800000 | (1u << 31) | reg3 | (0xAA << 5);
            *len = 12;
            break;
        }
        case 5: {
            *(uint32_t*)buf = 0xCA000000 | (1u << 31) | reg1 | (reg2 << 5) | (reg2 << 16);
            *(uint32_t*)(buf + 4) = 0xB5000000 | (1u << 31) | reg1 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD503201F;
            *len = 12;
            break;
        }
        case 6: {
            *(uint32_t*)buf = 0x72000000 | (1u << 31) | 31 | (reg1 << 5);
            *(uint32_t*)(buf + 4) = 0x54000001 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD503201F;
            *len = 12;
            break;
        }
        case 7: {
            *(uint32_t*)buf = 0xEB000000 | (1u << 31) | 31 | (reg1 << 5) | (reg1 << 16);
            *(uint32_t*)(buf + 4) = 0x54000000 | branch_imm;
            *(uint32_t*)(buf + 8) = 0x91000000 | (1u << 31) | reg2 | (reg2 << 5) | (1 << 10);
            *len = 12;
            break;
        }
        case 8: {
            *(uint32_t*)buf = 0x92400000 | (1u << 31) | reg1 | (reg2 << 5);
            *(uint32_t*)(buf + 4) = 0xB4000000 | (1u << 31) | reg1 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD2800000 | (1u << 31) | reg3 | (0x55 << 5);
            *len = 12;
            break;
        }
        case 9: {
            *(uint32_t*)buf = 0xAA1F03E0 | (1u << 31) | reg1 | (31 << 5);
            *(uint32_t*)(buf + 4) = 0xB5000000 | (1u << 31) | reg1 | branch_imm;
            *(uint32_t*)(buf + 8) = 0xD503201F;
            *len = 12;
            break;
        }
    }
}

/* Unified opaque predicate generator */
#if defined(ARCH_X86)
    #define forge_ghost forge_ghost_x86
#elif defined(ARCH_ARM)
    #define forge_ghost forge_ghost_arm
#endif

#endif /* FORGE_H */