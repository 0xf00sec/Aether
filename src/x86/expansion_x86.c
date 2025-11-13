#include <aether.h>

/* mov reg, reg > push src; pop dst */
static expansion_t mov_reg(uint8_t dst, uint8_t src, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (dst == 4 || src == 4) {  /* Don't use RSP */
        exp.valid = false;
        return exp;
    }
    
    exp.code[0] = 0x50 | src;  /* push src */
    exp.code[1] = 0x58 | dst;  /* pop dst */
    exp.len = 2;
    exp.valid = true;
    return exp;
}

/* mov reg, reg > xchg twice (double swap = mov) */
static expansion_t reg_xchg(uint8_t dst, uint8_t src, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (dst == src) {
        exp.valid = false;
        return exp;
    }
    
    /* xchg dst, src; xchg dst, src (double swap = mov) */
    exp.code[0] = 0x48; exp.code[1] = 0x87;
    exp.code[2] = 0xC0 | (dst << 3) | src;
    exp.code[3] = 0x48; exp.code[4] = 0x87;
    exp.code[5] = 0xC0 | (dst << 3) | src;
    exp.len = 6;
    exp.valid = true;
    return exp;
}

/**
 * For small immediates (<=20), splits into multiple tiny adds to maximize size.
 * Otherwise does standard xor+add. Always get larger code than original.
 */
static expansion_t xor_add(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Skip 64-bit values that don't fit in 32-bit signed */
    if (imm > 0x7FFFFFFF && imm < 0xFFFFFFFF80000000ULL) {
        exp.valid = false;
        return exp;
    }
    
    /* For small immediates, use multiple adds for size increase */
    if (imm <= 20 && imm > 0) {
        /* xor reg, reg */
        exp.code[0] = 0x48; exp.code[1] = 0x31;
        exp.code[2] = 0xC0 | (reg << 3) | reg;
        exp.len = 3;
        
        /* Multiple small adds */
        uint64_t remaining = imm;
        while (remaining > 0 && exp.len < 100) {
            uint8_t chunk = (remaining > 5) ? 5 : (uint8_t)remaining;
            exp.code[exp.len++] = 0x48;
            exp.code[exp.len++] = 0x83;
            exp.code[exp.len++] = 0xC0 | reg;
            exp.code[exp.len++] = chunk;
            remaining -= chunk;
        }
    } else if (imm <= 0x7FFFFFFF) {
        /* Standard xor + add for 32-bit values */
        exp.code[0] = 0x48; exp.code[1] = 0x31;
        exp.code[2] = 0xC0 | (reg << 3) | reg;  /* xor reg, reg */
        exp.code[3] = 0x48; exp.code[4] = 0x81;
        exp.code[5] = 0xC0 | reg;  /* add reg, imm32 */
        *(uint32_t*)(exp.code + 6) = (uint32_t)imm;
        exp.len = 10;
    } else {
        /* For negative 32-bit values (sign-extended) */
        exp.code[0] = 0x48; exp.code[1] = 0x31;
        exp.code[2] = 0xC0 | (reg << 3) | reg;  /* xor reg, reg */
        exp.code[3] = 0x48; exp.code[4] = 0x81;
        exp.code[5] = 0xC0 | reg;  /* add reg, imm32 */
        *(int32_t*)(exp.code + 6) = (int32_t)imm;
        exp.len = 10;
    }
    
    exp.valid = true;
    return exp;
}

/* mov reg, imm > push imm; pop reg */
static expansion_t push_pop(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (reg == 4) {  /* Don't use RSP */
        exp.valid = false;
        return exp;
    }
    
    /* Only works for 32-bit sign-extended immediates */
    if (imm > 0x7FFFFFFF && imm < 0xFFFFFFFF80000000ULL) {
        exp.valid = false;
        return exp;
    }
    
    exp.code[0] = 0x68;  /* push imm32 */
    *(int32_t*)(exp.code + 1) = (int32_t)imm;
    exp.code[5] = 0x58 | reg;  /* pop reg */
    exp.len = 6;
    exp.valid = true;
    return exp;
}

/* add reg, 1 > inc reg */
static expansion_t add1_to_inc(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    exp.code[0] = 0x48; exp.code[1] = 0xFF;
    exp.code[2] = 0xC0 | reg;  /* inc reg */
    exp.len = 3;
    exp.valid = true;
    return exp;
}

static expansion_t to_inc_chain(uint8_t reg, uint8_t count, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (count == 0 || count > 20) {  /* Reasonable limit */
        exp.valid = false;
        return exp;
    }
        
    for (uint8_t i = 0; i < count; i++) {
        exp.code[exp.len++] = 0x48;
        exp.code[exp.len++] = 0xFF;
        exp.code[exp.len++] = 0xC0 | reg;  /* inc reg */
    }
    exp.valid = true;
    return exp;
}

/* add reg, imm > lea reg, [reg+imm] */
static expansion_t to_lea(uint8_t reg, int32_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (imm >= -128 && imm <= 127) {  /* disp8 */
        exp.code[0] = 0x48; exp.code[1] = 0x8D;
        exp.code[2] = 0x40 | (reg << 3) | reg;  /* lea reg, [reg+disp8] */
        exp.code[3] = (uint8_t)imm;
        exp.len = 4;
    } else {  /* disp32 */
        exp.code[0] = 0x48; exp.code[1] = 0x8D;
        exp.code[2] = 0x80 | (reg << 3) | reg;  /* lea reg, [reg+disp32] */
        *(int32_t*)(exp.code + 3) = imm;
        exp.len = 7;
    }
    exp.valid = true;
    return exp;
}

/* add reg, imm > sub reg, -imm */
static expansion_t sub_neg(uint8_t reg, int32_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (imm == INT32_MIN) {  /* Can't negate */
        exp.valid = false;
        return exp;
    }
    
    exp.code[0] = 0x48; exp.code[1] = 0x81;
    exp.code[2] = 0xE8 | reg;  /* sub reg, imm32 */
    *(int32_t*)(exp.code + 3) = -imm;
    exp.len = 7;
    exp.valid = true;
    return exp;
}

/* sub reg, reg > xor reg, reg (when src == dst) */
static expansion_t to_xor(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    exp.code[0] = 0x48; exp.code[1] = 0x31;
    exp.code[2] = 0xC0 | (reg << 3) | reg;  /* xor reg, reg */
    exp.len = 3;
    exp.valid = true;
    return exp;
}

/**
 * Six different ways to zero sub/mov/and/imul/push-pop/lea.
 * All semantically equivalent, just different encodings.
 */
static expansion_t zero_reg(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    switch (chacha20_random(rng) % 6) {
        case 0:  /* sub reg, reg */
            exp.code[0] = 0x48; exp.code[1] = 0x29;
            exp.code[2] = 0xC0 | (reg << 3) | reg;
            exp.len = 3;
            break;
            
        case 1:  /* mov reg, 0 */
            exp.code[0] = 0x48; exp.code[1] = 0xC7;
            exp.code[2] = 0xC0 | reg;
            *(uint32_t*)(exp.code + 3) = 0;
            exp.len = 7;
            break;
            
        case 2:  /* and reg, 0 */
            exp.code[0] = 0x48; exp.code[1] = 0x83;
            exp.code[2] = 0xE0 | reg;
            exp.code[3] = 0x00;
            exp.len = 4;
            break;
            
        case 3:  /* imul reg, 0 */
            exp.code[0] = 0x48; exp.code[1] = 0x6B;
            exp.code[2] = 0xC0 | (reg << 3) | reg;
            exp.code[3] = 0x00;
            exp.len = 4;
            break;
            
        case 4:  /* push 0; pop reg */
            if (reg != 4) {
                exp.code[0] = 0x6A; exp.code[1] = 0x00;  /* push 0 */
                exp.code[2] = 0x58 | reg;  /* pop reg */
                exp.len = 3;
            } else {
                exp.valid = false;
                return exp;
            }
            break;
            
        case 5:  /* lea reg, [0] */
            exp.code[0] = 0x48; exp.code[1] = 0x8D;
            exp.code[2] = 0x04 | (reg << 3);  /* lea reg, [...] */
            exp.code[3] = 0x25;  /* SIB: [disp32] */
            *(uint32_t*)(exp.code + 4) = 0;
            exp.len = 8;
            break;
    }
    
    exp.valid = true;
    return exp;
}

/* test reg, reg > or reg, 0; cmp reg, 0 */
static expansion_t or_cmp(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    exp.code[0] = 0x48; exp.code[1] = 0x83;
    exp.code[2] = 0xC8 | reg;  /* or reg, 0 */
    exp.code[3] = 0x00;
    exp.code[4] = 0x48; exp.code[5] = 0x83;
    exp.code[6] = 0xF8 | reg;  /* cmp reg, 0 */
    exp.code[7] = 0x00;
    exp.len = 8;
    exp.valid = true;
    return exp;
}

/* cmp reg, reg > sub reg, reg (if we can clobber reg) */
static expansion_t cmp_to_sub(uint8_t reg1, uint8_t reg2, bool can_clobber, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (!can_clobber || reg1 != reg2) {
        exp.valid = false;
        return exp;
    }
    
    /* cmp reg, reg > sub reg, reg (when reg1 == reg2, result is always 0) */
    exp.code[0] = 0x48; exp.code[1] = 0x29;
    exp.code[2] = 0xC0 | (reg1 << 3) | reg2;
    exp.len = 3;
    exp.valid = true;
    return exp;
}

/* push reg > sub rsp, 8; mov [rsp], reg */
static expansion_t sub_mov(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (reg == 4) {  /* Special handling for RSP */
        exp.valid = false;
        return exp;
    }
    
    exp.code[0] = 0x48; exp.code[1] = 0x83;
    exp.code[2] = 0xEC; exp.code[3] = 0x08;  /* sub rsp, 8 */
    exp.code[4] = 0x48; exp.code[5] = 0x89;
    exp.code[6] = 0x04 | (reg << 3);  /* mov [rsp], reg */
    exp.code[7] = 0x24;  /* SIB byte */
    exp.len = 8;
    exp.valid = true;
    return exp;
}

/* pop reg > mov reg, [rsp]; add rsp, 8 */
static expansion_t mov_add(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (reg == 4) {  /* Special handling for RSP */
        exp.valid = false;
        return exp;
    }
    
    exp.code[0] = 0x48; exp.code[1] = 0x8B;
    exp.code[2] = 0x04 | (reg << 3);  /* mov reg, [rsp] */
    exp.code[3] = 0x24;  /* SIB byte */
    exp.code[4] = 0x48; exp.code[5] = 0x83;
    exp.code[6] = 0xC4; exp.code[7] = 0x08;  /* add rsp, 8 */
    exp.len = 8;
    exp.valid = true;
    return exp;
}

/* xor reg, reg > and reg, 0 (both zero) */
static expansion_t xor_self(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    exp.code[0] = 0x48; exp.code[1] = 0x83;
    exp.code[2] = 0xE0 | reg;  /* and reg, 0 */
    exp.code[3] = 0x00;
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* not reg > xor reg, -1 */
static expansion_t not_to_xor(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    exp.code[0] = 0x48; exp.code[1] = 0x81;
    exp.code[2] = 0xF0 | reg;  /* xor reg, imm32 */
    *(uint32_t*)(exp.code + 3) = 0xFFFFFFFF;
    exp.len = 7;
    exp.valid = true;
    return exp;
}

/* neg reg > not reg; inc reg */
static expansion_t not_inc(uint8_t reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    exp.code[0] = 0x48; exp.code[1] = 0xF7;
    exp.code[2] = 0xD0 | reg;  /* not reg */
    exp.code[3] = 0x48; exp.code[4] = 0xFF;
    exp.code[5] = 0xC0 | reg;  /* inc reg */
    exp.len = 6;
    exp.valid = true;
    return exp;
}

/* mov reg, [mem] > lea temp, [mem]; mov reg, [temp] */
static expansion_t lea_mov(uint8_t reg, uint8_t base, int32_t disp, 
                                              uint8_t temp_reg, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (reg == 4 || base == 4 || temp_reg == 4) {
        exp.valid = false;
        return exp;
    }
    
    /* lea temp, [base+disp] */
    exp.code[0] = 0x48; exp.code[1] = 0x8D;
    if (disp >= -128 && disp <= 127) {
        exp.code[2] = 0x40 | (temp_reg << 3) | base;
        exp.code[3] = (uint8_t)disp;
        exp.len = 4;
    } else {
        exp.code[2] = 0x80 | (temp_reg << 3) | base;
        *(int32_t*)(exp.code + 3) = disp;
        exp.len = 7;
    }
    
    /* mov reg, [temp] */
    exp.code[exp.len++] = 0x48;
    exp.code[exp.len++] = 0x8B;
    exp.code[exp.len++] = 0x00 | (reg << 3) | temp_reg;
    
    exp.valid = true;
    return exp;
}

/* add rax, rbx > lea rax, [rax+rbx] */
static expansion_t lea_indexed(uint8_t dst, uint8_t src, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    if (dst == 4 || src == 4) {  /* RSP can't be index */
        exp.valid = false;
        return exp;
    }
    
    /* lea dst, [dst+src] */
    exp.code[0] = 0x48; exp.code[1] = 0x8D;
    exp.code[2] = 0x04 | (dst << 3);  /* ModRM with SIB */
    exp.code[3] = (src << 3) | dst;   /* SIB: scale=0, index=src, base=dst */
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* mov reg, imm > mov reg, part1; shl reg, N; add reg, part2 */
static expansion_t shift_add(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Only handle 32-bit values */
    if (imm == 0 || imm > 0x7FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    /* Split: imm = (part1 << shift) + part2 */
    uint8_t shift = 1 + (chacha20_random(rng) % 3);  /* 1-3 bits */
    uint32_t imm32 = (uint32_t)imm;
    uint32_t part1 = imm32 >> shift;
    uint32_t part2 = imm32 - (part1 << shift);
    
    /* mov reg, part1 */
    exp.code[0] = 0x48; exp.code[1] = 0xC7;
    exp.code[2] = 0xC0 | reg;
    *(uint32_t*)(exp.code + 3) = part1;
    
    /* shl reg, shift */
    exp.code[7] = 0x48; exp.code[8] = 0xC1;
    exp.code[9] = 0xE0 | reg;
    exp.code[10] = shift;
    
    /* add reg, part2 */
    exp.code[11] = 0x48; exp.code[12] = 0x81;
    exp.code[13] = 0xC0 | reg;
    *(uint32_t*)(exp.code + 14) = part2;
    
    exp.len = 18;
    exp.valid = true;
    return exp;
}

/* mov reg, imm > mov reg, ~imm; not reg */
static expansion_t imm_to_not(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Only handle 32-bit values */
    if (imm > 0x7FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    /* mov reg, ~imm */
    exp.code[0] = 0x48; exp.code[1] = 0xC7;
    exp.code[2] = 0xC0 | reg;
    *(int32_t*)(exp.code + 3) = ~(int32_t)imm;
    
    /* not reg */
    exp.code[7] = 0x48; exp.code[8] = 0xF7;
    exp.code[9] = 0xD0 | reg;
    
    exp.len = 10;
    exp.valid = true;
    return exp;
}

/* mov reg, imm > mov reg, imm^key; xor reg, key */
static expansion_t xor_key(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Only handle 32-bit values */
    if (imm > 0x7FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    uint32_t key = chacha20_random(rng);
    uint32_t imm32 = (uint32_t)imm;
    
    /* mov reg, imm^key */
    exp.code[0] = 0x48; exp.code[1] = 0xC7;
    exp.code[2] = 0xC0 | reg;
    *(uint32_t*)(exp.code + 3) = imm32 ^ key;
    
    /* xor reg, key */
    exp.code[7] = 0x48; exp.code[8] = 0x81;
    exp.code[9] = 0xF0 | reg;
    *(uint32_t*)(exp.code + 10) = key;
    
    exp.len = 14;
    exp.valid = true;
    return exp;
}

/* mov reg, imm > mov reg, -imm; neg reg */
static expansion_t imm_to_neg(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Only handle positive 32-bit values that can be negated */
    if (imm == 0 || imm > 0x7FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    int32_t imm32 = (int32_t)imm;
    if (imm32 == INT32_MIN) {
        exp.valid = false;
        return exp;
    }
    
    /* mov reg, -imm */
    exp.code[0] = 0x48; exp.code[1] = 0xC7;
    exp.code[2] = 0xC0 | reg;
    *(int32_t*)(exp.code + 3) = -imm32;
    
    /* neg reg */
    exp.code[7] = 0x48; exp.code[8] = 0xF7;
    exp.code[9] = 0xD8 | reg;
    
    exp.len = 10;
    exp.valid = true;
    return exp;
}

/* mov reg, imm > mov reg, imm*2; shr reg, 1 */
static expansion_t mul_shr(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Only handle values that won't overflow when doubled */
    if (imm == 0 || imm > 0x3FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    uint32_t imm32 = (uint32_t)imm;
    
    /* mov reg, imm*2 */
    exp.code[0] = 0x48; exp.code[1] = 0xC7;
    exp.code[2] = 0xC0 | reg;
    *(uint32_t*)(exp.code + 3) = imm32 * 2;
    
    /* shr reg, 1 */
    exp.code[7] = 0x48; exp.code[8] = 0xD1;
    exp.code[9] = 0xE8 | reg;
    
    exp.len = 10;
    exp.valid = true;
    return exp;
}

/* mov reg, imm > complex multi-step sequence */
static expansion_t mov_imm(uint8_t reg, uint64_t imm, chacha_state_t *rng) {
    expansion_t exp = {0};
    
    /* Only handle 32-bit values */
    if (imm == 0 || imm > 0x7FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    uint32_t imm32 = (uint32_t)imm;
    
    /* Strategy: imm = (a + b) * c + d */
    uint32_t c = 2 + (chacha20_random(rng) % 3);  /* 2-4 */
    uint32_t d = imm32 % c;
    uint32_t temp = (imm32 - d) / c;
    uint32_t a = temp / 2;
    uint32_t b = temp - a;
    
    /* xor reg, reg */
    exp.code[0] = 0x48; exp.code[1] = 0x31;
    exp.code[2] = 0xC0 | (reg << 3) | reg;
    
    /* add reg, a */
    exp.code[3] = 0x48; exp.code[4] = 0x81;
    exp.code[5] = 0xC0 | reg;
    *(uint32_t*)(exp.code + 6) = a;
    
    /* add reg, b */
    exp.code[10] = 0x48; exp.code[11] = 0x81;
    exp.code[12] = 0xC0 | reg;
    *(uint32_t*)(exp.code + 13) = b;
    
    /* imul reg, c */
    exp.code[17] = 0x48; exp.code[18] = 0x6B;
    exp.code[19] = 0xC0 | (reg << 3) | reg;
    exp.code[20] = (uint8_t)c;
    
    /* add reg, d */
    if (d > 0) {
        exp.code[21] = 0x48; exp.code[22] = 0x81;
        exp.code[23] = 0xC0 | reg;
        *(uint32_t*)(exp.code + 24) = d;
        exp.len = 28;
    } else {
        exp.len = 21;
    }
    
    exp.valid = true;
    return exp;
}

/* Main dispatcher for x86 expansions */
expansion_t expand_instruction(const x86_inst_t *inst, liveness_state_t *liveness, 
                                size_t offset, chacha_state_t *rng,
                                uint8_t *code, size_t code_size) {
    expansion_t exp = {0};
    
    if (!inst || !inst->valid || !rng) {
        exp.valid = false;
        return exp;
    }
    
    /* Don't expand SIMD/MMX/SSE/AVX */
    if (inst->is_simd || inst->vex || inst->evex) {
        exp.valid = false;
        return exp;
    }
    
    uint8_t op = inst->opcode[0];
    
    /* MOV reg, reg */
    if (op == 0x89 && inst->has_modrm) {
        uint8_t mod = (inst->modrm >> 6) & 3;
        if (mod == 3) {  /* reg-to-reg */
            uint8_t dst = modrm_rm(inst->modrm);
            uint8_t src = modrm_reg(inst->modrm);
            
            switch (chacha20_random(rng) % 2) {
                case 0: return mov_reg(dst, src, rng);
                case 1: return reg_xchg(dst, src, rng);
            }
        }
    }
    
    /* MOV reg, imm */
    if ((op & 0xF8) == 0xB8) {
        uint8_t reg = op & 0x7;
        uint64_t imm = inst->imm;
        
        /* Usually must be preserved exactly */
        if (imm > 0x7FFFFFFF && imm < 0xFFFFFFFF80000000ULL) {
            exp.valid = false;
            return exp;
        }
        
        if (imm == 0) {
            return zero_reg(reg, rng);
        } else {
            /* Try expansions in order, return first valid one */
            expansion_t candidates[8];
            candidates[0] = xor_add(reg, imm, rng);
            candidates[1] = push_pop(reg, imm, rng);
            candidates[2] = shift_add(reg, imm, rng);
            candidates[3] = imm_to_not(reg, imm, rng);
            candidates[4] = xor_key(reg, imm, rng);
            candidates[5] = imm_to_neg(reg, imm, rng);
            candidates[6] = mul_shr(reg, imm, rng);
            candidates[7] = mov_imm(reg, imm, rng);
            
            /* Prefer larger expansions */
            int best_idx = -1;
            size_t best_len = inst->len;
            for (int i = 0; i < 8; i++) {
                if (candidates[i].valid && candidates[i].len > best_len) {
                    best_idx = i;
                    best_len = candidates[i].len;
                }
            }
            
            /* If we found a size-increasing expansion, use it */
            if (best_idx >= 0) {
                return candidates[best_idx];
            }
            
            /* Otherwise, pick random valid expansion */
            int valid_count = 0;
            int valid_indices[8];
            for (int i = 0; i < 8; i++) {
                if (candidates[i].valid) {
                    valid_indices[valid_count++] = i;
                }
            }
            
            if (valid_count > 0) {
                return candidates[valid_indices[chacha20_random(rng) % valid_count]];
            }
        }
    }
    
    /* ADD reg, imm (all small) */
    if (op == 0x83 && inst->has_modrm) {
        uint8_t modrm_reg_field = modrm_reg(inst->modrm);
        if (modrm_reg_field == 0) {  /* ADD operation */
            uint8_t reg = modrm_rm(inst->modrm);
            uint8_t mod = (inst->modrm >> 6) & 3;
            
            if (mod == 3 && inst->imm > 0 && inst->imm <= 15) {
                bool next_uses_carry = false;
                
                if (code && code_size > 0) {
                    size_t scan_offset = offset + inst->len;
                    int lookahead = 5;
                    
                    while (lookahead > 0 && scan_offset < code_size && !next_uses_carry) {
                        x86_inst_t scan_inst;
                        if (!decode_x86_withme(code + scan_offset, code_size - scan_offset, 
                                              0, &scan_inst, NULL) || !scan_inst.valid) {
                            break;
                        }
                        
                        uint8_t op = scan_inst.opcode[0];
                        
                        /* ADC */
                        if ((op >= 0x10 && op <= 0x15) || 
                            (op >= 0x80 && op <= 0x83 && scan_inst.has_modrm && 
                             modrm_reg(scan_inst.modrm) == 2)) {
                            next_uses_carry = true;
                            break;
                        }
                        
                        /* SBB */
                        if ((op >= 0x18 && op <= 0x1D) || 
                            (op >= 0x80 && op <= 0x83 && scan_inst.has_modrm && 
                             modrm_reg(scan_inst.modrm) == 3)) {
                            next_uses_carry = true;
                            break;
                        }
                        
                        /* RCL/RCR */
                        if ((op >= 0xC0 && op <= 0xC1) || (op >= 0xD0 && op <= 0xD3)) {
                            if (scan_inst.has_modrm) {
                                uint8_t reg_field = modrm_reg(scan_inst.modrm);
                                if (reg_field == 2 || reg_field == 3) {
                                    next_uses_carry = true;
                                    break;
                                }
                            }
                        }
                        
                        if (op == 0x72 || op == 0x73) {
                            next_uses_carry = true;
                            break;
                        }
                        if (scan_inst.opcode_len >= 2 && op == 0x0F) {
                            uint8_t op2 = scan_inst.opcode[1];
                            if (op2 == 0x82 || op2 == 0x83) {
                                next_uses_carry = true;
                                break;
                            }
                            /* SETC/SETNC */
                            if (op2 == 0x92 || op2 == 0x93) {
                                next_uses_carry = true;
                                break;
                            }
                            /* CMOVC/CMOVNC */
                            if (op2 == 0x42 || op2 == 0x43) {
                                next_uses_carry = true;
                                break;
                            }
                        }
                        
                        if (op == 0x9F || op == 0x9C) {
                            next_uses_carry = true;
                            break;
                        }
                        
                        bool clobbers_cf = false;

                        if ((op >= 0x00 && op <= 0x05) ||  /* ADD */
                            (op >= 0x28 && op <= 0x2D) ||  /* SUB */
                            (op >= 0x38 && op <= 0x3D) ||  /* CMP */
                            (op >= 0x80 && op <= 0x83 && scan_inst.has_modrm &&
                             (modrm_reg(scan_inst.modrm) == 0 ||  /* ADD */
                              modrm_reg(scan_inst.modrm) == 5 ||  /* SUB */
                              modrm_reg(scan_inst.modrm) == 7))) { /* CMP */
                            clobbers_cf = true;
                        }
                        
                        if ((op >= 0x08 && op <= 0x0D) ||  /* OR */
                            (op >= 0x20 && op <= 0x25) ||  /* AND */
                            (op >= 0x30 && op <= 0x35) ||  /* XOR */
                            (op >= 0x84 && op <= 0x85) ||  /* TEST */
                            (op >= 0xA8 && op <= 0xA9)) {  /* TEST */
                            clobbers_cf = true;
                        }
                        
                        if ((op >= 0xC0 && op <= 0xC1) || (op >= 0xD0 && op <= 0xD3) ||
                            op == 0x9E || op == 0x9D) {
                            clobbers_cf = true;
                            break;
                        }

                        scan_offset += scan_inst.len;
                        lookahead--;
                    }
                }
                
                expansion_t lea_exp = to_lea(reg, (int32_t)inst->imm, rng);
                if (!next_uses_carry) {
                    expansion_t inc_chain = to_inc_chain(reg, (uint8_t)inst->imm, rng);
                    if (inc_chain.valid && inc_chain.len > inst->len) {
                        return inc_chain;
                    }
                } else {
                    DBG("[Expand] Skipping INC chain \n");
                }
                
                if (lea_exp.valid) {
                    return lea_exp;
                }
            }
        }
    }
    
    /* XOR reg, reg (zeroing) */
    if (op == 0x31 && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        if (reg == rm) {
            return zero_reg(reg, rng);
        }
    }
    
    /* SUB reg, reg (zeroing) */
    if (op == 0x29 && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        if (reg == rm) {
            return to_xor(reg, rng);
        }
    }
    
    /* TEST reg, reg */
    if (op == 0x85 && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        if (reg == rm) {
            return or_cmp(reg, rng);
        }
    }
    
    /* NOT reg */
    if (op == 0xF7 && inst->has_modrm) {
        uint8_t modrm_reg_field = modrm_reg(inst->modrm);
        if (modrm_reg_field == 2) {  /* NOT operation */
            uint8_t reg = modrm_rm(inst->modrm);
            return not_to_xor(reg, rng);
        }
    }
    
    /* NEG reg */
    if (op == 0xF7 && inst->has_modrm) {
        uint8_t modrm_reg_field = modrm_reg(inst->modrm);
        if (modrm_reg_field == 3) {  /* NEG operation */
            uint8_t reg = modrm_rm(inst->modrm);
            return not_inc(reg, rng);
        }
    }
    
    /* ADD reg, reg (doubling) */
    if (op == 0x01 && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        uint8_t mod = (inst->modrm >> 6) & 3;
        
        if (mod == 3 && reg == rm) {  /* add reg, reg (double) */
            /* shl reg, 1 */
            exp.code[0] = 0x48; exp.code[1] = 0xD1;
            exp.code[2] = 0xE0 | reg;
            exp.len = 3;
            exp.valid = true;
            return exp;
        }
        
        /* add dst, src > lea dst, [dst+src] */
        if (mod == 3) {
            return lea_indexed(rm, reg, rng);
        }
    }
    
    /* SUB reg, imm > add reg, -imm */
    if (op == 0x83 && inst->has_modrm) {
        uint8_t modrm_reg_field = modrm_reg(inst->modrm);
        if (modrm_reg_field == 5) {  /* SUB operation */
            uint8_t reg = modrm_rm(inst->modrm);
            int8_t imm = (int8_t)inst->imm;
            
            if (imm != -128) {  /* Can negate */
                exp.code[0] = 0x48; exp.code[1] = 0x83;
                exp.code[2] = 0xC0 | reg;  /* ADD */
                exp.code[3] = (uint8_t)(-imm);
                exp.len = 4;
                exp.valid = true;
                return exp;
            }
        }
    }
    
    /* INC reg > add reg, 1 */
    if (op == 0xFF && inst->has_modrm) {
        uint8_t modrm_reg_field = modrm_reg(inst->modrm);
        if (modrm_reg_field == 0) {  /* INC operation */
            uint8_t reg = modrm_rm(inst->modrm);
            
            switch (chacha20_random(rng) % 2) {
                case 0:  /* add reg, 1 */
                    exp.code[0] = 0x48; exp.code[1] = 0x83;
                    exp.code[2] = 0xC0 | reg;
                    exp.code[3] = 0x01;
                    exp.len = 4;
                    break;
                case 1:  /* lea reg, [reg+1] */
                    exp.code[0] = 0x48; exp.code[1] = 0x8D;
                    exp.code[2] = 0x40 | (reg << 3) | reg;
                    exp.code[3] = 0x01;
                    exp.len = 4;
                    break;
            }
            exp.valid = true;
            return exp;
        }
    }
    
    /* DEC reg > sub reg, 1 */
    if (op == 0xFF && inst->has_modrm) {
        uint8_t modrm_reg_field = modrm_reg(inst->modrm);
        if (modrm_reg_field == 1) {  /* DEC operation */
            uint8_t reg = modrm_rm(inst->modrm);
            
            switch (chacha20_random(rng) % 2) {
                case 0:  /* sub reg, 1 */
                    exp.code[0] = 0x48; exp.code[1] = 0x83;
                    exp.code[2] = 0xE8 | reg;
                    exp.code[3] = 0x01;
                    exp.len = 4;
                    break;
                case 1:  /* lea reg, [reg-1] */
                    exp.code[0] = 0x48; exp.code[1] = 0x8D;
                    exp.code[2] = 0x40 | (reg << 3) | reg;
                    exp.code[3] = 0xFF;  /* -1 as disp8 */
                    exp.len = 4;
                    break;
            }
            exp.valid = true;
            return exp;
        }
    }
    
    exp.valid = false;
    return exp;
}

bool apply_expansion(uint8_t *code, size_t *size, size_t offset, 
                     const x86_inst_t *inst, liveness_state_t *liveness,
                     chacha_state_t *rng, reloc_table_t *reloc_table,
                     uint64_t base_addr) {
    if (!code || !size || !inst || !rng) return false;
    
    expansion_t exp = expand_instruction(inst, liveness, offset, rng, code, *size);
    if (!exp.valid || exp.len == 0) return false;
    
    /* Check if expansion fits */
    size_t size_diff = exp.len > inst->len ? exp.len - inst->len : 0;
    if (offset + exp.len > *size || *size + size_diff > *size * 2) {
        return false;
    }
    
    if (exp.len > inst->len) {
        size_t sf_zn = *size * 9 / 10; 
        
        if (reloc_table && base_addr != 0) {
        } else if (offset < sf_zn) { 
            return false;
        }
        
        size_t scan_window = 128;
        size_t scan_end = (offset + scan_window < *size) ? offset + scan_window : *size;
        
        for (size_t scan_off = offset; scan_off < scan_end; ) {
            x86_inst_t scan_inst;
            if (!decode_x86_withme(code + scan_off, *size - scan_off, 0, &scan_inst, NULL) ||
                !scan_inst.valid || scan_inst.len == 0) {
                scan_off++;
                continue;
            }
            
            if (scan_inst.rip_relative) {
                /* Found RIP-relative instruction nearby? don't expand */
                return false;
            }
            
            if (scan_inst.has_modrm) {
                uint8_t mod = (scan_inst.modrm >> 6) & 3;
                uint8_t rm = scan_inst.modrm & 7;
                if (mod == 0 && rm == 5) {
                    /* This is RIP-relative [rip+disp32] */
                    return false;
                }
            }
            
            scan_off += scan_inst.len;
        }
    }
    
    if (exp.len > inst->len) {
        /* Check if THIS instruction is RIP-relative */
        if (inst->rip_relative || (inst->has_modrm && 
            ((inst->modrm >> 6) & 3) == 0 && (inst->modrm & 7) == 5)) {
            DBG("[Expand] Refusing to expand RIP-relative instruction at 0x%zx\n", offset);
            return false;
        }
        
        /* Check nearby instructions for RIP-relative addressing */
        size_t scan_window = 128;
        size_t scan_start = (offset > scan_window) ? offset - scan_window : 0;
        size_t scan_end = (offset + scan_window < *size) ? offset + scan_window : *size;
        
        for (size_t scan_off = scan_start; scan_off < scan_end; ) {
            if (scan_off == offset) {
                scan_off += inst->len;
                continue;
            }
            
            x86_inst_t scan_inst;
            if (!decode_x86_withme(code + scan_off, *size - scan_off, 0, &scan_inst, NULL) ||
                !scan_inst.valid || scan_inst.len == 0) {
                scan_off++;
                continue;
            }
            
            /* Check if this instruction is RIP-relative */
            if (scan_inst.rip_relative || (scan_inst.has_modrm && 
                ((scan_inst.modrm >> 6) & 3) == 0 && (scan_inst.modrm & 7) == 5)) {
                
                /* If we have a relocation table, we can fix it up */
                if (reloc_table && base_addr != 0) {
                    DBG("[Expand] RIP-relative at 0x%zx will be fixed by relocation table\n", scan_off);
                } else {
                    /* No relocation table - refuse to expand */
                    DBG("[Expand] Refusing expansion - RIP-relative at 0x%zx would break\n", scan_off);
                    return false;
                }
            }
            
            scan_off += scan_inst.len;
        }
        
        /* to expand get a room */
        memmove(code + offset + exp.len, 
                code + offset + inst->len,
                *size - offset - inst->len);
        *size += size_diff;
        
        /* Update relocation table if provided */
        if (reloc_table && base_addr != 0) {
            reloc_update(reloc_table, offset + inst->len, 
                        size_diff, code, *size, base_addr, ARCH_X86);
        }
    } else if (exp.len < inst->len) {
        /* Shrinking - fill with NOPs */
        size_t nop_count = inst->len - exp.len;
        memset(code + offset + exp.len, 0x90, nop_count);
    }
    
    /* Apply expansion */
    memcpy(code + offset, exp.code, exp.len);
    
    /* Validate */
    x86_inst_t verify;
    if (!decode_x86_withme(code + offset, *size - offset, 0, &verify, NULL) || 
        !verify.valid) {
        /* Rollback */
        memcpy(code + offset, inst->raw, inst->len);
        if (exp.len > inst->len) {
            memmove(code + offset + inst->len,
                    code + offset + exp.len,
                    *size - offset - exp.len);
            *size -= size_diff;
            
            /* Rollback relocation updates, this is tricky, so we just rebuild later */
        }
        return false;
    }
    
    return true;
}

size_t expand_code(uint8_t *code, size_t size, size_t max_size,
                            liveness_state_t *liveness, chacha_state_t *rng,
                            unsigned expansion_intensity, reloc_table_t *reloc_table,
                            uint64_t base_addr) {
    if (!code || size == 0 || !rng) return size;
    
    size_t current_size = size;
    size_t offset = 0;
    
    while (offset < current_size && current_size < max_size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, current_size - offset, 0, &inst, NULL) ||
            !inst.valid || inst.len == 0) {
            offset++;
            continue;
        }
        
        /* Randomly decide whether to expand this instruction */
        if ((chacha20_random(rng) % 100) < expansion_intensity) {
            if (apply_expansion(code, &current_size, offset, &inst, liveness, rng,
                              reloc_table, base_addr)) {
                /* Expansion applied, re-decode to get new length */
                x86_inst_t new_inst;
                if (decode_x86_withme(code + offset, current_size - offset, 0, &new_inst, NULL)) {
                    offset += new_inst.len;
                    continue;
                }
            }
        }
        
        offset += inst.len;
    }
    
    return current_size;
}

/* 3xpand, then expand the expanded code again */
size_t expand_chains(uint8_t *code, size_t size, size_t max_size,
                          liveness_state_t *liveness, chacha_state_t *rng,
                          unsigned chain_depth, unsigned expansion_intensity,
                          reloc_table_t *reloc_table, uint64_t base_addr) {
    if (!code || size == 0 || !rng || chain_depth == 0) return size;
    
    size_t current_size = size;
    
    /* Apply multiple rounds of expansion */
    for (unsigned round = 0; round < chain_depth && current_size < max_size; round++) {
        size_t round_start_size = current_size;
        size_t offset = 0;
        
        /* Scan through code and expand instructions */
        while (offset < current_size && current_size < max_size) {
            x86_inst_t inst;
            if (!decode_x86_withme(code + offset, current_size - offset, 0, &inst, NULL) ||
                !inst.valid || inst.len == 0) {
                offset++;
                continue;
            }
            
            /* Probability decreases with each round to avoid explosion */
            unsigned round_intensity = expansion_intensity / (round + 1);
            if (round_intensity < 10) round_intensity = 10;
            
            if ((chacha20_random(rng) % 100) < round_intensity) {
                size_t pre_expand_size = current_size;
                
                if (apply_expansion(code, &current_size, offset, &inst, liveness, rng,
                                  reloc_table, base_addr)) {
                    /* Expansion succeeded - re-decode to get new length */
                    x86_inst_t new_inst;
                    if (decode_x86_withme(code + offset, current_size - offset, 0, &new_inst, NULL)) {
                        offset += new_inst.len;
                        
                        /* Can't have this */
                        if (current_size > pre_expand_size + 100) {
                            current_size = pre_expand_size;
                            break;
                        }
                        continue;
                    }
                }
            }
            
            offset += inst.len;
        }
        
        /* If no expansion happened this round, stop */
        if (current_size == round_start_size) {
            break;
        }
    }
    
    return current_size;
}

/* Aggressively chain-expand MOV immediate instructions */
size_t mov_immediates(uint8_t *code, size_t size, size_t max_size,
                                   liveness_state_t *liveness, chacha_state_t *rng,
                                   unsigned chain_depth) {
    if (!code || size == 0 || !rng || chain_depth == 0) return size;
    
    size_t current_size = size;
    
    for (unsigned round = 0; round < chain_depth && current_size < max_size; round++) {
        size_t offset = 0;
        bool expanded_any = false;
        
        while (offset < current_size && current_size < max_size) {
            x86_inst_t inst;
            if (!decode_x86_withme(code + offset, current_size - offset, 0, &inst, NULL) ||
                !inst.valid || inst.len == 0) {
                offset++;
                continue;
            }
            
            /* Target MOV reg, imm instructions */
            if ((inst.opcode[0] & 0xF8) == 0xB8 && inst.imm != 0) {
                if (apply_expansion(code, &current_size, offset, &inst, liveness, rng, NULL, 0)) {
                    expanded_any = true;
                    
                    /* Re-decode to get new length */
                    x86_inst_t new_inst;
                    if (decode_x86_withme(code + offset, current_size - offset, 0, &new_inst, NULL)) {
                        offset += new_inst.len;
                        continue;
                    }
                }
            }
            
            offset += inst.len;
        }
        
        if (!expanded_any) break;
    }
    
    return current_size;
}

/* Chain expand arithmetic instructions (ADD, SUB, INC, DEC) */
size_t expand_arithmetic(uint8_t *code, size_t size, size_t max_size,
                               liveness_state_t *liveness, chacha_state_t *rng,
                               unsigned chain_depth) {
    if (!code || size == 0 || !rng || chain_depth == 0) return size;
    
    size_t current_size = size;
    
    for (unsigned round = 0; round < chain_depth && current_size < max_size; round++) {
        size_t offset = 0;
        bool expanded_any = false;
        
        while (offset < current_size && current_size < max_size) {
            x86_inst_t inst;
            if (!decode_x86_withme(code + offset, current_size - offset, 0, &inst, NULL) ||
                !inst.valid || inst.len == 0) {
                offset++;
                continue;
            }
            
            uint8_t op = inst.opcode[0];
            bool is_arithmetic = false;
            
            /* Check if it's an arithmetic instruction */
            if (op == 0x83 && inst.has_modrm) {  /* ADD/SUB with imm8 */
                uint8_t modrm_reg_field = modrm_reg(inst.modrm);
                if (modrm_reg_field == 0 || modrm_reg_field == 5) {  /* ADD or SUB */
                    is_arithmetic = true;
                }
            } else if (op == 0xFF && inst.has_modrm) {  /* INC/DEC */
                uint8_t modrm_reg_field = modrm_reg(inst.modrm);
                if (modrm_reg_field == 0 || modrm_reg_field == 1) {  /* INC or DEC */
                    is_arithmetic = true;
                }
            } else if (op == 0x01 || op == 0x29) {  /* ADD/SUB reg, reg */
                is_arithmetic = true;
            }
            
            if (is_arithmetic) {
                if (apply_expansion(code, &current_size, offset, &inst, liveness, rng, NULL, 0)) {
                    expanded_any = true;
                    
                    x86_inst_t new_inst;
                    if (decode_x86_withme(code + offset, current_size - offset, 0, &new_inst, NULL)) {
                        offset += new_inst.len;
                        continue;
                    }
                }
            }
            
            offset += inst.len;
        }
        
        if (!expanded_any) break;
    }
    
    return current_size;
}
