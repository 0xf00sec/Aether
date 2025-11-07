#include <aether.h>

#if defined(ARCH_ARM)

/* MOVZ for first non-zero 16-bit chunk, MOVK for the rest expands to 2-4 instructions. */
static arm64_expansion_t movz_movk(uint8_t rd, uint64_t imm, 
                                                      bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29) {  /* Don't expand special registers */
        exp.valid = false;
        return exp;
    }
    
    size_t offset = 0;
    bool first = true;
    
    /* how many 16-bit chunks are non-zero */
    for (int shift = 0; shift < (is_64bit ? 64 : 32); shift += 16) {
        uint16_t chunk = (imm >> shift) & 0xFFFF;
        
        if (chunk != 0 || (shift == 0 && imm == 0)) {
            uint32_t insn;
            
            if (first) {
                /* MOVZ Xd, #chunk, LSL #shift */
                insn = 0xD2800000;
                insn |= (is_64bit ? (1u << 31) : 0);
                insn |= rd;
                insn |= ((uint32_t)chunk << 5);
                insn |= ((shift / 16) << 21);
                first = false;
            } else {
                /* MOVK Xd, #chunk, LSL #shift */
                insn = 0xF2800000;
                insn |= (is_64bit ? (1u << 31) : 0);
                insn |= rd;
                insn |= ((uint32_t)chunk << 5);
                insn |= ((shift / 16) << 21);
            }
            
            *(uint32_t*)(exp.code + offset) = insn;
            offset += 4;
        }
    }
    
    exp.len = offset;
    exp.valid = (offset > 0);
    return exp;
}

/* Split immediate into base + delta: movz + add */
static arm64_expansion_t imm_to_ari(uint8_t rd, uint64_t imm,
                                                       bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || imm == 0) {
        exp.valid = false;
        return exp;
    }
    
    /* imm = base + delta */
    uint32_t base = (uint32_t)imm / 2;
    uint32_t delta = (uint32_t)imm - base;
    
    /* MOVZ Xd, #base */
    uint32_t insn1 = 0xD2800000;
    insn1 |= (is_64bit ? (1u << 31) : 0);
    insn1 |= rd;
    insn1 |= ((base & 0xFFFF) << 5);
    *(uint32_t*)(exp.code) = insn1;
    
    /* ADD Xd, Xd, #delta */
    uint32_t insn2 = 0x91000000;
    insn2 |= (is_64bit ? (1u << 31) : 0);
    insn2 |= rd;
    insn2 |= (rd << 5);
    insn2 |= ((delta & 0xFFF) << 10);
    *(uint32_t*)(exp.code + 4) = insn2;
    
    exp.len = 8;
    exp.valid = true;
    return exp;
}

static arm64_expansion_t imm_to_neg(uint8_t rd, uint64_t imm,
                                                bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || imm == 0 || imm > 0x7FFFFFFF) {
        exp.valid = false;
        return exp;
    }
    
    uint32_t neg_imm = (uint32_t)(-((int64_t)imm));
    
    /* MOVZ Xd, #(-imm) */
    uint32_t insn1 = 0xD2800000;
    insn1 |= (is_64bit ? (1u << 31) : 0);
    insn1 |= rd;
    insn1 |= ((neg_imm & 0xFFFF) << 5);
    *(uint32_t*)(exp.code) = insn1;
    
    /* NEG Xd, Xd (SUB Xd, XZR, Xd) */
    uint32_t insn2 = 0xCB000000;
    insn2 |= (is_64bit ? (1u << 31) : 0);
    insn2 |= rd;
    insn2 |= (31 << 5);  /* XZR */
    insn2 |= (rd << 16);
    *(uint32_t*)(exp.code + 4) = insn2;
    
    exp.len = 8;
    exp.valid = true;
    return exp;
}

static arm64_expansion_t imm_to_chain(uint8_t rd, uint8_t rn, uint32_t imm,
                                                  bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29 || imm == 0 || imm > 4095) {
        exp.valid = false;
        return exp;
    }
    
    size_t offset = 0;
    uint32_t remaining = imm;
    bool first = true;
    
    /* Split into chunks of 1-255 */
    while (remaining > 0 && offset < 60) {
        uint32_t chunk = (remaining > 255) ? 255 : remaining;
        
        /* ADD Xd, Xsrc, #chunk */
        uint32_t insn = 0x91000000;
        insn |= (is_64bit ? (1u << 31) : 0);
        insn |= rd;
        insn |= ((first ? rn : rd) << 5);
        insn |= (chunk << 10);
        
        *(uint32_t*)(exp.code + offset) = insn;
        offset += 4;
        remaining -= chunk;
        first = false;
    }
    
    exp.len = offset;
    exp.valid = (offset > 4);  /* Must be larger than original */
    return exp;
}

/* SUB Xd, Xn, #imm > ADD Xd, Xn, #(-imm) */
static arm64_expansion_t sub_neg(uint8_t rd, uint8_t rn, uint32_t imm,
                                                bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29 || imm == 0 || imm > 4095) {
        exp.valid = false;
        return exp;
    }
    
    /* Check if we can represent -imm as a 12-bit immediate */
    uint32_t neg_imm = (uint32_t)(-((int32_t)imm));
    if (neg_imm > 4095) {
        /* Can't fit in 12 bits, try loading it first */
        /* MOVZ Xtmp, #(-imm & 0xFFFF) */
        uint32_t insn1 = 0xD2800000;
        insn1 |= (is_64bit ? (1u << 31) : 0);
        insn1 |= 16;  /* Use X16 (IP0) as temp */
        insn1 |= ((neg_imm & 0xFFFF) << 5);
        *(uint32_t*)(exp.code) = insn1;
        
        /* ADD Xd, Xn, Xtmp */
        uint32_t insn2 = 0x8B000000;
        insn2 |= (is_64bit ? (1u << 31) : 0);
        insn2 |= rd;
        insn2 |= (rn << 5);
        insn2 |= (16 << 16);  /* X16 */
        *(uint32_t*)(exp.code + 4) = insn2;
        
        exp.len = 8;
        exp.valid = true;
        return exp;
    }
    
    /* Simple case */
    uint32_t insn = 0x91000000;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rn << 5);
    insn |= (neg_imm << 10);
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

static arm64_expansion_t sub_imm(uint8_t rd, uint8_t rn, uint32_t imm,
                                                  bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29 || imm == 0 || imm > 4095) {
        exp.valid = false;
        return exp;
    }
    
    size_t offset = 0;
    uint32_t remaining = imm;
    bool first = true;
    
    while (remaining > 0 && offset < 60) {
        uint32_t chunk = (remaining > 255) ? 255 : remaining;
        
        /* SUB Xd, Xsrc, #chunk */
        uint32_t insn = 0xD1000000;
        insn |= (is_64bit ? (1u << 31) : 0);
        insn |= rd;
        insn |= ((first ? rn : rd) << 5);
        insn |= (chunk << 10);
        
        *(uint32_t*)(exp.code + offset) = insn;
        offset += 4;
        remaining -= chunk;
        first = false;
    }
    
    exp.len = offset;
    exp.valid = (offset > 4);
    return exp;
}

/* Six ways to zero a register (eor/sub/and/movz/orr with XZR) */
static arm64_expansion_t zero_reg(uint8_t rd, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29) {
        exp.valid = false;
        return exp;
    }
    
    switch (chacha20_random(rng) % 6) {
        case 0: {  /* EOR Xd, Xd, Xd */
            uint32_t insn = 0xCA000000;
            insn |= (is_64bit ? (1u << 31) : 0);
            insn |= rd | (rd << 5) | (rd << 16);
            *(uint32_t*)(exp.code) = insn;
            exp.len = 4;
            break;
        }
        case 1: {  /* SUB Xd, Xd, Xd */
            uint32_t insn = 0xCB000000;
            insn |= (is_64bit ? (1u << 31) : 0);
            insn |= rd | (rd << 5) | (rd << 16);
            *(uint32_t*)(exp.code) = insn;
            exp.len = 4;
            break;
        }
        case 2: {  /* AND Xd, Xd, #0 */
            uint32_t insn = 0x92400000;
            insn |= (is_64bit ? (1u << 31) : 0);
            insn |= rd | (rd << 5);
            *(uint32_t*)(exp.code) = insn;
            exp.len = 4;
            break;
        }
        case 3: {  /* MOVZ Xd, #0 */
            uint32_t insn = 0xD2800000;
            insn |= (is_64bit ? (1u << 31) : 0);
            insn |= rd;
            *(uint32_t*)(exp.code) = insn;
            exp.len = 4;
            break;
        }
        case 4: {  /* ORR Xd, XZR, XZR */
            uint32_t insn = 0xAA1F03E0;
            insn |= (is_64bit ? (1u << 31) : 0);
            insn |= rd | (31 << 5);
            *(uint32_t*)(exp.code) = insn;
            exp.len = 4;
            break;
        }
        case 5: {  /* EOR Xd, XZR, XZR */
            uint32_t insn = 0xCA1F03E0;
            insn |= (is_64bit ? (1u << 31) : 0);
            insn |= rd | (31 << 5);
            *(uint32_t*)(exp.code) = insn;
            exp.len = 4;
            break;
        }
    }
    
    exp.valid = true;
    return exp;
}

/* MOV reg, reg > ORR reg, XZR, reg */
static arm64_expansion_t mov_to_orr(uint8_t rd, uint8_t rm, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rm >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* ORR Xd, XZR, Xm */
    uint32_t insn = 0xAA0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rm << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* MOV reg, reg > ADD reg, XZR, reg */
static arm64_expansion_t mov_to_add(uint8_t rd, uint8_t rm, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rm >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* ADD Xd, XZR, Xm */
    uint32_t insn = 0x8B0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rm << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* XOR with zero = MOV */
static arm64_expansion_t mov_to_eor(uint8_t rd, uint8_t rm, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rm >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* EOR Xd, XZR, Xm */
    uint32_t insn = 0xCA0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rm << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* ADD reg, reg, #0 > MOV reg, reg (via ORR) */
static arm64_expansion_t add_zero_to_mov(uint8_t rd, uint8_t rn, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* ORR Xd, XZR, Xn */
    uint32_t insn = 0xAA0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rn << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* SUB reg, reg, #0 > MOV reg, reg */
static arm64_expansion_t sub_zero_to_mov(uint8_t rd, uint8_t rn, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* ORR Xd, XZR, Xn */
    uint32_t insn = 0xAA0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rn << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* ADD reg, reg > LSL reg, reg, #0 then ADD (chain) */
static arm64_expansion_t add_reg_chain(uint8_t rd, uint8_t rn, uint8_t rm, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29 || rm >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* Split ADD Xd, Xn, Xm > ADD Xd, Xn, XZR; ADD Xd, Xd, Xm */
    /* First ADD Xd, Xn, XZR (which is just MOV Xd, Xn) */
    uint32_t insn1 = 0xAA0003E0;
    insn1 |= (is_64bit ? (1u << 31) : 0);
    insn1 |= rd;
    insn1 |= (rn << 16);
    insn1 |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn1;
    
    /* Second */
    uint32_t insn2 = 0x8B000000;
    insn2 |= (is_64bit ? (1u << 31) : 0);
    insn2 |= rd;
    insn2 |= (rd << 5);
    insn2 |= (rm << 16);
    *(uint32_t*)(exp.code + 4) = insn2;
    
    exp.len = 8;
    exp.valid = true;
    return exp;
}

/* MUL reg, reg, #1 > MOV reg, reg */
static arm64_expansion_t mul_one_to_mov(uint8_t rd, uint8_t rn, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* ORR Xd, XZR, Xn */
    uint32_t insn = 0xAA0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rn << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* LSL reg, reg, #0 > MOV reg, reg */
static arm64_expansion_t lsl_zero_to_mov(uint8_t rd, uint8_t rn, bool is_64bit, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29) {
        exp.valid = false;
        return exp;
    }
    
    /* ORR Xd, XZR, Xn */
    uint32_t insn = 0xAA0003E0;
    insn |= (is_64bit ? (1u << 31) : 0);
    insn |= rd;
    insn |= (rn << 16);
    insn |= (31 << 5);  /* XZR */
    *(uint32_t*)(exp.code) = insn;
    
    exp.len = 4;
    exp.valid = true;
    return exp;
}

/* ldr [base+offset] > add temp, base, offset; ldr [temp] */
static arm64_expansion_t add_ldr(uint8_t rd, uint8_t rn, uint32_t offset,
                                                bool is_64bit, uint8_t temp_reg, 
                                                chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (rd >= 29 || rn >= 29 || temp_reg >= 29 || offset == 0) {
        exp.valid = false;
        return exp;
    }
    
    /* ADD Xtmp, Xn, #offset */
    uint32_t insn1 = 0x91000000;
    insn1 |= (is_64bit ? (1u << 31) : 0);
    insn1 |= temp_reg;
    insn1 |= (rn << 5);
    insn1 |= ((offset & 0xFFF) << 10);
    *(uint32_t*)(exp.code) = insn1;
    
    /* LDR Xd, [Xtmp] */
    uint32_t insn2 = 0xF9400000;
    insn2 |= (is_64bit ? (1u << 31) : 0);
    insn2 |= rd;
    insn2 |= (temp_reg << 5);
    *(uint32_t*)(exp.code + 4) = insn2;
    
    exp.len = 8;
    exp.valid = true;
    return exp;
}

/* Tries multiple patterns, picks largest valid one. Handles mov/add/sub and more */
static arm64_expansion_t arm64_inst(const arm64_inst_t *inst,
                                                   liveness_state_t *liveness,
                                                   size_t offset, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    
    if (!inst || !inst->valid || !rng) {
        exp.valid = false;
        return exp;
    }
    
    /* MOV immediate (MOVZ/MOVN) */
    if (inst->type == ARM_OP_MOV && inst->imm != 0) {
        /* Try expansions in order of size increase */
        arm64_expansion_t candidates[3];
        candidates[0] = movz_movk(inst->rd, inst->imm, inst->is_64bit, rng);
        candidates[1] = imm_to_ari(inst->rd, inst->imm, inst->is_64bit, rng);
        candidates[2] = imm_to_neg(inst->rd, inst->imm, inst->is_64bit, rng);
        
        /* Find largest valid expansion */
        size_t best_len = 4;
        int best_idx = -1;
        for (int i = 0; i < 3; i++) {
            if (candidates[i].valid && candidates[i].len > best_len) {
                best_len = candidates[i].len;
                best_idx = i;
            }
        }
        
        if (best_idx >= 0) {
            return candidates[best_idx];
        }
    }
    
    /* MOV Xd, #0 (zero register) */
    if (inst->type == ARM_OP_MOV && inst->imm == 0) {
        return zero_reg(inst->rd, inst->is_64bit, rng);
    }
    
    /* MOV reg, reg */
    if (inst->type == ARM_OP_MOV && inst->rm < 32 && inst->rm < 29) {
        switch (chacha20_random(rng) % 3) {
            case 0: return mov_to_orr(inst->rd, inst->rm, inst->is_64bit, rng);
            case 1: return mov_to_add(inst->rd, inst->rm, inst->is_64bit, rng);
            case 2: return mov_to_eor(inst->rd, inst->rm, inst->is_64bit, rng);
        }
    }
    
    /* ADD immediate */
    if (inst->type == ARM_OP_ADD && inst->imm > 0 && inst->imm <= 4095) {
        arm64_expansion_t chain = imm_to_chain(inst->rd, inst->rn, 
                                                          (uint32_t)inst->imm, 
                                                          inst->is_64bit, rng);
        if (chain.valid && chain.len > 4) {
            return chain;
        }
    }
    
    /* ADD reg, reg, #0 > MOV reg, reg */
    if (inst->type == ARM_OP_ADD && inst->imm == 0 && inst->rn < 29) {
        return add_zero_to_mov(inst->rd, inst->rn, inst->is_64bit, rng);
    }
    
    /* ADD reg, reg */
    if (inst->type == ARM_OP_ADD && inst->rm < 29 && inst->rn < 29) {
        arm64_expansion_t chain = add_reg_chain(inst->rd, inst->rn, inst->rm, 
                                                          inst->is_64bit, rng);
        if (chain.valid && chain.len > 4) {
            return chain;
        }
    }
    
    /* SUB immediate */
    if (inst->type == ARM_OP_SUB && inst->imm > 0 && inst->imm <= 4095) {
        /* Try both chain and neg expansion */
        arm64_expansion_t candidates[2];
        candidates[0] = sub_imm(inst->rd, inst->rn, (uint32_t)inst->imm, inst->is_64bit, rng);
        candidates[1] = sub_neg(inst->rd, inst->rn, (uint32_t)inst->imm, inst->is_64bit, rng);
        
        /* Prefer larger expansion */
        size_t best_len = 4;
        int best_idx = -1;
        for (int i = 0; i < 2; i++) {
            if (candidates[i].valid && candidates[i].len > best_len) {
                best_len = candidates[i].len;
                best_idx = i;
            }
        }
        
        if (best_idx >= 0) {
            return candidates[best_idx];
        }
    }
    
    /* SUB reg, reg, #0 > MOV reg, reg */
    if (inst->type == ARM_OP_SUB && inst->imm == 0 && inst->rn < 29) {
        return sub_zero_to_mov(inst->rd, inst->rn, inst->is_64bit, rng);
    }
    
    /* MUL reg, reg, #1 > MOV reg, reg */
    if (inst->type == ARM_OP_MUL && inst->rm < 29 && inst->rn < 29) {
    }
    
    if (inst->type == ARM_OP_LDR && inst->imm > 0 && inst->imm <= 4095) {
        uint8_t temp_reg = 16;
        if (inst->rd != 16 && inst->rn != 16) {
            arm64_expansion_t ldr_exp = add_ldr(inst->rd, inst->rn, (uint32_t)inst->imm,
                                                          inst->is_64bit, temp_reg, rng);
            if (ldr_exp.valid && ldr_exp.len > 4) {
                return ldr_exp;
            }
        }
    }
    
    exp.valid = false;
    return exp;
}

/* Apply expansion to code buffer */
bool apply_arm64(uint8_t *code, size_t *size, size_t max_size,
                           size_t offset, const arm64_inst_t *inst,
                           liveness_state_t *liveness, chacha_state_t *rng) {
    if (!code || !size || !inst || !rng) return false;
    if (offset + 4 > *size) return false;
    
    arm64_expansion_t exp = arm64_inst(inst, liveness, offset, rng);
    if (!exp.valid || exp.len == 0) return false;
    
    /* Check if expansion fits */
    size_t size_diff = (exp.len > 4) ? (exp.len - 4) : 0;
    if (*size + size_diff > max_size) return false;
    
    /* Can't expand if it would shift code and break control flow */
    /* ARM64 branches use PC-relative offsets that would become invalid */
    /* Only allow if: 
     1. Replacement (same size), OR 
     2. We're near the end of the code (last 20% for small, 10% for large)
    */
    if (exp.len > 4) {
        size_t safe_zone;
        
        /* For larger expansions (>8 bytes), use stricter zone (last 10%) */
        if (exp.len > 8) {
            safe_zone = *size * 9 / 10;
        } else {
            /* For small expansions (4->8 bytes), more permissive (last 20%) */
            safe_zone = *size * 4 / 5;
        }
        
        /* If we're not in the safe zone, reject expansion */
        if (offset < safe_zone) {
            return false;
        }
    }
    
    /* Make room for expansion */
    if (exp.len > 4) {
        memmove(code + offset + exp.len,
                code + offset + 4,
                *size - offset - 4);
        *size += size_diff;
    }
    
    /* Apply expansion */
    memcpy(code + offset, exp.code, exp.len);
    
    /* Validate all expanded instructions */
    for (size_t i = 0; i < exp.len; i += 4) {
        arm64_inst_t verify;
        if (!decode_arm64(code + offset + i, &verify) || !verify.valid || verify.ring0) {
            /* Rollback */
            memcpy(code + offset, inst->raw, 4);
            if (exp.len > 4) {
                memmove(code + offset + 4,
                        code + offset + exp.len,
                        *size - offset - exp.len);
                *size -= size_diff;
            }
            return false;
        }
    }
    
    return true;
}

size_t expand_arm64(uint8_t *code, size_t size, size_t max_size,
                                 liveness_state_t *liveness, chacha_state_t *rng,
                                 unsigned expansion_intensity) {
    if (!code || size == 0 || !rng || (size % 4) != 0) return size;
    
    size_t current_size = size;
    size_t offset = 0;
    
    while (offset + 4 <= current_size && current_size < max_size) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            offset += 4;
            continue;
        }
        
        /* Randomly decide whether to expand */
        if ((chacha20_random(rng) % 100) < expansion_intensity) {
            if (apply_arm64(code, &current_size, max_size, offset, 
                                     &inst, liveness, rng)) {
                /* Re-decode to get new length */
                arm64_inst_t new_inst;
                size_t expanded_len = 0;
                for (size_t i = offset; i < current_size; i += 4) {
                    if (decode_arm64(code + i, &new_inst) && new_inst.valid) {
                        expanded_len += 4;
                    } else {
                        break;
                    }
                    /* Stop at next original instruction boundary */
                    if (expanded_len >= 8) break;
                }
                offset += expanded_len;
                continue;
            }
        }
        
        offset += 4;
    }
    
    return current_size;
}

/* Recursively expand code multiple times */
size_t expand_chains_arm64(uint8_t *code, size_t size, size_t max_size,
                                    liveness_state_t *liveness, chacha_state_t *rng,
                                    unsigned chain_depth, unsigned expansion_intensity) {
    if (!code || size == 0 || !rng || chain_depth == 0) return size;
    
    size_t current_size = size;
    
    /* Apply multiple rounds of expansion */
    for (unsigned round = 0; round < chain_depth && current_size < max_size; round++) {
        size_t round_start_size = current_size;
        size_t offset = 0;
        
        /* Scan through code and expand instructions */
        while (offset + 4 <= current_size && current_size < max_size) {
            arm64_inst_t inst;
            if (!decode_arm64(code + offset, &inst) || !inst.valid) {
                offset += 4;
                continue;
            }
            
            /* Probability decreases with each round to avoid explosion */
            unsigned round_intensity = expansion_intensity / (round + 1);
            if (round_intensity < 10) round_intensity = 10;
            
            if ((chacha20_random(rng) % 100) < round_intensity) {
                size_t pre_expand_size = current_size;
                
                if (apply_arm64(code, &current_size, max_size, offset, &inst, liveness, rng)) {
                    arm64_inst_t new_inst;
                    size_t expanded_len = 0;
                    for (size_t i = offset; i < current_size && i < offset + 16; i += 4) {
                        if (decode_arm64(code + i, &new_inst) && new_inst.valid) {
                            expanded_len += 4;
                        } else {
                            break;
                        }
                        /* Stop at reasonable boundary */
                        if (expanded_len >= 12) break;
                    }
                    offset += expanded_len;
                    
                    /* Safety check: prevent runaway expansion */
                    if (current_size > pre_expand_size + 100) {
                        current_size = pre_expand_size;
                        break;
                    }
                    continue;
                }
            }
            
            offset += 4;
        }
        
        /* If no expansion happened this round, stop */
        if (current_size == round_start_size) {
            break;
        }
    }
    
    return current_size;
}

/* Aggressively chain-expand MOV immediate instructions */
size_t mov_immediates_arm64(uint8_t *code, size_t size, size_t max_size,
                                     liveness_state_t *liveness, chacha_state_t *rng,
                                     unsigned chain_depth) {
    if (!code || size == 0 || !rng || chain_depth == 0) return size;
    
    size_t current_size = size;
    
    for (unsigned round = 0; round < chain_depth && current_size < max_size; round++) {
        size_t offset = 0;
        bool expanded_any = false;
        
        while (offset + 4 <= current_size && current_size < max_size) {
            arm64_inst_t inst;
            if (!decode_arm64(code + offset, &inst) || !inst.valid) {
                offset += 4;
                continue;
            }
            
            /* Target MOV reg, imm instructions */
            if (inst.type == ARM_OP_MOV && inst.imm != 0) {
                if (apply_arm64(code, &current_size, max_size, offset, &inst, liveness, rng)) {
                    expanded_any = true;
                    
                    /* Re-decode to get new length */
                    arm64_inst_t new_inst;
                    size_t expanded_len = 0;
                    for (size_t i = offset; i < current_size && i < offset + 16; i += 4) {
                        if (decode_arm64(code + i, &new_inst) && new_inst.valid) {
                            expanded_len += 4;
                        } else {
                            break;
                        }
                        if (expanded_len >= 12) break;
                    }
                    offset += expanded_len;
                    continue;
                }
            }
            
            offset += 4;
        }
        
        if (!expanded_any) break;
    }
    
    return current_size;
}

/* Chain expand arithmetic instructions (ADD, SUB) */
size_t expand_arithmetic_arm64(uint8_t *code, size_t size, size_t max_size,
                                    liveness_state_t *liveness, chacha_state_t *rng,
                                    unsigned chain_depth) {
    if (!code || size == 0 || !rng || chain_depth == 0) return size;
    
    size_t current_size = size;
    
    for (unsigned round = 0; round < chain_depth && current_size < max_size; round++) {
        size_t offset = 0;
        bool expanded_any = false;
        
        while (offset + 4 <= current_size && current_size < max_size) {
            arm64_inst_t inst;
            if (!decode_arm64(code + offset, &inst) || !inst.valid) {
                offset += 4;
                continue;
            }
            
            bool is_arithmetic = false;
            
            /* Check if it's an arithmetic instruction */
            if (inst.type == ARM_OP_ADD || inst.type == ARM_OP_SUB) {
                is_arithmetic = true;
            }
            
            if (is_arithmetic) {
                if (apply_arm64(code, &current_size, max_size, offset, &inst, liveness, rng)) {
                    expanded_any = true;
                    
                    arm64_inst_t new_inst;
                    size_t expanded_len = 0;
                    for (size_t i = offset; i < current_size && i < offset + 16; i += 4) {
                        if (decode_arm64(code + i, &new_inst) && new_inst.valid) {
                            expanded_len += 4;
                        } else {
                            break;
                        }
                        if (expanded_len >= 12) break;
                    }
                    offset += expanded_len;
                    continue;
                }
            }
            
            offset += 4;
        }
        
        if (!expanded_any) break;
    }
    
    return current_size;
}

#endif  /* ARCH_ARM */
