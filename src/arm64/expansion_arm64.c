#include <aether.h>

/* Main dispatcher for ARM expansions */

#if defined(__aarch64__) || defined(_M_ARM64)

static inline bool can_use_reg(uint8_t reg) {return reg < 29;}
static inline void emit_arm64(uint8_t *code, size_t *len, uint32_t base, bool is_64bit, 
                               uint8_t rd, uint8_t rn, uint8_t rm, uint32_t imm) {
    uint32_t insn = base;
    if (is_64bit) insn |= (1u << 31);
    if (rd < 32) insn |= rd;
    if (rn < 32) insn |= (rn << 5);
    if (rm < 32) insn |= (rm << 16);
    if (imm) insn |= (imm << 10);
    *(uint32_t*)(code + *len) = insn;
    *len += 4;
}



static arm64_expansion_t arm64_inst(const arm64_inst_t *inst, liveness_state_t *liveness,
                                    size_t offset, chacha_state_t *rng) {
    arm64_expansion_t exp = {0};
    if (!inst || !inst->valid || !rng || !can_use_reg(inst->rd)) return exp;
    
    bool is_64 = inst->is_64bit;
    uint8_t rd = inst->rd, rn = inst->rn, rm = inst->rm;
    
    if (inst->type == ARM_OP_MOV) {
        if (inst->imm == 0) {
            switch (chacha20_random(rng) % 4) {
                case 0: emit_arm64(exp.code, &exp.len, 0xCA000000, is_64, rd, rd, rd, 0); break;
                case 1: emit_arm64(exp.code, &exp.len, 0xCB000000, is_64, rd, rd, rd, 0); break;
                case 2: emit_arm64(exp.code, &exp.len, 0x92400000, is_64, rd, rd, 32, 0); break;
                case 3: emit_arm64(exp.code, &exp.len, 0xD2800000, is_64, rd, 32, 32, 0); break;
            }
            exp.valid = true;
            return exp;
        }
        
        if (rm < 29) {
            uint32_t bases[] = {0xAA0003E0, 0x8B0003E0, 0xCA0003E0};
            uint32_t base = bases[chacha20_random(rng) % 3];
            emit_arm64(exp.code, &exp.len, base, is_64, rd, 31, rm, 0);
            exp.valid = true;
            return exp;
        }
        
        if (inst->imm > 0 && inst->imm <= 0xFFFF) {
            uint64_t imm = inst->imm;
            int choice = -1;
            size_t best = 4;
            
            size_t movz_len = 0;
            for (int s = 0; s < (is_64 ? 64 : 32); s += 16) {
                if (((imm >> s) & 0xFFFF) != 0 || (s == 0 && imm == 0)) movz_len += 4;
            }
            if (movz_len > best) {best = movz_len; choice = 0;}
            if (8 > best) {best = 8; choice = 1;}
            
            switch (choice) {
                case 0: {
                    bool first = true;
                    for (int s = 0; s < (is_64 ? 64 : 32); s += 16) {
                        uint16_t chunk = (imm >> s) & 0xFFFF;
                        if (chunk || (s == 0 && !imm)) {
                            uint32_t insn = first ? 0xD2800000 : 0xF2800000;
                            if (is_64) insn |= (1u << 31);
                            insn |= rd | ((uint32_t)chunk << 5) | ((s / 16) << 21);
                            *(uint32_t*)(exp.code + exp.len) = insn;
                            exp.len += 4;
                            first = false;
                        }
                    }
                    break;
                }
                case 1: {
                    uint32_t base = (uint32_t)imm / 2, delta = (uint32_t)imm - base;
                    emit_arm64(exp.code, &exp.len, 0xD2800000, is_64, rd, 32, 32, 0);
                    exp.code[exp.len - 4] |= ((base & 0xFFFF) << 5);
                    emit_arm64(exp.code, &exp.len, 0x91000000, is_64, rd, rd, 32, delta & 0xFFF);
                    break;
                }
                default: return exp;
            }
            exp.valid = true;
            return exp;
        }
    }
    
    if (inst->type == ARM_OP_ADD) {
        if (inst->imm == 0 && can_use_reg(rn)) {
            emit_arm64(exp.code, &exp.len, 0xAA0003E0, is_64, rd, 31, rn, 0);
            exp.valid = true;
            return exp;
        }
        
        if (inst->imm > 0 && inst->imm <= 4095) {
            uint32_t imm = (uint32_t)inst->imm, rem = imm;
            bool first = true;
            while (rem > 0 && exp.len < 60) {
                uint32_t chunk = rem > 255 ? 255 : rem;
                emit_arm64(exp.code, &exp.len, 0x91000000, is_64, rd, first ? rn : rd, 32, chunk);
                rem -= chunk;
                first = false;
            }
            exp.valid = exp.len > 4;
            return exp;
        }
        
        if (can_use_reg(rm) && can_use_reg(rn)) {
            emit_arm64(exp.code, &exp.len, 0xAA0003E0, is_64, rd, 31, rn, 0);
            emit_arm64(exp.code, &exp.len, 0x8B000000, is_64, rd, rd, rm, 0);
            exp.valid = true;
            return exp;
        }
    }
    
    if (inst->type == ARM_OP_SUB) {
        if (inst->imm == 0 && can_use_reg(rn)) {
            emit_arm64(exp.code, &exp.len, 0xAA0003E0, is_64, rd, 31, rn, 0);
            exp.valid = true;
            return exp;
        }
        
        if (inst->imm > 0 && inst->imm <= 4095) {
            uint32_t imm = (uint32_t)inst->imm, rem = imm;
            bool first = true;
            while (rem > 0 && exp.len < 60) {
                uint32_t chunk = rem > 255 ? 255 : rem;
                emit_arm64(exp.code, &exp.len, 0xD1000000, is_64, rd, first ? rn : rd, 32, chunk);
                rem -= chunk;
                first = false;
            }
            exp.valid = exp.len > 4;
            return exp;
        }
    }
    
    if (inst->type == ARM_OP_LDR && inst->imm > 0 && inst->imm <= 4095 && 
        rd != 16 && rn != 16) {
        emit_arm64(exp.code, &exp.len, 0x91000000, is_64, 16, rn, 32, (uint32_t)inst->imm & 0xFFF);
        emit_arm64(exp.code, &exp.len, 0xF9400000, is_64, rd, 16, 32, 0);
        exp.valid = exp.len > 4;
        return exp;
    }
    
    return exp;
}

bool apply_arm64(uint8_t *code, size_t *size, size_t max_size, size_t offset, 
                 const arm64_inst_t *inst, liveness_state_t *liveness, chacha_state_t *rng) {
    if (!code || !size || !inst || !rng || offset + 4 > *size) return false;
    
    arm64_expansion_t exp = arm64_inst(inst, liveness, offset, rng);
    if (!exp.valid || !exp.len) return false;
    
    size_t diff = exp.len > 4 ? exp.len - 4 : 0;
    if (*size + diff > max_size) return false;
    
    if (exp.len > 4) {
        size_t safe = exp.len > 8 ? *size * 9 / 10 : *size * 4 / 5;
        if (offset < safe) return false;
        
        for (size_t so = offset; so + 4 <= offset + 128 && so + 4 <= *size; so += 4) {
            arm64_inst_t si;
            if (!decode_arm64(code + so, &si) || !si.valid) continue;
            if (si.type == ARM_OP_BRANCH || si.type == ARM_OP_BRANCH_LINK || si.type == ARM_OP_BRANCH_COND ||
                si.type == ARM_OP_CBZ || si.type == ARM_OP_CBNZ || si.type == ARM_OP_TBZ || si.type == ARM_OP_TBNZ ||
                si.type == ARM_OP_ADRP || si.type == ARM_OP_ADR || (si.raw & 0x3B000000) == 0x18000000) {
                return false;
            }
        }
        
        memmove(code + offset + exp.len, code + offset + 4, *size - offset - 4);
        *size += diff;
    }
    
    memcpy(code + offset, exp.code, exp.len);
    
    for (size_t i = 0; i < exp.len; i += 4) {
        arm64_inst_t verify;
        if (!decode_arm64(code + offset + i, &verify) || !verify.valid || verify.ring0) {
            memcpy(code + offset, &inst->raw, 4);
            if (exp.len > 4) {
                memmove(code + offset + 4, code + offset + exp.len, *size - offset - exp.len);
                *size -= diff;
            }
            return false;
        }
    }
    
    return true;
}

static size_t expand_loop_arm64(uint8_t *code, size_t size, size_t max, liveness_state_t *liveness,
                                chacha_state_t *rng, unsigned intensity, bool (*filter)(const arm64_inst_t*)) {
    if (!code || !size || !rng || (size % 4)) return size;
    size_t cur = size, off = 0;
    while (off + 4 <= cur && cur < max) {
        arm64_inst_t inst;
        if (!decode_arm64(code + off, &inst) || !inst.valid) {off += 4; continue;}
        if ((!filter || filter(&inst)) && (chacha20_random(rng) % 100) < intensity) {
            if (apply_arm64(code, &cur, max, off, &inst, liveness, rng)) {
                size_t elen = 0;
                for (size_t i = off; i < cur && i < off + 16; i += 4) {
                    arm64_inst_t ni;
                    if (decode_arm64(code + i, &ni) && ni.valid) elen += 4; else break;
                    if (elen >= 12) break;
                }
                off += elen;
                continue;
            }
        }
        off += 4;
    }
    return cur;
}

size_t expand_arm64(uint8_t *code, size_t size, size_t max_size,
                    liveness_state_t *liveness, chacha_state_t *rng,
                    unsigned expansion_intensity) {
    /* Don't expand PAC-protected functions - mutations break SP context */
    if (size >= 4) {
        uint32_t first_insn = *(uint32_t*)code;
        if ((first_insn & 0xFFFFFBFFu) == 0xD503233Fu) {  /* PACIASP/PACIBSP */
            return size;  /* Return unchanged */
        }
    }
    return expand_loop_arm64(code, size, max_size, liveness, rng, expansion_intensity, NULL);
}

size_t expand_chains_arm64(uint8_t *code, size_t size, size_t max_size,
                            liveness_state_t *liveness, chacha_state_t *rng,
                            unsigned chain_depth, unsigned expansion_intensity) {
    if (!code || !size || !rng || !chain_depth) return size;
    /* Don't expand PAC-protected functions */
    if (size >= 4) {
        uint32_t first_insn = *(uint32_t*)code;
        if ((first_insn & 0xFFFFFBFFu) == 0xD503233Fu) {  /* PACIASP/PACIBSP */
            return size;
        }
    }
    size_t cur = size;
    for (unsigned r = 0; r < chain_depth && cur < max_size; r++) {
        size_t start = cur;
        unsigned intensity = expansion_intensity / (r + 1);
        if (intensity < 10) intensity = 10;
        cur = expand_loop_arm64(code, cur, max_size, liveness, rng, intensity, NULL);
        if (cur == start) break;
    }
    return cur;
}

static bool is_mov_imm_arm64(const arm64_inst_t *i) {return i->type == ARM_OP_MOV && i->imm != 0;}
static bool is_arith_arm64(const arm64_inst_t *i) {return i->type == ARM_OP_ADD || i->type == ARM_OP_SUB;}

size_t mov_immediates_arm64(uint8_t *code, size_t size, size_t max_size,
                             liveness_state_t *liveness, chacha_state_t *rng,
                             unsigned chain_depth) {
    if (!code || !size || !rng || !chain_depth) return size;
    /* Don't expand PAC-protected functions */
    if (size >= 4) {
        uint32_t first_insn = *(uint32_t*)code;
        if ((first_insn & 0xFFFFFBFFu) == 0xD503233Fu) return size;
    }
    size_t cur = size;
    for (unsigned r = 0; r < chain_depth && cur < max_size; r++) {
        size_t start = cur;
        cur = expand_loop_arm64(code, cur, max_size, liveness, rng, 100, is_mov_imm_arm64);
        if (cur == start) break;
    }
    return cur;
}

size_t expand_arithmetic_arm64(uint8_t *code, size_t size, size_t max_size,
                                liveness_state_t *liveness, chacha_state_t *rng,
                                unsigned chain_depth) {
    if (!code || !size || !rng || !chain_depth) return size;
    /* Don't expand PAC-protected functions */
    if (size >= 4) {
        uint32_t first_insn = *(uint32_t*)code;
        if ((first_insn & 0xFFFFFBFFu) == 0xD503233Fu) return size;
    }
    size_t cur = size;
    for (unsigned r = 0; r < chain_depth && cur < max_size; r++) {
        size_t start = cur;
        cur = expand_loop_arm64(code, cur, max_size, liveness, rng, 100, is_arith_arm64);
        if (cur == start) break;
    }
    return cur;
}

#endif  /* __aarch64__ || _M_ARM64 */
