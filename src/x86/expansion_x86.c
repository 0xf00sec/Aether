#include <aether.h>

/* Main dispatcher for x86 expansions */

static inline bool can_use_reg(uint8_t reg) {return reg != 4;}
static inline bool imm_fits_32bit_signed(uint64_t imm) {
    return imm <= 0x7FFFFFFF || imm >= 0xFFFFFFFF80000000ULL;}

static inline void emit_rex_modrm(uint8_t *code, size_t *len, uint8_t opcode, uint8_t reg) {
    code[(*len)++] = 0x48;
    code[(*len)++] = opcode;
    code[(*len)++] = 0xC0 | reg;
}

static inline void emit_rex_modrm_reg(uint8_t *code, size_t *len, uint8_t opcode, uint8_t reg1, uint8_t reg2) {
    code[(*len)++] = 0x48;
    code[(*len)++] = opcode;
    code[(*len)++] = 0xC0 | (reg1 << 3) | reg2;
}

expansion_t expand_instruction(const x86_inst_t *inst, liveness_state_t *liveness, 
                                size_t offset, chacha_state_t *rng,
                                uint8_t *code, size_t code_size) {
    expansion_t exp = {0};
    
    if (!inst || !inst->valid || !rng || inst->is_simd || inst->vex || inst->evex) {
        return exp;
    }
    
    uint8_t op = inst->opcode[0];
    
    if (op == 0x89 && inst->has_modrm && ((inst->modrm >> 6) & 3) == 3) {
        uint8_t dst = modrm_rm(inst->modrm);
        uint8_t src = modrm_reg(inst->modrm);
        
        if (!can_use_reg(dst) || !can_use_reg(src)) return exp;
        
        if (chacha20_random(rng) & 1) {
            exp.code[0] = 0x50 | src;
            exp.code[1] = 0x58 | dst;
            exp.len = 2;
        } else if (dst != src) {
            exp.code[0] = 0x48; exp.code[1] = 0x87;
            exp.code[2] = 0xC0 | (dst << 3) | src;
            exp.code[3] = 0x48; exp.code[4] = 0x87;
            exp.code[5] = 0xC0 | (dst << 3) | src;
            exp.len = 6;
        } else {
            return exp;
        }
        exp.valid = true;
        return exp;
    }
    
    if ((op & 0xF8) == 0xB8) {
        uint8_t reg = op & 0x7;
        uint64_t imm = inst->imm;
        
        if (!imm_fits_32bit_signed(imm)) return exp;
        
        if (imm == 0) {
            switch (chacha20_random(rng) % 5) {
                case 0: emit_rex_modrm_reg(exp.code, &exp.len, 0x29, reg, reg); break;
                case 1: emit_rex_modrm(exp.code, &exp.len, 0x83, 0xE0 | reg); exp.code[exp.len++] = 0; break;
                case 2: emit_rex_modrm_reg(exp.code, &exp.len, 0x6B, reg, reg); exp.code[exp.len++] = 0; break;
                case 3: if (!can_use_reg(reg)) return exp; exp.code[exp.len++] = 0x6A; exp.code[exp.len++] = 0; exp.code[exp.len++] = 0x58 | reg; break;
                case 4: exp.code[exp.len++] = 0x48; exp.code[exp.len++] = 0x8D; exp.code[exp.len++] = 0x04 | (reg << 3); exp.code[exp.len++] = 0x25; *(uint32_t*)(exp.code + exp.len) = 0; exp.len += 4; break;
            }
            exp.valid = true;
            return exp;
        }
        
        uint32_t imm32 = (uint32_t)imm;
        int choice = -1;
        size_t best = inst->len;
        
        if (imm <= 20) {
            size_t test = 3 + (imm * 4);
            if (test > best) {best = test; choice = 0;}
        }
        if (imm <= 0x7FFFFFFF && can_use_reg(reg) && 6 > best) {best = 6; choice = 1;}
        if (imm > 0 && imm <= 0x7FFFFFFF && 18 > best) {best = 18; choice = 2;}
        if (imm <= 0x7FFFFFFF && 14 > best) {best = 14; choice = 3;}
        if (imm > 0 && imm <= 0x3FFFFFFF && 10 > best) {best = 10; choice = 4;}
        if (imm > 0 && imm <= 0x7FFFFFFF) {
            uint32_t c = 2 + (chacha20_random(rng) % 3);
            size_t test = (imm32 % c) ? 28 : 21;
            if (test > best) {best = test; choice = 5;}
        }
        
        switch (choice) {
            case 0:
                emit_rex_modrm_reg(exp.code, &exp.len, 0x31, reg, reg);
                for (uint64_t r = imm; r > 0 && exp.len < 100; r -= (r > 5 ? 5 : r)) {
                    uint8_t c = r > 5 ? 5 : (uint8_t)r;
                    emit_rex_modrm(exp.code, &exp.len, 0x83, 0xC0 | reg);
                    exp.code[exp.len++] = c;
                }
                break;
            case 1:
                exp.code[exp.len++] = 0x68;
                *(int32_t*)(exp.code + exp.len) = (int32_t)imm; exp.len += 4;
                exp.code[exp.len++] = 0x58 | reg;
                break;
            case 2: {
                uint8_t s = 1 + (chacha20_random(rng) % 3);
                uint32_t p1 = imm32 >> s, p2 = imm32 - (p1 << s);
                emit_rex_modrm(exp.code, &exp.len, 0xC7, 0xC0 | reg);
                *(uint32_t*)(exp.code + exp.len) = p1; exp.len += 4;
                emit_rex_modrm(exp.code, &exp.len, 0xC1, 0xE0 | reg);
                exp.code[exp.len++] = s;
                emit_rex_modrm(exp.code, &exp.len, 0x81, 0xC0 | reg);
                *(uint32_t*)(exp.code + exp.len) = p2; exp.len += 4;
                break;
            }
            case 3: {
                uint32_t k = chacha20_random(rng);
                emit_rex_modrm(exp.code, &exp.len, 0xC7, 0xC0 | reg);
                *(uint32_t*)(exp.code + exp.len) = imm32 ^ k; exp.len += 4;
                emit_rex_modrm(exp.code, &exp.len, 0x81, 0xF0 | reg);
                *(uint32_t*)(exp.code + exp.len) = k; exp.len += 4;
                break;
            }
            case 4:
                emit_rex_modrm(exp.code, &exp.len, 0xC7, 0xC0 | reg);
                *(uint32_t*)(exp.code + exp.len) = imm32 * 2; exp.len += 4;
                emit_rex_modrm(exp.code, &exp.len, 0xD1, 0xE8 | reg);
                break;
            case 5: {
                uint32_t c = 2 + (chacha20_random(rng) % 3);
                uint32_t d = imm32 % c, t = (imm32 - d) / c, a = t / 2, b = t - a;
                emit_rex_modrm_reg(exp.code, &exp.len, 0x31, reg, reg);
                emit_rex_modrm(exp.code, &exp.len, 0x81, 0xC0 | reg);
                *(uint32_t*)(exp.code + exp.len) = a; exp.len += 4;
                emit_rex_modrm(exp.code, &exp.len, 0x81, 0xC0 | reg);
                *(uint32_t*)(exp.code + exp.len) = b; exp.len += 4;
                emit_rex_modrm_reg(exp.code, &exp.len, 0x6B, reg, reg);
                exp.code[exp.len++] = (uint8_t)c;
                if (d) {
                    emit_rex_modrm(exp.code, &exp.len, 0x81, 0xC0 | reg);
                    *(uint32_t*)(exp.code + exp.len) = d; exp.len += 4;
                }
                break;
            }
            default: return exp;
        }
        
        exp.valid = true;
        return exp;
    }
    
    if (op == 0x83 && inst->has_modrm) {
        uint8_t rf = modrm_reg(inst->modrm);
        uint8_t reg = modrm_rm(inst->modrm);
        
        if (rf == 0 && ((inst->modrm >> 6) & 3) == 3 && inst->imm > 0 && inst->imm <= 15) {
            bool cf = false;
            if (code && code_size > 0) {
                for (size_t so = offset + inst->len, lh = 5; lh && so < code_size && !cf; lh--) {
                    x86_inst_t si;
                    if (!decode_x86_withme(code + so, code_size - so, 0, &si, NULL) || !si.valid) break;
                    uint8_t s = si.opcode[0];
                    if ((s >= 0x10 && s <= 0x1D) || (s >= 0x80 && s <= 0x83 && si.has_modrm && (modrm_reg(si.modrm) == 2 || modrm_reg(si.modrm) == 3)) ||
                        ((s >= 0xC0 && s <= 0xD3) && si.has_modrm && (modrm_reg(si.modrm) == 2 || modrm_reg(si.modrm) == 3)) ||
                        s == 0x72 || s == 0x73 || s == 0x9F || s == 0x9C ||
                        (si.opcode_len >= 2 && s == 0x0F && ((si.opcode[1] >= 0x42 && si.opcode[1] <= 0x43) || (si.opcode[1] >= 0x82 && si.opcode[1] <= 0x83) || (si.opcode[1] >= 0x92 && si.opcode[1] <= 0x93)))) {
                        cf = true;
                    } else if ((s >= 0x00 && s <= 0x3D) || (s >= 0x84 && s <= 0xA9) || (s >= 0xC0 && s <= 0xD3) || s == 0x9E || s == 0x9D) {
                        break;
                    }
                    so += si.len;
                }
            }
            
            if (!cf && inst->imm <= 20) {
                for (uint8_t i = 0; i < inst->imm; i++) emit_rex_modrm(exp.code, &exp.len, 0xFF, 0xC0 | reg);
                exp.valid = true;
                return exp;
            }
            
            int32_t imm = (int32_t)inst->imm;
            exp.code[exp.len++] = 0x48; exp.code[exp.len++] = 0x8D;
            if (imm >= -128 && imm <= 127) {
                exp.code[exp.len++] = 0x40 | (reg << 3) | reg;
                exp.code[exp.len++] = (uint8_t)imm;
            } else {
                exp.code[exp.len++] = 0x80 | (reg << 3) | reg;
                *(int32_t*)(exp.code + exp.len) = imm; exp.len += 4;
            }
            exp.valid = true;
            return exp;
        }
        
        if (rf == 5 && (int8_t)inst->imm != -128) {
            emit_rex_modrm(exp.code, &exp.len, 0x83, 0xC0 | reg);
            exp.code[exp.len++] = (uint8_t)(-(int8_t)inst->imm);
            exp.valid = true;
            return exp;
        }
    }
    
    if ((op == 0x31 || op == 0x29) && inst->has_modrm && modrm_reg(inst->modrm) == modrm_rm(inst->modrm)) {
        emit_rex_modrm_reg(exp.code, &exp.len, 0x31, modrm_reg(inst->modrm), modrm_reg(inst->modrm));
        exp.valid = true;
        return exp;
    }
    
    if (op == 0x85 && inst->has_modrm && modrm_reg(inst->modrm) == modrm_rm(inst->modrm)) {
        uint8_t reg = modrm_reg(inst->modrm);
        emit_rex_modrm(exp.code, &exp.len, 0x83, 0xC8 | reg); exp.code[exp.len++] = 0;
        emit_rex_modrm(exp.code, &exp.len, 0x83, 0xF8 | reg); exp.code[exp.len++] = 0;
        exp.valid = true;
        return exp;
    }
    
    if (op == 0xF7 && inst->has_modrm) {
        uint8_t rf = modrm_reg(inst->modrm), reg = modrm_rm(inst->modrm);
        if (rf == 2) {
            emit_rex_modrm(exp.code, &exp.len, 0x81, 0xF0 | reg);
            *(uint32_t*)(exp.code + exp.len) = 0xFFFFFFFF; exp.len += 4;
            exp.valid = true;
            return exp;
        }
        if (rf == 3) {
            emit_rex_modrm(exp.code, &exp.len, 0xF7, 0xD0 | reg);
            emit_rex_modrm(exp.code, &exp.len, 0xFF, 0xC0 | reg);
            exp.valid = true;
            return exp;
        }
    }
    
    if (op == 0x01 && inst->has_modrm && ((inst->modrm >> 6) & 3) == 3) {
        uint8_t reg = modrm_reg(inst->modrm), rm = modrm_rm(inst->modrm);
        if (reg == rm) {
            emit_rex_modrm(exp.code, &exp.len, 0xD1, 0xE0 | reg);
            exp.valid = true;
            return exp;
        }
        if (can_use_reg(rm) && can_use_reg(reg)) {
            exp.code[exp.len++] = 0x48; exp.code[exp.len++] = 0x8D;
            exp.code[exp.len++] = 0x04 | (rm << 3);
            exp.code[exp.len++] = (reg << 3) | rm;
            exp.valid = true;
            return exp;
        }
    }
    
    if (op == 0xFF && inst->has_modrm) {
        uint8_t rf = modrm_reg(inst->modrm), reg = modrm_rm(inst->modrm);
        if (rf == 0 || rf == 1) {
            if (chacha20_random(rng) & 1) {
                emit_rex_modrm(exp.code, &exp.len, 0x83, (rf == 0 ? 0xC0 : 0xE8) | reg);
                exp.code[exp.len++] = 1;
            } else {
                exp.code[exp.len++] = 0x48; exp.code[exp.len++] = 0x8D;
                exp.code[exp.len++] = 0x40 | (reg << 3) | reg;
                exp.code[exp.len++] = rf == 0 ? 1 : 0xFF;
            }
            exp.valid = true;
            return exp;
        }
    }
    
    return exp;
}

bool apply_expansion(uint8_t *code, size_t *size, size_t offset, 
                     const x86_inst_t *inst, liveness_state_t *liveness,
                     chacha_state_t *rng, reloc_table_t *reloc_table,
                     uint64_t base_addr) {
    if (!code || !size || !inst || !rng) return false;
    
    expansion_t exp = expand_instruction(inst, liveness, offset, rng, code, *size);
    if (!exp.valid || exp.len == 0) return false;
    
    size_t diff = exp.len > inst->len ? exp.len - inst->len : 0;
    if (offset + exp.len > *size || *size + diff > *size * 2) return false;
    
    if (exp.len > inst->len) {
        if (!reloc_table && offset < *size * 9 / 10) return false;
        if (inst->rip_relative || (inst->has_modrm && ((inst->modrm >> 6) & 3) == 0 && (inst->modrm & 7) == 5)) return false;
        
        size_t ss = offset > 128 ? offset - 128 : 0, se = offset + 128 < *size ? offset + 128 : *size;
        for (size_t so = ss; so < se; ) {
            if (so == offset) {so += inst->len; continue;}
            x86_inst_t si;
            if (!decode_x86_withme(code + so, *size - so, 0, &si, NULL) || !si.valid || si.len == 0) {so++; continue;}
            if ((si.rip_relative || (si.has_modrm && ((si.modrm >> 6) & 3) == 0 && (si.modrm & 7) == 5)) && (!reloc_table || !base_addr)) return false;
            so += si.len;
        }
        
        memmove(code + offset + exp.len, code + offset + inst->len, *size - offset - inst->len);
        *size += diff;
        if (reloc_table && base_addr) reloc_update(reloc_table, offset + inst->len, diff, code, *size, base_addr, ARCH_X86);
    } else if (exp.len < inst->len) {
        memset(code + offset + exp.len, 0x90, inst->len - exp.len);
    }
    
    memcpy(code + offset, exp.code, exp.len);
    
    x86_inst_t verify;
    if (!decode_x86_withme(code + offset, *size - offset, 0, &verify, NULL) || !verify.valid) {
        memcpy(code + offset, inst->raw, inst->len);
        if (exp.len > inst->len) {
            memmove(code + offset + inst->len, code + offset + exp.len, *size - offset - exp.len);
            *size -= diff;
        }
        return false;
    }
    
    return true;
}

static size_t expand_loop(uint8_t *code, size_t size, size_t max, liveness_state_t *liveness, 
                          chacha_state_t *rng, unsigned intensity, reloc_table_t *reloc, 
                          uint64_t base, bool (*filter)(const x86_inst_t*)) {
    if (!code || !size || !rng) return size;
    size_t cur = size, off = 0;
    while (off < cur && cur < max) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + off, cur - off, 0, &inst, NULL) || !inst.valid || !inst.len) {off++; continue;}
        if ((!filter || filter(&inst)) && (chacha20_random(rng) % 100) < intensity) {
            if (apply_expansion(code, &cur, off, &inst, liveness, rng, reloc, base)) {
                x86_inst_t ni;
                if (decode_x86_withme(code + off, cur - off, 0, &ni, NULL)) {off += ni.len; continue;}
            }
        }
        off += inst.len;
    }
    return cur;
}

size_t expand_code(uint8_t *code, size_t size, size_t max_size,
                   liveness_state_t *liveness, chacha_state_t *rng,
                   unsigned expansion_intensity, reloc_table_t *reloc_table,
                   uint64_t base_addr) {
    return expand_loop(code, size, max_size, liveness, rng, expansion_intensity, reloc_table, base_addr, NULL);
}

/* 3xpand, then expand the expanded code again */
size_t expand_chains(uint8_t *code, size_t size, size_t max_size,
                     liveness_state_t *liveness, chacha_state_t *rng,
                     unsigned chain_depth, unsigned expansion_intensity,
                     reloc_table_t *reloc_table, uint64_t base_addr) {
    if (!code || !size || !rng || !chain_depth) return size;
    size_t cur = size;
    for (unsigned r = 0; r < chain_depth && cur < max_size; r++) {
        size_t start = cur;
        unsigned intensity = expansion_intensity / (r + 1);
        if (intensity < 10) intensity = 10;
        cur = expand_loop(code, cur, max_size, liveness, rng, intensity, reloc_table, base_addr, NULL);
        if (cur == start) break;
    }
    return cur;
}

static bool is_mov_imm(const x86_inst_t *i) {return (i->opcode[0] & 0xF8) == 0xB8 && i->imm != 0;}
static bool is_arith(const x86_inst_t *i) {
    uint8_t op = i->opcode[0];
    if (op == 0x83 && i->has_modrm) {uint8_t rf = modrm_reg(i->modrm); return rf == 0 || rf == 5;}
    if (op == 0xFF && i->has_modrm) {uint8_t rf = modrm_reg(i->modrm); return rf == 0 || rf == 1;}
    return op == 0x01 || op == 0x29;
}

size_t mov_immediates(uint8_t *code, size_t size, size_t max_size,
                      liveness_state_t *liveness, chacha_state_t *rng,
                      unsigned chain_depth) {
    if (!code || !size || !rng || !chain_depth) return size;
    size_t cur = size;
    for (unsigned r = 0; r < chain_depth && cur < max_size; r++) {
        size_t start = cur;
        cur = expand_loop(code, cur, max_size, liveness, rng, 100, NULL, 0, is_mov_imm);
        if (cur == start) break;
    }
    return cur;
}

size_t expand_arithmetic(uint8_t *code, size_t size, size_t max_size,
                         liveness_state_t *liveness, chacha_state_t *rng,
                         unsigned chain_depth) {
    if (!code || !size || !rng || !chain_depth) return size;
    size_t cur = size;
    for (unsigned r = 0; r < chain_depth && cur < max_size; r++) {
        size_t start = cur;
        cur = expand_loop(code, cur, max_size, liveness, rng, 100, NULL, 0, is_arith);
        if (cur == start) break;
    }
    return cur;
}
