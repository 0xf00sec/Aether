#include <wisp.h>

static void write_rel32(uint8_t *p, int32_t v) {memcpy(p, &v, sizeof(v));}
static void write_u64(uint8_t *p, uint64_t v) {memcpy(p, &v, sizeof(v));}

void init_engine(engine_context_t *ctx) {
    if (!ctx) return;
    ctx->debug_code = NULL;
    ctx->debug_code_size = 0;
    ctx->unsafe_mode = false;
}

void drop_mut(muttt_t *log, size_t offset, size_t length,  
                     mutx_type_t type, uint32_t gen, const char *desc) {
    if (!log) return;
    
    if (log->count >= log->cap) {
        size_t new_cap = log->cap ? log->cap * 2 : 4;
        mutx_entry_t *tmp = realloc(log->entries, new_cap * sizeof(mutx_entry_t));
        if (!tmp) {
            return;
        }
        log->entries = tmp;
        log->cap = new_cap;
    }

    mutx_entry_t *entry = &log->entries[log->count++];
    entry->offset = offset;
    entry->length = length;
    entry->type = type;
    entry->gen = gen;
    strncpy(entry->des, desc, 63);
    entry->des[63] = '\0';
}

int init_mut(muttt_t *log) {
    if (!log) return 0;
    
    log->cap = 0;
    log->count = 0;
    log->entries = NULL;
    
    log->entries = malloc(64 * sizeof(mutx_entry_t));
    if (!log->entries) {
        return 0;
    }
    
    log->cap = 64;
    log->count = 0;
    
    memset(log->entries, 0, 64 * sizeof(mutx_entry_t));
    
    return 1;
}

void freeme(muttt_t *log) {
    if (!log) return;
    
    if (log->entries) {
        free(log->entries);
    }
    
    log->entries = NULL;
    log->cap = 0;
    log->count = 0;
}

void boot_live(liveness_state_t *state) {
    if (!state) return;
    
    memset(state, 0, sizeof(*state));
    state->num_regs = 16;

    for (int i = 0; i < state->num_regs; i++) {
        state->regs[i].reg = i;
        state->regs[i].iz_live = false;
        state->regs[i].iz_vol = (i <= 5); 
        state->regs[i].def_offset = 0;
        state->regs[i].last_use = 0;
    }
}

void pulse_live(liveness_state_t *state, size_t offset, const void *inst_ptr) {
    if (!state || !inst_ptr) return;
    
#if defined(ARCH_X86)
    const x86_inst_t *inst = (const x86_inst_t *)inst_ptr;
    if (!inst || !inst->valid) return;
    
    if (inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        
        if (reg >= 16 || rm >= 16) return;
        
        switch (inst->opcode[0]) {
            case 0x89: // MOV reg->rm
                if (rm < 16) {
                    state->regs[rm].iz_live = true;
                    state->regs[rm].def_offset = offset;
                }
                if (reg < 16) {
                    state->regs[reg].last_use = offset;
                }
                break;
            case 0x8B: // MOV rm->reg
                if (reg < 16) {
                    state->regs[reg].iz_live = true;
                    state->regs[reg].def_offset = offset;
                }
                if (rm < 16) {
                    state->regs[rm].last_use = offset;
                }
                break;
            case 0x01: case 0x03: // ADD
            case 0x29: case 0x2B: // SUB
            case 0x31: case 0x33: // XOR
            case 0x21: case 0x23: // AND
            case 0x09: case 0x0B: // OR
                if (reg < 16) {
                    state->regs[reg].last_use = offset;
                    state->regs[reg].iz_live = true;
                    state->regs[reg].def_offset = offset;
                }
                if (rm < 16) {
                    state->regs[rm].last_use = offset;
                }
                break;
            default:
                if (reg < 16) state->regs[reg].last_use = offset;
                if (rm < 16) state->regs[rm].last_use = offset;
                break;
        }
    }
    
    if ((inst->opcode[0] & 0xF8) == 0xB8) { // MOV reg, imm
        uint8_t reg = inst->opcode[0] & 0x7;
        if (reg < 16) {
            state->regs[reg].iz_live = true;
            state->regs[reg].def_offset = offset;
        }
    }
    
    if ((inst->opcode[0] & 0xF8) == 0x50) { // PUSH reg
        uint8_t reg = inst->opcode[0] & 0x7;
        if (reg < 16) {
            state->regs[reg].last_use = offset;
        }
    } else if ((inst->opcode[0] & 0xF8) == 0x58) { // POP reg
        uint8_t reg = inst->opcode[0] & 0x7;
        if (reg < 16) {
            state->regs[reg].iz_live = true;
            state->regs[reg].def_offset = offset;
        }
    }
#endif
}

uint8_t jack_reg(const liveness_state_t *state, uint8_t original_reg, 
                                              size_t current_offset, chacha_state_t *rng) {
    if (!state || !rng) return original_reg;
    
    if (original_reg == 4 || original_reg == 5) { // RSP/RBP
        return original_reg;
    }
    
    if (original_reg >= 16) {
        return original_reg;
    }
    
    uint8_t candidates[8] = {0};
    uint8_t num_candidates = 0;
    
    for (uint8_t reg = 0; reg < 8; reg++) {
        if (reg == original_reg) continue;
        if (reg == 4 || reg == 5) continue; // Never use RSP/RBP
        
        bool is_safe = false;
        if (!state->regs[reg].iz_live) {
            is_safe = true;
        } else if (state->regs[reg].last_use > 0 && 
                   current_offset > state->regs[reg].last_use &&
                   (current_offset - state->regs[reg].last_use) > 32) {
            is_safe = true;
        }
        
        if (is_safe && !state->regs[reg].iz_vol) {
            candidates[num_candidates++] = reg;
        }
    }
    
    if (num_candidates == 0) {
        for (uint8_t reg = 0; reg < 8; reg++) {
            if (reg == original_reg) continue;
            if (reg == 4 || reg == 5) continue;
            
            if (!state->regs[reg].iz_live || 
                (current_offset > state->regs[reg].last_use &&
                 (current_offset - state->regs[reg].last_use) > 16)) {
                candidates[num_candidates++] = reg;
            }
        }
    }
    
    return (num_candidates > 0) ? 
           candidates[chacha20_random(rng) % num_candidates] : 
           original_reg;
}

__attribute__((always_inline)) inline bool is_op_ok(const uint8_t *code) {
#if defined(ARCH_X86)
    x86_inst_t inst;
    if (!decode_x86_withme(code, 16, 0, &inst, NULL)) return false;
    return !inst.ring0 && inst.valid;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (!decode_arm64(code, &inst)) return false;
    return !inst.ring0 && inst.valid;
#else
    return false;
#endif
}

size_t snap_len(const uint8_t *code, size_t maxlen) {
#if defined(ARCH_X86)
    if (maxlen == 0) return 0;
    x86_inst_t inst;
    return decode_x86_withme(code, maxlen, 0, &inst, NULL) ? inst.len : 0;
#elif defined(ARCH_ARM)
    if (maxlen < 4) return 0;
    arm64_inst_t inst;
    return decode_arm64(code, &inst) ? 4 : 0;
#else
    return 0;
#endif
}

__attribute__((always_inline)) inline bool is_chunk_ok(const uint8_t *code, size_t max_len) {
    if (!code || max_len == 0) return false;

    size_t offset = 0;
    size_t valid_count = 0;
    size_t invalid_count = 0;

    const size_t max_invalid_ratio = max_len / 8; 
    const size_t max_single_invalid = max_len / 20; 

    while (offset < max_len) {
        size_t len = snap_len(code + offset, max_len - offset);

        if (!len) {
            invalid_count++;
            if (invalid_count > max_invalid_ratio) return false;
            offset++;
            continue;
        }

        if (offset + len > max_len) return false;

        if (is_op_ok(code + offset)) {
            valid_count++;
            invalid_count = 0; 
        } else {
            invalid_count++;
            if (invalid_count > max_single_invalid) return false;
        }

        offset += len;
    }
    return valid_count > 0 && (invalid_count * 10 < valid_count);
}

__attribute__((always_inline)) inline void forge_ghost_x86(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;
    
    uint8_t reg1 = chacha20_random(rng) % 8;
    uint8_t reg2 = chacha20_random(rng) % 8;
    uint8_t reg3 = chacha20_random(rng) % 8;
    while (reg2 == reg1) reg2 = chacha20_random(rng) % 8;
    while (reg3 == reg1 || reg3 == reg2) reg3 = chacha20_random(rng) % 8;

    uint8_t imm8 = chacha20_random(rng) & 0xFF;
    uint64_t imm64 = ((uint64_t)chacha20_random(rng) << 32) | chacha20_random(rng);

    switch (chacha20_random(rng) % 12) {
        case 0: { /* XOR + TEST + JZ */
            buf[0] = 0x48; buf[1] = 0x31; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            write_rel32(buf + 8, 12);
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
        case 8: { /* MOV + ADD + CMP + JNE (64-bit immediate) */
            buf[0] = 0x48; buf[1] = 0xB8 | reg1;
            write_rel32(buf + 2, imm64);
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

__attribute__((always_inline)) inline void forge_ghost_arm(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;
    
    uint8_t reg1 = chacha20_random(rng) % 31; 
    uint8_t reg2 = chacha20_random(rng) % 31;  
    uint8_t reg3 = chacha20_random(rng) % 31;  
    
    while (reg2 == reg1) reg2 = chacha20_random(rng) % 31;
    while (reg3 == reg1 || reg3 == reg2) reg3 = chacha20_random(rng) % 31;
    
    switch(chacha20_random(rng) % 6) {
        case 0: { 
            *(uint32_t*)buf = 0xD2800000 | (reg1 << 5);
            *(uint32_t*)(buf + 4) = 0xB4000000 | (reg1 << 5) | ((value & 0x7FFFF) << 5);
            *len = 8;
            break;
        }
        case 1: { 
            *(uint32_t*)buf = 0xEB000000 | (reg1 << 16) | (reg1 << 5);
            *(uint32_t*)(buf + 4) = 0x54000000 | ((value & 0x7FFFF) << 5);
            *len = 8;
            break;
        }
        case 2: { 
            *(uint32_t*)buf = 0xEA000000 | (reg1 << 16) | (reg1 << 5);
            *(uint32_t*)(buf + 4) = 0x54000000 | ((value & 0x7FFFF) << 5);
            *len = 8;
            break;
        }
        case 3: { 
            *(uint32_t*)buf = 0x72000000 | (reg1 << 5) | (reg1 << 16);
            *(uint32_t*)(buf + 4) = 0x54000001 | ((value & 0x7FFFF) << 5);
            *len = 8;
            break;
        }
        case 4: { 
            *(uint32_t*)buf = 0xCB000000 | (reg1 << 5) | (reg1 << 16);
            *(uint32_t*)(buf + 4) = 0xB4000000 | (reg1 << 5) | ((value & 0x7FFFF) << 5);
            *len = 8;
            break;
        }
        case 5: { 
            *(uint32_t*)buf = 0xCA000000 | (reg1 << 5) | (reg1 << 16) | (reg1 << 10);
            *(uint32_t*)(buf + 4) = 0xB5000000 | (reg1 << 5) | ((value & 0x7FFFF) << 5);
            *len = 8;
            break;
        }
    }
}

__attribute__((always_inline)) inline void forge_ghost(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
#if defined(ARCH_X86)
    forge_ghost_x86(buf, len, value, rng);
#elif defined(ARCH_ARM)
    forge_ghost_arm(buf, len, value, rng);
#endif
}

void spew_trash(uint8_t *buf, size_t *len, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;

    const uint8_t usable_regs[] = {0,1,2,3,8,9,10,11,12,13,14,15};
    size_t reg_count = sizeof(usable_regs) / sizeof(usable_regs[0]);

    uint8_t r1 = usable_regs[chacha20_random(rng) % reg_count];
    uint8_t r2;
    do { r2 = usable_regs[chacha20_random(rng) % reg_count]; } while (r2 == r1);

    uint8_t choice = chacha20_random(rng) % 20;

    switch(choice) {
        case 0: buf[0] = 0x90; *len = 1; break;                     
        case 1: buf[0]=0x66; buf[1]=0x90; *len=2; break;             
        case 2: buf[0]=0x48; buf[1]=0x89; buf[2]=0xC0 | (r1<<3) | r2; *len=3; break;
        case 3: buf[0]=0x48; buf[1]=0x31; buf[2]=0xC0 | (r1<<3) | r1; *len=3; break;
        case 4: buf[0]=0x48; buf[1]=0x8D; buf[2]=0x40 | r1; buf[3]=0x00; *len=4; break;
        case 5: buf[0]=0x48; buf[1]=0x83; buf[2]=0xC0 | r1; buf[3]=0x00; *len=4; break;
        case 6: buf[0]=0x48; buf[1]=0x83; buf[2]=0xE8; buf[3]=r1; *len=4; break;
        case 7: 
            if (r1 < 8) { buf[0]=0x50|r1; buf[1]=0x58|r1; *len=2; } 
            else { buf[0]=0x90; *len=1; } 
            break;
        case 8: buf[0]=0x48; buf[1]=0x85; buf[2]=0xC0 | (r1<<3) | r1; *len=3; break;
        case 9: buf[0]=0x48; buf[1]=0x39; buf[2]=0xC0 | (r1<<3) | r1; *len=3; break;
        case 10: buf[0]=0x48; buf[1]=0x09; buf[2]=0xC0 | (r1<<3) | r1; *len=3; break;
        case 11: buf[0]=0x48; buf[1]=0x21; buf[2]=0xC0 | (r1<<3) | r1; *len=3; break;
        case 12: buf[0]=0x48; buf[1]=0x87; buf[2]=0xC0 | (r1<<3) | r1; *len=3; break;
        case 13: buf[0]=0x0F; buf[1]=0x1F; buf[2]=0x00; *len=3; break;
        case 14: buf[0]=0x0F; buf[1]=0x1F; buf[2]=0x40; buf[3]=0x00; *len=4; break;
        case 15: buf[0]=0x48; buf[1]=0x89; buf[2]=0xC0 | (r1<<3) | r2; *len=3; break;
        case 16: buf[0]=0x48; buf[1]=0x31; buf[2]=0xC0 | (r1<<3) | r2; *len=3; break;
        case 17: buf[0]=0x48; buf[1]=0x01; buf[2]=0xC0 | (r2<<3) | r1; *len=3; break;
        case 18: buf[0]=0x48; buf[1]=0x29; buf[2]=0xC0 | (r2<<3) | r1; *len=3; break;
        case 19: buf[0]=0x0F; buf[1]=0x1F; buf[2]=0x40 | (chacha20_random(rng) % 8); buf[3]=0x00; *len=4; break;
    }
}

bool sketch_flow(uint8_t *code, size_t size, flowmap *cfg) {
    if (!code || !cfg || size < 16) {
        if (cfg) *cfg = (flowmap){0};
        return false;
    }

    const size_t initial_cap = 1024;
    cfg->blocks = calloc(initial_cap, sizeof(blocknode));
    if (!cfg->blocks) return false;

    cfg->num_blocks = 0;
    cfg->cap_blocks = initial_cap;

    size_t offset = 0;
    size_t block_start = 0;
    bool in_block = false;

    while (offset < size) {
        size_t len = snap_len(code + offset, size - offset);
        if (!len || offset + len > size) { offset++; continue; }

        bool is_control_flow = false;

#if defined(ARCH_X86)
        x86_inst_t inst;
        if (decode_x86_withme(code + offset, size - offset, 0, &inst, NULL)) {
            uint8_t op = inst.opcode[0];
            is_control_flow = (op == 0xE8 || op == 0xE9 || (op >= 0x70 && op <= 0x7F) || 
                               (op == 0x0F && inst.opcode_len > 1 && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) || 
                               op == 0xC3 || op == 0xC2);
        }
#elif defined(ARCH_ARM)
        arm64_inst_t inst;
        if (decode_arm64(code + offset, &inst)) {
            is_control_flow = inst.type != ARM_OP_NONE;
        }
#endif

        if (!in_block) { block_start = offset; in_block = true; }

        if (is_control_flow) {
            if (cfg->num_blocks < cfg->cap_blocks) {
                cfg->blocks[cfg->num_blocks++] = (blocknode){block_start, offset + len, cfg->num_blocks};
            }
            in_block = false;
        }
        offset += len;
    }

    if (in_block && cfg->num_blocks < cfg->cap_blocks) {
        cfg->blocks[cfg->num_blocks++] = (blocknode){block_start, offset, cfg->num_blocks};
    }

    cfg->entry_block = 0;
    cfg->exit_block = cfg->num_blocks ? cfg->num_blocks - 1 : 0;

    return true;
}

void flatline_flow(uint8_t *code, size_t size, flowmap *cfg, chacha_state_t *rng) {
    if (!code || !cfg || !rng || cfg->num_blocks < 3) return;
    
    patch_t patch[64]; 
    size_t np = 0;
    size_t out = 0;
    size_t max_blocks = cfg->num_blocks;
    
    if (max_blocks > 0 && max_blocks > (SIZE_MAX - 128 - size) / 8) {
        return; // overflow
    }
    
    size_t buf_sz = size + 128 + max_blocks * 8;
    uint8_t *nbuf = malloc(buf_sz);
    if (!nbuf) return;
    
    size_t *bmap = malloc(max_blocks * sizeof(size_t));
    if (!bmap) { free(nbuf); return; }
    
    size_t *order = malloc(max_blocks * sizeof(size_t));
    if (!order) { free(nbuf); free(bmap); return; }
    
    for (size_t i = 0; i < max_blocks; i++) order[i] = i;
    
    for (size_t i = max_blocks - 1; i > 0; i--) {
        size_t j = 1 + (chacha20_random(rng) % i); // keep block 0 pinned at index 0
        size_t t = order[i]; order[i] = order[j]; order[j] = t;
    }
    
    if (order[0] != 0) {
        size_t idx0 = 0;
        for (size_t k = 1; k < max_blocks; k++) { 
            if (order[k] == 0) { idx0 = k; break; } 
        }
        size_t t = order[0]; order[0] = order[idx0]; order[idx0] = t;
    }

    for (size_t i = 0; i < max_blocks; i++) {
        size_t bi = order[i];
        blocknode *b = &cfg->blocks[bi];
        bmap[bi] = out;
        size_t blen = b->end - b->start;
        
        memcpy(nbuf + out, code + b->start, blen);

        if (blen > 0) {
            x86_inst_t inst;
            size_t back = blen < 16 ? blen : 16;
            
            if (decode_x86_withme(nbuf + out + blen - back, back, 0, &inst, NULL) && 
                inst.valid && inst.len && blen >= inst.len) {
                
                uint8_t *p = nbuf + out + blen - inst.len;
                size_t instruction_addr_in_new_buffer = p - nbuf;
                uint64_t current_absolute_target = 0;
                bool should_patch = false;

                if (inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9) { // CALL rel32 / JMP rel32
                    current_absolute_target = instruction_addr_in_new_buffer + inst.len + (int32_t)inst.imm;
                    should_patch = true;
                } 
                else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) { // Jcc rel8
                    current_absolute_target = instruction_addr_in_new_buffer + 2 + (int8_t)inst.opcode[1];
                    should_patch = true;
                } 
                else if (inst.opcode[0] == 0x0F && inst.opcode_len > 1 && 
                         inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) { // Jcc rel32
                    current_absolute_target = instruction_addr_in_new_buffer + 6 + (int32_t)inst.imm;
                    should_patch = true;
                }
                else if (inst.opcode[0] == 0xEB) { // JMP rel8
                    current_absolute_target = instruction_addr_in_new_buffer + 2 + (int8_t)inst.imm;
                    should_patch = true;
                }

                if (should_patch && np < (sizeof(patch)/sizeof(patch[0]))) {
                    patch[np].off = instruction_addr_in_new_buffer;
                    patch[np].blki = bi;
                    patch[np].abs_target = current_absolute_target;
                    patch[np].inst_len = inst.len;
                    
                    if (inst.opcode[0] == 0xE8) patch[np].typ = 2; // CALL
                    else if (inst.opcode[0] == 0xE9) patch[np].typ = 1; // JMP
                    else if (inst.opcode[0] == 0xEB) patch[np].typ = 5; // JMP rel8
                    else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) patch[np].typ = 3; // Jcc rel8
                    else if (inst.opcode[0] == 0x0F) patch[np].typ = 4; // Jcc rel32
                    
                    np++;
                }
            }
        }
        out += blen;
    }

    for (size_t i = 0; i < np; i++) {
        patch_t *p = &patch[i];
        size_t src = p->off;

        size_t tgt_blk = (size_t)-1;
        for (size_t k = 0; k < max_blocks; k++) {
            if (p->abs_target >= cfg->blocks[k].start && p->abs_target < cfg->blocks[k].end) {
                tgt_blk = k;
                break;
            }
        }
        
        if (tgt_blk == (size_t)-1) {
            continue;
        }

        size_t new_tgt = bmap[tgt_blk];
        int32_t new_disp = 0;

        switch (p->typ) {
            case 1: // JMP rel32 (opcode E9)
            case 2: // CALL rel32 (opcode E8)
                new_disp = (int32_t)(new_tgt - (src + 5)); // 5 bytes for E9/E9 + rel32
                if (src + 1 + sizeof(int32_t) <= buf_sz) {
                    *(int32_t*)(nbuf + src + 1) = new_disp;
                }
                break;
                
            case 3: // Jcc rel8 (opcode 70-7F)
                new_disp = (int8_t)(new_tgt - (src + 2)); // 2 bytes for Jcc + rel8
                if (src + 1 < buf_sz) {
                    nbuf[src + 1] = (uint8_t)new_disp;
                }
                break;
                
            case 4: // Jcc rel32 (opcode 0F 80-8F)
                new_disp = (int32_t)(new_tgt - (src + 6)); // 6 bytes for 0F + opcode + rel32
                if (src + 2 + sizeof(int32_t) <= buf_sz) {
                    *(int32_t*)(nbuf + src + 2) = new_disp;
                }
                break;
                
            case 5: // JMP rel8 (opcode EB)
                new_disp = (int8_t)(new_tgt - (src + 2)); // 2 bytes for EB + rel8
                if (src + 1 < buf_sz) {
                    nbuf[src + 1] = (uint8_t)new_disp;
                }
                break;
        }

        x86_inst_t test_inst;
        if (!decode_x86_withme(nbuf + src, 16, 0, &test_inst, NULL) || !test_inst.valid) {
            // Patch validation failed, skip
        }
    }

    for (size_t i = 0; i < np; i++) {
        patch_t *p = &patch[i];
        x86_inst_t inst;
        if (!decode_x86_withme(nbuf + p->off, 16, 0, &inst, NULL) || !inst.valid) {
            free(nbuf); free(bmap); free(order);
            return;
        }
    }

    if (out <= size) {
        memcpy(code, nbuf, out);
        memset(code + out, 0, size - out);
    }
    
    free(nbuf); 
    free(bmap); 
    free(order);
}

#if defined(ARCH_X86)
static uint8_t random_gpr(chacha_state_t *rng) {
    if (!rng) return 0;
    return chacha20_random(rng) % 8;
}

static void emit_tr(uint8_t *buf, size_t *off, uint64_t target, bool is_call) {
    if (!buf || !off) return;
    
    /* mov rax, imm64 ; jmp/call rax */
    buf[(*off)++] = 0x48; buf[(*off)++] = 0xB8;
    memcpy(buf + *off, &target, 8);
    *off += 8;
    if (is_call) { buf[(*off)++] = 0xFF; buf[(*off)++] = 0xD0; } // call rax
    else         { buf[(*off)++] = 0xFF; buf[(*off)++] = 0xE0; } // jmp rax
}

void shuffle_blocks(uint8_t *code, size_t size, void *rng) {
    if (!code || !rng) return;
    
    flowmap cfg;
    if (!sketch_flow(code, size, &cfg)) return;
    if (cfg.num_blocks < 2) { free(cfg.blocks); return; }

    size_t nb = cfg.num_blocks;
    size_t *order = malloc(nb * sizeof(size_t));
    if (!order) { free(cfg.blocks); return; }
    
    for (size_t i=0;i<nb;i++) order[i]=i;
    for (size_t i=nb-1;i>1;i--) {
        size_t j = 1 + (chacha20_random(rng)%i);
        size_t t=order[i]; order[i]=order[j]; order[j]=t;
    }

    uint8_t *nbuf = malloc(size*2);
    if (!nbuf) { free(order); free(cfg.blocks); return; }
    
    size_t *new_off = malloc(nb * sizeof(size_t));
    if (!new_off) { free(order); free(nbuf); free(cfg.blocks); return; }
    
    size_t out=0;
    for (size_t oi=0; oi<nb; oi++) {
        size_t bi=order[oi];
        blocknode *b=&cfg.blocks[bi];
        size_t blen=b->end-b->start;
        memcpy(nbuf+out, code+b->start, blen);
        new_off[bi]=out;
        out+=blen;
    }

    size_t tramp_base = out;
    size_t tramp_off = tramp_base;

    for (size_t oi=0; oi<nb; oi++) {
        size_t bi=order[oi];
        blocknode *b=&cfg.blocks[bi];
        size_t blen=b->end-b->start;
        size_t off=new_off[bi];
        size_t cur=0;
        while (cur<blen) {
            x86_inst_t inst;
            if (!decode_x86_withme(nbuf+off+cur, blen-cur, 0, &inst, NULL) || !inst.valid) { cur++; continue; }
            size_t inst_off = off+cur;
            int typ=0;
            if (inst.opcode[0]==0xE8) typ=2;
            else if (inst.opcode[0]==0xE9) typ=1;
            else if (inst.opcode[0]==0xEB) typ=5;
            else if (inst.opcode[0]>=0x70 && inst.opcode[0]<=0x7F) typ=3;
            else if (inst.opcode[0]==0x0F && inst.opcode_len>1 && inst.opcode[1]>=0x80) typ=4;
            if (!typ) { cur+=inst.len; continue; }

            int64_t oldtgt=0;
            if (typ==1||typ==2) oldtgt=inst_off+inst.len+(int32_t)inst.imm;
            else if (typ==3||typ==5) oldtgt=inst_off+inst.len+(int8_t)inst.imm;
            else if (typ==4) oldtgt=inst_off+inst.len+(int32_t)inst.imm;

            size_t tgt_blk=SIZE_MAX;
            for (size_t k=0;k<nb;k++) {
                if (oldtgt>=cfg.blocks[k].start && oldtgt<cfg.blocks[k].end) { tgt_blk=k; break; }
            }

            if (tgt_blk!=SIZE_MAX) {
                int32_t rel=0;
                size_t tgt=new_off[tgt_blk];
                if (typ==1||typ==2) { rel=(int32_t)(tgt-(inst_off+inst.len)); memcpy(nbuf+inst_off+1,&rel,4); }
                else if (typ==3||typ==5) {
                    int32_t d=(int32_t)(tgt-(inst_off+inst.len));
                    if (d>=-128 && d<=127) nbuf[inst_off+1]=(uint8_t)d;
                    else {
                        if (typ==3) { uint8_t cc=nbuf[inst_off]&0x0F; nbuf[inst_off]=0x0F; nbuf[inst_off+1]=0x80|cc; rel=(int32_t)(tgt-(inst_off+6)); memcpy(nbuf+inst_off+2,&rel,4); }
                        else { nbuf[inst_off]=0xE9; rel=(int32_t)(tgt-(inst_off+5)); memcpy(nbuf+inst_off+1,&rel,4); }
                    }
                }
                else if (typ==4) { rel=(int32_t)(tgt-(inst_off+inst.len)); memcpy(nbuf+inst_off+2,&rel,4); }
            } else {
                bool is_call=(typ==2);
                emit_tr(nbuf,&tramp_off,(uint64_t)oldtgt,is_call);
                size_t tramp_loc=tramp_off- (is_call?15:12);
                int32_t rel=(int32_t)(tramp_loc-(inst_off+ (typ==2||typ==1?5:2)));
                if (typ==2||typ==1) { nbuf[inst_off]=is_call?0xE8:0xE9; memcpy(nbuf+inst_off+1,&rel,4); }
                else if (typ==3) { uint8_t cc=nbuf[inst_off]&0x0F; nbuf[inst_off]=0x0F; nbuf[inst_off+1]=0x80|cc; rel=(int32_t)(tramp_loc-(inst_off+6)); memcpy(nbuf+inst_off+2,&rel,4); }
                else if (typ==4) { rel=(int32_t)(tramp_loc-(inst_off+6)); memcpy(nbuf+inst_off+2,&rel,4); }
                else if (typ==5) { nbuf[inst_off]=0xE9; rel=(int32_t)(tramp_loc-(inst_off+5)); memcpy(nbuf+inst_off+1,&rel,4); }
            }
            cur+=inst.len;
        }
    }

    size_t final_size=tramp_off;
    if (final_size<=size) {
        memcpy(code,nbuf,final_size);
        if (final_size<size) memset(code+final_size,0,size-final_size);
    }

    free(order); free(new_off); free(nbuf); free(cfg.blocks);
}

static inline bool is_control_flow(const x86_inst_t *i) {
    if (!i) return false;
    uint8_t op = i->opcode[0];
    if (op == 0xE8 || op == 0xE9 || op == 0xEB) return true; // call/jmp/shortjmp
    if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA) return true; // ret
    if (op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) return true;
    if (op == 0xFF) return true;
    return false;
}

static inline uint16_t inst_reg_mask(const x86_inst_t *i) {
    if (!i) return 0;
    
    uint16_t m = 0;
    if (i->has_modrm) {
        uint8_t r = modrm_reg(i->modrm) & 7;
        uint8_t rm = modrm_rm(i->modrm) & 7;
        m |= (1u << r) | (1u << rm);
    }
    uint8_t op = i->opcode[0];
    if ((op & 0xF8) == 0xB8) { // mov reg, imm -> writes reg
        uint8_t reg = op & 0x7;
        m |= (1u << reg);
    }
    if ((op & 0xF8) == 0x50) { // push/pop family touches reg (and rsp)
        uint8_t reg = op & 0x7;
        m |= (1u << reg);
    }
    if ((op & 0xF8) == 0x40) {
        uint8_t reg = op & 0x7;
        m |= (1u << reg);
    }
    if (i->has_modrm && (op == 0x83 || op == 0x81 || op == 0x69 || op == 0x6B)) {
        uint8_t rm = modrm_rm(i->modrm) & 7;
        m |= (1u << rm);
    }
    return m;
}

static inline bool independent_inst(const x86_inst_t *a, const x86_inst_t *b) {
    if (!a || !b) return false;
    if (is_control_flow(a) || is_control_flow(b)) return false;
    uint16_t ma = inst_reg_mask(a);
    uint16_t mb = inst_reg_mask(b);
    if (ma & mb) return false;
    return true;
}

static inline bool swap_adjacent_ranges(uint8_t *code, size_t size, size_t a_off, size_t a_len, size_t b_len) {
    if (a_off + a_len + b_len > size) return false;
    uint8_t *tmp = (uint8_t*)malloc(a_len);
    if (!tmp) return false;
    memcpy(tmp, code + a_off, a_len);
    memmove(code + a_off, code + a_off + a_len, b_len); // move B forward into A's place
    memcpy(code + a_off + b_len, tmp, a_len);
    free(tmp);
    return true;
}

static int build_instruction_window(uint8_t *code, size_t size, size_t offset, 
                                   x86_inst_t *win, size_t *win_offs, int max_window) {
    if (!code || !win || !win_offs) return 0;
    
    int win_cnt = 0;
    size_t scan = offset;

    while (scan < size && win_cnt < max_window) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + scan, size - scan, 0, &inst, NULL) || 
            !inst.valid || inst.len == 0 || scan + inst.len > size) {
            scan++;
            continue;
        }
        win[win_cnt] = inst;
        win_offs[win_cnt] = scan;
        win_cnt++;
        scan += inst.len;
        if (is_control_flow(&inst)) break;
    }
    return win_cnt;
}

static void window_reordering(uint8_t *code, size_t size, x86_inst_t *win, 
                                     size_t *win_offs, int win_cnt, chacha_state_t *rng,
                                     unsigned mutation_intensity, muttt_t *log, unsigned gen) {
    if (!code || !win || !win_offs || !rng) return;
    
    for (int i = 0; i + 1 < win_cnt; ++i) {
        size_t a_off = win_offs[i];
        size_t a_len = win[i].len;
        size_t b_off = win_offs[i+1];
        size_t b_len = win[i+1].len;
        
        if (b_off != a_off + a_len) {
            continue;
        }
        
        if (independent_inst(&win[i], &win[i+1])) {
            if ((chacha20_random(rng) % 10) < (mutation_intensity / 2 + 1)) {
                if (swap_adjacent_ranges(code, size, a_off, a_len, b_len)) {
                    win_offs[i] = a_off;
                    win_offs[i+1] = a_off + b_len;
                }
            }
        }
    }
}

static void scramble_x86(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen,
                        muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity) {
    if (!code || !rng) return;
    
    size_t offset = 0;

    if (liveness) boot_live(liveness);

    while (offset < size) {
        const int WINDOW_MAX = 8;
        x86_inst_t win[WINDOW_MAX];
        size_t win_offs[WINDOW_MAX];
        
        int win_cnt = build_instruction_window(code, size, offset, win, win_offs, WINDOW_MAX);
        
        window_reordering(code, size, win, win_offs, win_cnt, rng, 
                                mutation_intensity, log, gen);

        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0 || offset + inst.len > size) {
            offset++;
            continue;
        }

        if (liveness) pulse_live(liveness, offset, &inst);

        bool mutated = false;

        if (inst.has_modrm && inst.len <= 8) {
            uint8_t reg = modrm_reg(inst.modrm);
            uint8_t rm = modrm_rm(inst.modrm);
            uint8_t new_reg = reg;
            uint8_t new_rm = rm;

            if (liveness) {
                new_reg = jack_reg(liveness, reg, offset, rng);
                new_rm = jack_reg(liveness, rm, offset, rng);
            } else {
                new_reg = random_gpr(rng);
                new_rm = random_gpr(rng);
            }

            uint8_t orig_modrm = inst.modrm;

            if ((inst.opcode[0] & 0xF8) != 0x50 && (inst.opcode[0] & 0xF8) != 0x58) {
                for (int i = 0; i < 3 && !mutated; i++) {
                    uint8_t temp_modrm = orig_modrm;
                    if (i == 0) {
                        temp_modrm = (orig_modrm & 0xC7) | (new_reg << 3);
                    } else if (i == 1) {
                        temp_modrm = (orig_modrm & 0xF8) | new_rm;
                    } else {
                        temp_modrm = (orig_modrm & 0xC0) | (new_reg << 3) | new_rm;
                    }

                    size_t modrm_offset = offset + inst.opcode_len;
                    uint8_t orig_byte = code[modrm_offset];
                    code[modrm_offset] = temp_modrm;
                    if (is_op_ok(code + offset)) {
                        mutated = true;
                    } else {
                        code[modrm_offset] = orig_byte;
                    }
                }
            }
        }
        if (!mutated) {
            if (inst.opcode[0] == 0x31 && inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm)) {
                uint8_t reg = modrm_reg(inst.modrm);
                if (chacha20_random(rng) % 2) {
                    code[offset] = 0x29;
                } else {
                    code[offset] = 0xB8 + reg;
                    if (offset + 5 <= size) memset(code + offset + 1, 0, 4);
                }
                if (!is_op_ok(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                } else {
                    mutated = true;
                }
            }
            else if ((inst.opcode[0] & 0xF8) == 0xB8 && inst.imm == 0) {
                uint8_t reg = inst.opcode[0] & 0x7;
                switch(chacha20_random(rng) % 3) {
                    case 0:
                        code[offset] = 0x31;
                        code[offset+1] = 0xC0 | (reg << 3) | reg;
                        break;
                    case 1:
                        code[offset] = 0x83;
                        code[offset+1] = 0xE0 | reg;
                        code[offset+2] = 0x00;
                        break;
                    case 2:
                        code[offset] = 0x29;
                        code[offset+1] = 0xC0 | (reg << 3) | reg;
                        break;
                }
                if (!is_op_ok(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                } else mutated = true;
            }
            else if (inst.opcode[0] == 0x83 && inst.has_modrm && inst.raw[2] == 0x01) {
                uint8_t reg = modrm_rm(inst.modrm);
                if (chacha20_random(rng) % 2) {
                    code[offset] = 0x48 + reg;
                    if (offset + 1 < size && inst.len > 1) {
                        size_t fill_len = (inst.len - 1 < size - offset - 1) ? inst.len - 1 : size - offset - 1;
                        if (fill_len > 0) memset(code + offset + 1, 0x90, fill_len);
                    }
                } else {
                    if (offset + 4 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x8D;
                        code[offset+2] = 0x40 | (reg << 3) | reg;
                        code[offset+3] = 0x01;
                        if (offset + 4 < size && inst.len > 4) {
                            size_t fill_len = (inst.len - 4 < size - offset - 4) ? inst.len - 4 : size - offset - 4;
                            if (fill_len > 0) memset(code + offset + 4, 0x90, fill_len);
                        }
                    }
                }
                if (!is_op_ok(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                } else mutated = true;
            }
            else if (inst.opcode[0] == 0x8D && inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == rm) {
                    if (chacha20_random(rng) % 2) code[offset] = 0x89;
                    else code[offset] = 0x87;
                    if (!is_op_ok(code + offset)) code[offset] = 0x8D;
                    else mutated = true;
                }
            }
            else if (inst.opcode[0] == 0x85 && inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == rm) {
                    if (chacha20_random(rng) % 2) code[offset] = 0x39;
                    else code[offset] = 0x21;
                    if (!is_op_ok(code + offset)) code[offset] = 0x85;
                    else mutated = true;
                }
            }
            else if ((inst.opcode[0] & 0xF8) == 0x50) {
                uint8_t reg = inst.opcode[0] & 0x07;
                if (chacha20_random(rng) % 2) {
                    code[offset] = 0x58 | reg;
                } else {
                    if (offset + 8 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x83; code[offset+2] = 0xEC; code[offset+3] = 0x08;
                        code[offset+4] = 0x48; code[offset+5] = 0x89; code[offset+6] = 0x04; code[offset+7] = 0x24;
                        if (offset + 8 < size && inst.len > 8) {
                            size_t fill_len = (inst.len - 8 < size - offset - 8) ? inst.len - 8 : size - offset - 8;
                            if (fill_len > 0) memset(code + offset + 8, 0x90, fill_len);
                        }
                    }
                }
                if (!is_op_ok(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                } else mutated = true;
            }
        }

        if (!mutated && (chacha20_random(rng) % 10) < mutation_intensity) {
            uint8_t opq_buf[64];
            size_t opq_len;
            uint32_t target_value = chacha20_random(rng);
            forge_ghost(opq_buf, &opq_len, target_value, rng);

            uint8_t junk_buf[32];
            size_t junk_len;
            spew_trash(junk_buf, &junk_len, rng);

            if (opq_len + junk_len <= size - offset && offset + inst.len <= size) {
                size_t move_len = size - offset - opq_len - junk_len;
                if (offset + opq_len + junk_len <= size && move_len <= size) {
                    memmove(code + offset + opq_len + junk_len, code + offset, move_len);
                    memcpy(code + offset, opq_buf, opq_len);
                    memcpy(code + offset + opq_len, junk_buf, junk_len);
                }
                offset += opq_len + junk_len;
                mutated = true;
                continue;
            }
        }

        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 2)) {
            uint8_t junk_buf[32];
            size_t junk_len;
            spew_trash(junk_buf, &junk_len, rng);
            if (junk_len <= size - offset && offset + inst.len <= size) {
                size_t move_len = size - offset - junk_len;
                if (offset + junk_len <= size && move_len <= size) {
                    memmove(code + offset + junk_len, code + offset, move_len);
                    memcpy(code + offset, junk_buf, junk_len);
                }
                offset += junk_len;
                mutated = true;
                continue;
            }
        }

        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 3)) {
            if (inst.opcode[0] == 0x89 && inst.has_modrm && inst.len >= 6) {
                uint8_t reg = (inst.modrm >> 3) & 7;
                uint8_t push = 0x50 | reg;
                uint8_t mov_seq[3] = { 0x89, 0x04, 0x24 }; // mov [esp], r
                uint8_t pop = 0x58 | reg;
                uint8_t split_seq[6];
                split_seq[0] = push;
                memcpy(split_seq+1, mov_seq, 3);
                split_seq[4] = pop;
                split_seq[5] = 0x90; // pad
                memcpy(code + offset, split_seq, 6);
                offset += 6;
                mutated = true;
                continue;
            }
            if (inst.opcode[0] == 0x50 && (offset + 6 <= size)) {
                uint8_t b1 = code[offset];
                uint8_t b2 = code[offset+1];
                if ((b2 == 0x89 || b2 == 0x8B) && code[offset+2] == 0x04 && code[offset+3] == 0x24 && (code[offset+4] & 0xF8) == 0x58) {
                    uint8_t pr = b1 & 7;
                    uint8_t rr = (code[offset+2] >> 3) & 7;
                    code[offset] = 0x89;
                    code[offset+1] = 0xC0 | (pr << 3) | rr;
                    mutated = true;
                    if (offset + 2 < size) {
                        size_t fill = 6 - 2;
                        memset(code + offset + 2, 0x90, fill);
                    }
                }
            }
        }
        if (!mutated && (inst.opcode[0] & 0xF8) == 0xB8 && inst.imm != 0 && inst.len >= 5) {
            switch(chacha20_random(rng) % 20) {
                case 0:
                    if (offset + 3 <= size) {
                        code[offset] = 0x31;
                        code[offset+1] = 0xC0 | (inst.opcode[0] & 0x7);
                        code[offset+2] = 0x48;
                        code[offset+3] = 0x05;
                        *(uint32_t*)(code + offset + 4) = (uint32_t)inst.imm;
                    }
                    break;
                case 1:
                    if (offset + 9 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm / 2;
                        code[offset+7] = 0x48; code[offset+8] = 0x05;
                        *(uint32_t*)(code + offset + 9) = (uint32_t)inst.imm - ((uint32_t)inst.imm / 2);
                    }
                    break;
                case 2:
                    if (offset + 6 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x31;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        code[offset+3] = 0x48; code[offset+4] = 0x81;
                        code[offset+5] = 0xF0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 6) = (uint32_t)inst.imm;
                    }
                    break;
                case 3:
                    if (offset + 7 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x8D;
                        code[offset+2] = 0x05 | ((inst.opcode[0] & 0x7) << 3);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm;
                    }
                    break;
                case 4:
                    if (offset + 7 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = -(int32_t)inst.imm;
                        code[offset+7] = 0x48; code[offset+8] = 0xF7;
                        code[offset+9] = 0xD0 | (inst.opcode[0] & 0x7); // NEG
                    }
                    break;
                case 5:
                    if (offset + 9 <= size) {
                        code[offset] = 0x31; code[offset+1] = 0xC0 | (inst.opcode[0] & 0x7);
                        code[offset+2] = 0x48; code[offset+3] = 0x05;
                        *(uint32_t*)(code + offset + 4) = (uint32_t)inst.imm;
                    }
                    break;
                case 6:
                    if (offset + 13 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x81;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm - 1;
                        code[offset+7] = 0x48; code[offset+8] = 0x83;
                        code[offset+9] = 0xC0 | (inst.opcode[0] & 0x7);
                        code[offset+10] = 1;
                    }
                    break;
                case 7:
                    if (offset + 13 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x81;
                        code[offset+2] = 0xE8 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = 0;
                        code[offset+7] = 0x48; code[offset+8] = 0xF7;
                        code[offset+9] = 0xD0 | (inst.opcode[0] & 0x7);
                    }
                    break;
                case 8:
                    if (offset + 10 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm;
                        code[offset+7] = 0x48; code[offset+8] = 0xF7;
                        code[offset+9] = 0xE0 | (inst.opcode[0] & 0x7); // MUL
                    }
                    break;
                case 9:
                    if (offset + 12 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm * 2;
                        code[offset+7] = 0x48; code[offset+8] = 0xD1;
                        code[offset+9] = 0xE8 | (inst.opcode[0] & 0x7); // SHR 1
                    }
                    break;
                case 10:
                    if (offset + 9 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x81;
                        code[offset+2] = 0xF0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm ^ 0xAAAAAAAA;
                        code[offset+7] = 0x48; code[offset+8] = 0x81;
                        code[offset+9] = 0xF0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 10) = 0xAAAAAAAA;
                    }
                    break;
                case 11:
                    if (offset + 13 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x05;
                        *(uint32_t*)(code + offset + 2) = (uint32_t)inst.imm + 5;
                        code[offset+6] = 0x48; code[offset+7] = 0x2D;
                        *(uint32_t*)(code + offset + 8) = 5;
                    }
                    break;
                case 12:
                    if (offset + 10 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = -(int32_t)inst.imm;
                        code[offset+7] = 0x48; code[offset+8] = 0xF7;
                        code[offset+9] = 0xD0 | (inst.opcode[0] & 0x7); // second NEG
                    }
                    break;
                case 13:
                    if (offset + 8 <= size) {
                        code[offset] = 0x8D; code[offset+1] = 0x84;
                        code[offset+2] = 0x00; *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm;
                    }
                    break;
                case 14:
                    if (offset + 7 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x31;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        code[offset+3] = 0x48; code[offset+4] = 0x81;
                        code[offset+5] = 0xF0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 6) = (uint32_t)inst.imm;
                    }
                    break;
                case 15:
                    if (offset + 12 <= size) {
                        uint8_t b0 = (uint8_t)(inst.imm & 0xFF);
                        uint8_t b1 = (uint8_t)((inst.imm >> 8) & 0xFF);
                        uint8_t b2 = (uint8_t)((inst.imm >> 16) & 0xFF);
                        uint8_t b3 = (uint8_t)((inst.imm >> 24) & 0xFF);
                        code[offset] = 0xB0 | (inst.opcode[0] & 0x7); code[offset+1] = b0;
                        code[offset+2] = 0xB0 | (inst.opcode[0] & 0x7); code[offset+3] = b1;
                        code[offset+4] = 0xB0 | (inst.opcode[0] & 0x7); code[offset+5] = b2;
                        code[offset+6] = 0xB0 | (inst.opcode[0] & 0x7); code[offset+7] = b3;
                    }
                    break;
                case 16:
                    if (offset + 11 <= size) {
                        uint32_t half = inst.imm / 2;
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7); *(uint32_t*)(code + offset + 3) = half;
                        code[offset+7] = 0x48; code[offset+8] = 0x05;
                        *(uint32_t*)(code + offset + 9) = inst.imm - half;
                    }
                    break;
                case 17:
                    if (offset + 12 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0x2D;
                        *(uint32_t*)(code + offset + 2) = inst.imm - 10;
                        code[offset+6] = 0x48; code[offset+7] = 0x05;
                        *(uint32_t*)(code + offset + 8) = 10;
                    }
                    break;
                case 18:
                    if (offset + 12 <= size) {
                        code[offset] = 0x48; code[offset+1] = 0xF7;
                        code[offset+2] = 0xD0 | (inst.opcode[0] & 0x7);
                        code[offset+3] = 0x48; code[offset+4] = 0x81;
                        *(uint32_t*)(code + offset + 5) = inst.imm;
                    }
                    break;
                case 19: // arbitrary two-step add
                    if (offset + 12 <= size) {
                        uint32_t part1 = inst.imm / 3;
                        uint32_t part2 = inst.imm - part1;
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7); *(uint32_t*)(code + offset + 3) = part1;
                        code[offset+7] = 0x48; code[offset+8] = 0x05; *(uint32_t*)(code + offset + 9) = part2;
                    }
                    break;
            }
        
            if (!is_op_ok(code + offset)) {
                if (offset + inst.len <= size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
            } else {
                mutated = true;
            }
        }        

        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 4)) {
            uint8_t orgi_op = inst.opcode[0];
            uint8_t new_opcode = orgi_op;
            switch(chacha20_random(rng) % 4) {
                case 0:
                    if (inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm)) new_opcode = (orgi_op == 0x89) ? 0x87 : 0x89;
                    break;
                case 1:
                    if (orgi_op == 0x01) new_opcode = 0x29;
                    else if (orgi_op == 0x29) new_opcode = 0x01;
                    break;
                case 2:
                    if (orgi_op == 0x21) new_opcode = 0x09;
                    else if (orgi_op == 0x09) new_opcode = 0x21;
                    break;
                case 3:
                    if (orgi_op == 0x31 && inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm)) new_opcode = 0x89;
                    break;
            }
            if (new_opcode != orgi_op) {
                code[offset] = new_opcode;
                if (is_op_ok(code + offset)) {
                    mutated = true;
                } else code[offset] = orgi_op;
            }
        }

        offset += inst.len;
    }

  
    if (gen > 5 && (chacha20_random(rng) % 10) < (gen > 15 ? 8 : 3)) {
        flowmap cfg;
        sketch_flow(code, size, &cfg);
        flatline_flow(code, size, &cfg, rng);
        free(cfg.blocks);
    }

    if (gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 5 : 2)) {
        shuffle_blocks(code, size, rng);
    }
}
#endif

#if defined(ARCH_ARM)
static uint8_t random_arm_reg(chacha_state_t *rng) {
    return chacha20_random(rng) % 31;
}

static void update_arm_liveness(liveness_state_t *state, size_t offset, const arm64_inst_t *inst) {
    if (!inst->valid) return;
    
    bool is_def = false;
    if (inst->type == ARM_OP_MOV || inst->type == ARM_OP_ADD || inst->type == ARM_OP_SUB ||
        inst->type == ARM_OP_AND || inst->type == ARM_OP_ORR || inst->type == ARM_OP_EOR ||
        inst->type == ARM_OP_LDR || inst->type == ARM_OP_LEA) {
        is_def = true;
    }
    
    if (is_def && inst->rd < 31) { 
        state->regs[inst->rd].iz_live = true;
        state->regs[inst->rd].def_offset = offset;
    }
    
    if (inst->rn < 31) {
        state->regs[inst->rn].last_use = offset;
    }
    if (inst->rm < 31) {
        state->regs[inst->rm].last_use = offset;
    }
}

static bool izar_reg(const liveness_state_t *state, uint8_t reg, size_t current_offset) {
    if (reg >= 31) return false; 
    
    if (state->regs[reg].iz_vol && state->regs[reg].iz_live) {
        if (current_offset - state->regs[reg].def_offset < 32) {
            return false;
        }
    }
    
    if (state->regs[reg].iz_live && 
        state->regs[reg].last_use - state->regs[reg].def_offset < 16) {
        return false;
    }
    
    return true;
}

static uint8_t findmearm(const liveness_state_t *state, uint8_t original_reg, 
                                                  size_t current_offset, chacha_state_t *rng) {
    uint8_t candidates[16];
    size_t num_candidates = 0;
    

    for (int i = 0; i < 16; i++) { 
        if (i != original_reg && izar_reg(state, i, current_offset)) {
            candidates[num_candidates++] = i;
        }
    }
    
    if (num_candidates == 0) {
        for (int i = 0; i < 16; i++) {
            if (i != original_reg && !state->regs[i].iz_live) {
                candidates[num_candidates++] = i;
            }
        }
    }
    
    if (num_candidates == 0) {
        return original_reg; 
    }
    
    return candidates[chacha20_random(rng) % num_candidates];
}

static void arm_semantic(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen,
                               muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity) {
    size_t offset = 0;
    
    if (liveness) {
        boot_live(liveness);
    }
    
    while (offset + 4 <= size) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            offset += 4;
            continue;
        }
        
        if (liveness) {
            update_arm_liveness(liveness, offset, &inst);
        }
        
        uint32_t original = *(uint32_t*)(code + offset);
        uint32_t mutated = original;
        bool changed = false;
        
        if (inst.type == ARM_OP_MOV || inst.type == ARM_OP_ADD || inst.type == ARM_OP_SUB ||
            inst.type == ARM_OP_AND || inst.type == ARM_OP_ORR || inst.type == ARM_OP_EOR) {
            
            uint8_t new_rd = inst.rd;
            uint8_t new_rn = inst.rn;
            uint8_t new_rm = inst.rm;
            
            if (liveness) {
                if (inst.rd < 31) new_rd = findmearm(liveness, inst.rd, offset, rng);
                if (inst.rn < 31) new_rn = findmearm(liveness, inst.rn, offset, rng);
                if (inst.rm < 31) new_rm = findmearm(liveness, inst.rm, offset, rng);
            } else {
                if (inst.rd < 31) new_rd = random_arm_reg(rng);
                if (inst.rn < 31) new_rn = random_arm_reg(rng);
                if (inst.rm < 31) new_rm = random_arm_reg(rng);
            }
            
            if (new_rd != inst.rd || new_rn != inst.rn || new_rm != inst.rm) {
                mutated = original & ~0x1F; 
                mutated |= new_rd;
                
                if (inst.rn < 31) {
                    mutated &= ~(0x1F << 5); 
                    mutated |= (new_rn << 5);
                }
                
                if (inst.rm < 31) {
                    mutated &= ~(0x1F << 16); 
                    mutated |= (new_rm << 16);
                }
                
                *(uint32_t*)(code + offset) = mutated;
                if (is_op_ok(code + offset)) {
                    changed = true;
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
        }
        
        if (!changed) {
            if (inst.type == ARM_OP_MOV && inst.rd == inst.rm) {
                if (chacha20_random(rng) % 2) {
  
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rd << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (is_op_ok(code + offset)) {
                    changed = true;
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
            else if (inst.type == ARM_OP_ADD && inst.imm == 0) {
                if (chacha20_random(rng) % 2) {
  
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rn << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (is_op_ok(code + offset)) {
                    changed = true;
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
            else if (inst.type == ARM_OP_SUB && inst.imm == 0) {
                if (chacha20_random(rng) % 2) {
  
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rn << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (is_op_ok(code + offset)) {
                    changed = true;
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
            else if (inst.type == ARM_OP_AND && inst.imm == 0xFFF) {
                if (chacha20_random(rng) % 2) {
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rn << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (is_op_ok(code + offset)) {
                    changed = true;
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
        }
        
        if (!changed && inst.imm != 0 && inst.imm_size > 0) {
            switch(chacha20_random(rng) % 3) {
                case 0: 
                    if (inst.imm <= 0xFFFF) {
                        uint32_t new_code[2] = {
                            0x52800000 | (inst.rd) | ((inst.imm & 0xFFFF) << 5), 
                            0x72800000 | (inst.rd) | ((inst.imm & 0xFFFF) << 5)  
                        };
                        if (offset + 8 <= size) {
                            memcpy(code + offset, new_code, 8);
                            offset += 8;
                            continue;
                        }
                    }
                break;
                case 1: 
                    if (inst.imm <= 0xFFF) {
                        uint32_t half = inst.imm / 2;
                        uint32_t new_code[2] = {
                            0x91000000 | (inst.rd) | (inst.rd << 5) | (half << 10), 
                            0x91000000 | (inst.rd) | (inst.rd << 5) | ((inst.imm - half) << 10) 
                        };
                        if (offset + 8 <= size) {
                            memcpy(code + offset, new_code, 8);
                            offset += 8;
                            continue;
                        }
                    }
                    break;
                case 2:
                    if (inst.imm <= 0xFFF) {
                        uint32_t new_code[2] = {
                            0xD2800000 | (inst.rd) | (0xFFFF << 5),
                            0xCA000000 | (inst.rd) | (inst.rd << 5) | (inst.rd << 16) | (inst.imm << 10)
                        };
                        if (offset + 8 <= size) {
                            memcpy(code + offset, new_code, 8);
                            if (log) {
                                drop_mut(log, offset, 8, MUT_OBFUSC, gen, "imm->mov+xor");
                            }
                            offset += 8;
                            continue;
                        }
                    }
                    break;
            }
        }
        
        if (!changed && gen > 2 && (chacha20_random(rng) % 10) < (gen > 10 ? 5 : gen)) {
            uint8_t opq_buf[32];
            size_t opq_len;
            uint32_t target_value = chacha20_random(rng);
            forge_ghost(opq_buf, &opq_len, target_value, rng);
            
            uint8_t junk_buf[16];
            size_t junk_len;
            spew_trash(junk_buf, &junk_len, rng);
            
            if (offset + 4 + opq_len + junk_len <= size) {
                memmove(code + offset + opq_len + junk_len, code + offset, size - offset - opq_len - junk_len);
                memcpy(code + offset, opq_buf, opq_len);
                memcpy(code + offset + opq_len, junk_buf, junk_len);
                
                if (log) {
                    drop_mut(log, offset, opq_len + junk_len, MUT_PRED, gen, " arm forge_ghost+junk");
                }
                offset += opq_len + junk_len;
                continue;
            }
        }
        
        if (!changed && gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 4 : 2)) {
            uint8_t junk_buf[16];
            size_t junk_len;
            spew_trash(junk_buf, &junk_len, rng);
            
            if (offset + 4 + junk_len <= size) {
                memmove(code + offset + junk_len, code + offset, size - offset - junk_len);
                memcpy(code + offset, junk_buf, junk_len);
                
                if (log) {
                    drop_mut(log, offset, junk_len, MUT_DEAD, gen, " arm junk");
                }
                offset += junk_len;
                continue;
            }
        }
        
        offset += 4;
    }
}
#endif

__attribute__((always_inline)) inline void _mut8(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen) {
    uint8_t *original = malloc(size);
    if (!original) return;
    memcpy(original, code, size);

    muttt_t mut_log;
    liveness_state_t liveness;
    init_mut(&mut_log);
    boot_live(&liveness);

    
    unsigned mutation_intensity = gen + 1;
    if (mutation_intensity > 20) mutation_intensity = 20;
    
#if defined(ARCH_X86)
    size_t offset = 0;
    int changes = 0;
    int semantic_mutations = 0;
    
    while (offset < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0 || offset + inst.len > size) {
            offset++;
            continue;
        }
        
        size_t original_offset = offset;
        scramble_x86(code + offset, inst.len, rng, gen, &mut_log, &liveness, mutation_intensity);
        if (memcmp(original + original_offset, code + original_offset, inst.len) != 0) {
            changes++;
            semantic_mutations++;
        }
        
        offset += inst.len;
    }
    
    if ((chacha20_random(rng) % 10) < (mutation_intensity / 2)) {
        flowmap cfg;
        sketch_flow(code, size, &cfg);
        flatline_flow(code, size, &cfg, rng);
        drop_mut(&mut_log, 0, size, MUT_FLATTEN, gen, "CF BS");
        changes++;
        DBG("[!] Flattening applied\n");
        free(cfg.blocks);
    }
    
    if ((chacha20_random(rng) % 10) < (mutation_intensity / 3)) {
        shuffle_blocks(code, size, rng);
        drop_mut(&mut_log, 0, size, MUT_REORDER, gen, "Block reorder");
        changes++;
        DBG("[!] Block reordering applied\n");
    }
    
    
#elif defined(ARCH_ARM)
    size_t offset = 0;
    int changes = 0;
    int semantic_mutations = 0;
    
    while (offset + 4 <= size) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            offset += 4;
            continue;
        }
        
        size_t original_offset = offset;
        arm_semantic(code + offset, 4, rng, gen, &mut_log, &liveness, mutation_intensity);
        if (memcmp(original + original_offset, code + original_offset, 4) != 0) {
            changes++;
            semantic_mutations++;
        }
        
        offset += 4;
    }
    
    if (gen > 5 && (chacha20_random(rng) % 10) < (gen > 15 ? 8 : 3)) {
        flowmap cfg;
        sketch_flow(code, size, &cfg);
        fg_arm(code, size, &cfg, rng);
        drop_mut(&mut_log, 0, size, MUT_FLATTEN, gen, "arm control flow flattening");
        changes++;
        DBG("[!] ARM control flow flattening applied\n");
        free(cfg.blocks);
    }
    
/*     if (gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 5 : 2)) {
        blocks_arm(code, size, rng);
        drop_mut(&mut_log, 0, size, MUT_REORDER, gen, "arm block reordering");
        changes++;
        DBG("[!] ARM block reordering applied\n");
    } */
    
#endif

  
#if defined(ARCH_X86)
    int bad_target = 0;
    for (size_t off = 0; off < size;) {
    x86_inst_t inst;
    if (!decode_x86_withme(code + off, size - off, 0, &inst, NULL) || !inst.valid || inst.len == 0) break;
    if (inst.has_modrm && (inst.opcode[0] >= 0x88 && inst.opcode[0] <= 0x8B)) {
        uint8_t base = inst.modrm & 0x7;
        if (base == 0 /* rax */ || base == 1 /* rcx */) {
                uint8_t orig_modrm = inst.modrm;
                int substituted = 0;
  
                for (uint8_t r = 2; r < 8; ++r) {
                    if (!liveness.regs[r].iz_live && r != 4 && r != 5) {
                        uint8_t reg_field = (orig_modrm >> 3) & 0x7;
                        if (r == reg_field) continue;
                        uint8_t new_modrm = (orig_modrm & 0xF8) | r;
                        code[off + inst.opcode_len] = new_modrm;
                        x86_inst_t test_inst;
                        if (decode_x86_withme(code + off, size - off, 0, &test_inst, NULL) && test_inst.valid) {
                            DBG("[ADV] Substituted base reg at 0x%zx: %d -> %d", off, base, r);
                            substituted = 1;
                            break;
                        }
                    }
                }
    off += inst.len;
                continue;
        }
        }
        if (inst.is_control_flow) {
            size_t target = 0;
            if (inst.opcode[0] == 0xE9 || inst.opcode[0] == 0xE8) { // JMP/CALL rel32
                target = off + inst.len + (int32_t)inst.imm;
            } else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) { // Jcc rel8
                target = off + inst.len + (int8_t)inst.opcode[1];
            } else if (inst.opcode[0] == 0x0F && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) { // Jcc rel32
                target = off + inst.len + (int32_t)inst.imm;
            } else {
                off += inst.len;
                continue;
            }
            int aligned = 0;
            for (size_t o2 = 0; o2 < size;) {
                x86_inst_t i2;
                if (!decode_x86_withme(code + o2, size - o2, 0, &i2, NULL) || !i2.valid || i2.len == 0) break;
                if (o2 == target) { aligned = 1; break; }
                o2 += i2.len;
            }
            if (!aligned && target < size) {
                DBG("[!] Jump/call at 0x%zx targets non-aligned offset 0x%zx", off, target);
                bad_target = 1;
            }
            if (inst.opcode[0] == 0x9A || inst.opcode[0] == 0xEA) {
  
                DBG("[!] Far call/jmp at 0x%zx, skipping mutation", off);
                continue; 
            }
        }
        off += inst.len;
    }
    if (bad_target) {
        memcpy(code, original, size);
        freeme(&mut_log);
        return;
    }
#endif

    memcpy(code, original, size);
    freeme(&mut_log);
}

static bool s_syscall(const uint8_t *code, size_t size) {
    #if defined(ARCH_X86)
        size_t offset = 0;
        while (offset < size) {
            x86_inst_t inst;
            if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0)
                break;
            if (inst.opcode_len == 2 && inst.opcode[0] == 0x0f && inst.opcode[1] == 0x05)
                return true;
            offset += inst.len;
        }
    #endif
        return false;
    }

    static bool has_anom(const uint8_t *code, size_t size) {
  
        #if defined(ARCH_X86)
            size_t offset = 0;
            while (offset < size) {
                x86_inst_t inst;
                if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0)
                    break;
                if (inst.opcode[0] == 0x48 && inst.opcode[1] == 0x31 && inst.raw[2] == 0xC0)
                    return true;
                if (inst.opcode[0] == 0xCD && inst.opcode[1] == 0x80)
                    return true;
                if (inst.opcode[0] == 0xEB)
                    return true;
                offset += inst.len;
            }
        #endif
            return false;
        }
        
static bool iz_exec(const uint8_t *code, size_t size) {
    size_t nonzero = 0;
    for (size_t i = 0; i < size; ++i)
        if (code[i] != 0x00 && code[i] != 0x90) 
            nonzero++;
    return (double)nonzero / size > 0.8;
}

bool is_shellcode_mode(const uint8_t *code, size_t size, const flowmap *cfg) {
    if (size == 0 || size > PAGE_SIZE) return false;
    if (cfg->num_blocks > 4) return false;

    if (s_syscall(code, size)) return true;
    if (has_anom(code, size)) return true;
    if (iz_exec(code, size) && cfg->num_blocks <= 2) return true;

    return false;
}

void mutate(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, engine_context_t *ctx) {
    if (ctx) {
        ctx->debug_code = code;
        ctx->debug_code_size = size;
    }
    if (size < 16) return;

     if (!rng) {
        return;
    }

    flowmap cfg;
    sketch_flow(code, size, &cfg);

    bool shellcode_mode = is_shellcode_mode(code, size, &cfg);

#if defined(ARCH_X86)
    muttt_t mut_log;
    liveness_state_t liveness;
    init_mut(&mut_log);
    boot_live(&liveness);

    if (shellcode_mode) {
        uint8_t *original = malloc(size);
        if (!original) return;
        memcpy(original, code, size);

        unsigned mutation_intensity = gen + 1;
        size_t offset = 0;

        while (offset < size) {
            x86_inst_t inst;
            if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) ||
                !inst.valid || inst.len == 0) break;

            bool skip = false;

            if (inst.is_control_flow || inst.modifies_ip)
                skip = true;

            if (inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm  = modrm_rm(inst.modrm);
                if (reg == 4 || reg == 5 || rm == 4 || rm == 5)
                    skip = true;
            }

            if ((inst.opcode[0] == 0x50 || inst.opcode[0] == 0x58) ||
                ((inst.opcode[0] & 0xF0) == 0xE0) ||
                (inst.opcode[0] == 0xC3 || inst.opcode[0] == 0xCB) ||
                inst.opcode[0] == 0x9A || inst.opcode[0] == 0xFF)
                skip = true;

            if ((inst.opcode[0] & 0xF8) == 0xB8)
                skip = true;

            if (!skip) {
                if (inst.opcode[0] == 0x90) {
  
                } else if ((inst.opcode[0] == 0x89 || inst.opcode[0] == 0x8B) && inst.has_modrm) {
                    uint8_t reg = modrm_reg(inst.modrm);
                    uint8_t rm  = modrm_rm(inst.modrm);
                    if (reg == rm && offset + 1 < size) {
                        code[offset]     = 0x31;
                        code[offset + 1] = 0xC0 | (reg << 3) | reg;
                    }
                } else if (inst.opcode[0] == 0x31 && inst.has_modrm) {
                    uint8_t reg = modrm_reg(inst.modrm);
                    uint8_t rm  = modrm_rm(inst.modrm);
                    if (reg == rm) {
                        code[offset]     = 0x89;
                        code[offset + 1] = 0xC0 | (reg << 3) | reg;
                    }
                }
            }

            offset += inst.len;
        }

  
        freeme(&mut_log);
        free(cfg.blocks);
        return;
    }
#endif

    _mut8(code, size, rng, gen);

  
#if defined(ARCH_X86)
    freeme(&mut_log);
#endif
    free(cfg.blocks);
}

size_t decode_map(const uint8_t *code, size_t size, instr_info_t *out, size_t max) {
    size_t n = 0, off = 0;
    size_t cf_count = 0;
    size_t failed_decodes = 0;
    
#if defined(ARCH_X86)
    while (off < size && n < max) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + off, size - off, 0, &inst, NULL)) {
            failed_decodes++;
            off++;
            continue;
        }
        out[n].off = off;
        out[n].len = inst.len;
        out[n].type = inst.opcode[0];
        out[n].cf = inst.is_control_flow;
        out[n].valid = 1;
        memcpy(out[n].raw, code + off, inst.len > 16 ? 16 : inst.len);
        
        if (inst.is_control_flow) {
            cf_count++;
        }
        
        off += inst.len;
        n++;
    }
#elif defined(ARCH_ARM)
    while (off + 4 <= size && n < max) {
        arm64_inst_t inst;
        if (!decode_arm64(code + off, &inst) || !inst.valid) {
            failed_decodes++;
            off += 4;
            continue;
        }
        out[n].off = off;
        out[n].len = 4;
        out[n].type = inst.type;
        out[n].cf = inst.is_control_flow;
        out[n].valid = 1;
        memcpy(out[n].raw, code + off, 4);
        
        if (inst.is_control_flow) {
            cf_count++;
        }
        
        off += 4;
        n++;
    }
#endif
    
    if (failed_decodes > 0) {}
    if (cf_count > 0) {}    
    return n;
}

#if defined(ARCH_X86)
static void block_liveness(const uint8_t *code, size_t size, blocknode *block, bool *live_regs) {
    if (!code || !block || !live_regs) return;

    memset(live_regs, 0, 16); // RAX .. R15

    instr_info_t instrs[128];
    size_t n_instrs = decode_map(code + block->start, block->end - block->start, instrs, sizeof(instrs)/sizeof(instrs[0]));

    for (size_t i = 0; i < n_instrs; i++) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + block->start + instrs[i].off, block->end - block->start - instrs[i].off, 0, &inst, NULL))
            continue;

        if (inst.has_modrm) {
            uint8_t reg = modrm_reg(inst.modrm);
            if (reg < 16) live_regs[reg] = false;  // overwritten
            uint8_t rm = modrm_rm(inst.modrm);
            if (rm < 16) live_regs[rm] = true;    // read
        }

        if (inst.opcode[0] == 0x50 || inst.opcode[0] == 0x58) { // push/pop
            live_regs[4] = true; // RSP live
        }
    }
}

void mut_sh3ll(uint8_t *shellcode, size_t shellcode_len, chacha_state_t *rng, unsigned gen, engine_context_t *ctx) {
    uint8_t *buffer = malloc(shellcode_len);
    if (!buffer) return;
    memcpy(buffer, shellcode, shellcode_len);

#if defined(ARCH_X86)
    size_t offset = 0;
    while (offset < shellcode_len) {
        x86_inst_t inst;
        if (!decode_x86_withme(buffer + offset, shellcode_len - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0) {
            offset++;
            continue;
        }
  
        bool is_nop = (inst.opcode[0] == 0x90);
        bool is_mov_rr = (inst.opcode[0] == 0x48 && inst.opcode[1] == 0x89 && inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm));
        bool is_xor_rr = (inst.opcode[0] == 0x48 && inst.opcode[1] == 0x31 && inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm));
        if (is_nop || is_mov_rr || is_xor_rr) {
            uint8_t r = chacha20_random(rng) % 3;
            if (r == 0 && !is_nop) {
                buffer[offset] = 0x90;
                for (size_t i = 1; i < inst.len; ++i) buffer[offset + i] = 0x90;
            } else if (r == 1 && is_mov_rr) {
                buffer[offset] = 0x48;
                buffer[offset + 1] = 0x31;
                buffer[offset + 2] = inst.modrm;
            } else if (r == 2 && is_xor_rr) {
                buffer[offset] = 0x48;
                buffer[offset + 1] = 0x89;
                buffer[offset + 2] = inst.modrm;
            }
        }
        offset += inst.len ? inst.len : 1;
    }
#endif
    memcpy(shellcode, buffer, shellcode_len);
    free(buffer);
    return;
}

static bool rec_cfg_add_block(rec_flowmap *cfg, size_t start, size_t end, bool is_exit) {
    if (!cfg || start >= end) return false;

    if (cfg->num_blocks >= cfg->cap_blocks) {
        size_t new_cap = cfg->cap_blocks ? cfg->cap_blocks * 2 : 32;
        if (new_cap <= cfg->cap_blocks) return false; 

        rec_block_t *tmp = realloc(cfg->blocks, new_cap * sizeof(rec_block_t));
        if (!tmp) return false;
        cfg->blocks = tmp;
        cfg->cap_blocks = new_cap;
    }

    rec_block_t *b = &cfg->blocks[cfg->num_blocks];
    b->start = start;
    b->end = end;
    b->num_successors = 0;
    b->is_exit = is_exit;
    cfg->num_blocks++; 
    return true;
}

void shit_recursive_x86_inner(const uint8_t *code, size_t size, rec_flowmap *cfg, size_t addr, int depth) {
    if (!cfg || !cfg->blocks || !cfg->visited) return;
    if (addr >= size || cfg->visited[addr] || depth > 1024) return;
    cfg->visited[addr] = true;

    size_t off = addr;
    while (off < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + off, size - off, 0, &inst, NULL) || !inst.valid || inst.len == 0) {
            rec_cfg_add_block(cfg, addr, (off + 1 <= size ? off + 1 : size), true);
            return;
        }

        size_t end_off = (off + inst.len <= size) ? off + inst.len : size;

        switch (inst.opcode[0]) {
            case 0xC3: case 0xCB: // ret
                rec_cfg_add_block(cfg, addr, end_off, true);
                return;

            case 0xE9: { // jmp rel32
                int32_t rel = (int32_t)inst.imm;
                size_t target = (rel < 0 && end_off < (size_t)(-rel)) ? 0 : end_off + rel;
                if (target < size) shit_recursive_x86_inner(code, size, cfg, target, depth + 1);
                rec_cfg_add_block(cfg, addr, end_off, false);
                return;
            }

            case 0xEB: { // jmp rel8
                int8_t rel = (int8_t)inst.imm;
                size_t target = (rel < 0 && end_off < (size_t)(-rel)) ? 0 : end_off + rel;
                if (target < size) shit_recursive_x86_inner(code, size, cfg, target, depth + 1);
                rec_cfg_add_block(cfg, addr, end_off, false);
                return;
            }

            case 0xE8: { // call rel32
                int32_t rel = (int32_t)inst.imm;
                size_t target = (rel < 0 && end_off < (size_t)(-rel)) ? 0 : end_off + rel;
                if (target < size) shit_recursive_x86_inner(code, size, cfg, target, depth + 1);
                off = end_off;
                continue; // fallthrough
            }

            default:
                if ((inst.opcode[0] & 0xF0) == 0x70 || inst.opcode[0] == 0xE3) { // jcc short
                    int8_t rel = (int8_t)inst.imm;
                    size_t target = (rel < 0 && end_off < (size_t)(-rel)) ? 0 : end_off + rel;
                    if (target < size) shit_recursive_x86_inner(code, size, cfg, target, depth + 1);
                    rec_cfg_add_block(cfg, addr, end_off, false);
                    if (end_off < size) shit_recursive_x86_inner(code, size, cfg, end_off, depth + 1);
                    return;
                } else if (inst.opcode[0] == 0xFF && (inst.modrm & 0x38) == 0x10) { // call [mem/reg]
                    rec_cfg_add_block(cfg, addr, end_off, true);
                    return;
                } else if (inst.opcode[0] == 0xFF && (inst.modrm & 0x38) == 0x20) { // jmp [mem/reg]
                    rec_cfg_add_block(cfg, addr, end_off, true);
                    return;
                }
        }

        off = end_off;
    }

    rec_cfg_add_block(cfg, addr, (off <= size ? off : size), true);
}

rec_flowmap *shit_recursive_x86(const uint8_t *code, size_t size) {
    if (!code || size == 0) return NULL;

    rec_flowmap *cfg = calloc(1, sizeof(rec_flowmap));
    if (!cfg) return NULL;

    cfg->code_size = size;
    cfg->num_blocks = 0;
    cfg->cap_blocks = 32;
    cfg->blocks = calloc(cfg->cap_blocks, sizeof(rec_block_t));
    if (!cfg->blocks) { free(cfg); return NULL; }

    cfg->visited = calloc(size, sizeof(bool));
    if (!cfg->visited) { free(cfg->blocks); free(cfg); return NULL; }

    shit_recursive_x86_inner(code, size, cfg, 0, 0);
    return cfg;
}

void mut_with_x86(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, muttt_t *log) {
    if (!code || size == 0) return;

    rec_flowmap *cfg = shit_recursive_x86(code, size);
    if (!cfg || cfg->num_blocks == 0) return;

    size_t *order = malloc(cfg->num_blocks * sizeof(size_t));
    if (!order) { free(cfg->blocks); free(cfg->visited); free(cfg); return; }
    for (size_t i = 0; i < cfg->num_blocks; ++i) order[i] = i;
    for (size_t i = cfg->num_blocks - 1; i > 0; --i) {
        size_t j = chacha20_random(rng) % (i + 1);
        size_t tmpi = order[i]; order[i] = order[j]; order[j] = tmpi;
    }

    uint8_t *tmp = malloc(size * 2);
    if (!tmp) { free(order); free(cfg->blocks); free(cfg->visited); free(cfg); return; }

    size_t out = 0;

    for (size_t i = 0; i < cfg->num_blocks; ++i) {
        rec_block_t *b = &cfg->blocks[order[i]];
        if (b->start >= size) continue;
        size_t block_end = b->end > size ? size : b->end;
        size_t blen = block_end - b->start;

  
        if ((chacha20_random(rng) % 4) == 0) {
            uint32_t val = chacha20_random(rng);
            size_t opq_len;
            uint8_t *opq_buf = malloc(32);
            if (!opq_buf) abort();
            forge_ghost(opq_buf, &opq_len, val, rng);
            if (out + opq_len <= size * 2) {
                memcpy(tmp + out, opq_buf, opq_len);
                if (log) drop_mut(log, out, opq_len, MUT_PRED, gen, "forge_ghost@entry");
                out += opq_len;
            }
            free(opq_buf);
        }

  
        if ((chacha20_random(rng) % 3) == 0) {
            size_t junk_len;
            uint8_t *junk_buf = malloc(16);
            if (!junk_buf) abort();
            spew_trash(junk_buf, &junk_len, rng);
            if (out + junk_len <= size * 2) {
                memcpy(tmp + out, junk_buf, junk_len);
                if (log) drop_mut(log, out, junk_len, MUT_JUNK, gen, "junk@entry");
                out += junk_len;
            }
            free(junk_buf);
        }

  
        if (out + blen <= size * 2)
            memcpy(tmp + out, code + b->start, blen);
        else {
            blen = size * 2 - out;
            if (blen > 0) memcpy(tmp + out, code + b->start, blen);
        }

  
        size_t block_offset = 0;
        while (block_offset < blen && out + block_offset < size * 2) {
            x86_inst_t inst;
            size_t avail_len = blen - block_offset;
            if (avail_len > size * 2 - (out + block_offset))
                avail_len = size * 2 - (out + block_offset);

            if (!decode_x86_withme(tmp + out + block_offset, avail_len, 0, &inst, NULL) ||
                !inst.valid || inst.len == 0) {
                block_offset++;
                continue;
            }

            size_t inst_end = block_offset + inst.len;

            if ((inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9)) {
                if (out + block_offset + 1 + sizeof(int32_t) <= size * 2 && inst.len >= 5) {
                    int32_t new_rel = 0;
                    *(int32_t*)(tmp + out + block_offset + 1) = new_rel;
                }
            } else if ((inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) ||
                       (inst.opcode[0] == 0x0F && inst.opcode_len > 1 && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F)) {
                if (out + block_offset + 2 <= size * 2) tmp[out + block_offset + 1] = 0;
            }

            block_offset += inst.len;
        }

        out += blen;

  
        if ((chacha20_random(rng) % 4) == 0) {
            uint32_t val = chacha20_random(rng);
            size_t opq_len;
            uint8_t *opq_buf = malloc(32);
            if (!opq_buf) abort();
            forge_ghost(opq_buf, &opq_len, val, rng);
            if (out + opq_len <= size * 2) {
                memcpy(tmp + out, opq_buf, opq_len);
                if (log) drop_mut(log, out, opq_len, MUT_PRED, gen, "forge_ghost@exit");
                out += opq_len;
            }
            free(opq_buf);
        }

  
        if ((chacha20_random(rng) % 3) == 0) {
            size_t junk_len;
            uint8_t *junk_buf = malloc(16);
            if (!junk_buf) abort();
            spew_trash(junk_buf, &junk_len, rng);
            if (out + junk_len <= size * 2) {
                memcpy(tmp + out, junk_buf, junk_len);
                if (log) drop_mut(log, out, junk_len, MUT_JUNK, gen, "junk@exit");
                out += junk_len;
            }
            free(junk_buf);
        }

  
        if ((chacha20_random(rng) % 6) == 0) {
            size_t fake_len = 4 + (chacha20_random(rng) % 8);
            if (out + fake_len <= size * 2) {
                uint8_t *fake = malloc(fake_len);
                if (!fake) abort();
                for (size_t k = 0; k < fake_len;) {
                    size_t junk_len;
                    uint8_t *junk_buf = malloc(16);
                    if (!junk_buf) abort();
                    spew_trash(junk_buf, &junk_len, rng);
                    size_t to_copy = (k + junk_len > fake_len) ? fake_len - k : junk_len;
                    memcpy(fake + k, junk_buf, to_copy);
                    k += to_copy;
                    free(junk_buf);
                }
                memcpy(tmp + out, fake, fake_len);
                if (log) drop_mut(log, out, fake_len, MUT_DEAD, gen, "fake block");
                out += fake_len;
                free(fake);
            }
        }
    }

  
    if ((chacha20_random(rng) % 3) == 0 && out + 32 <= size * 2) {
        uint32_t val = chacha20_random(rng);
        size_t opq_len;
        uint8_t *opq_buf = malloc(32);
        if (!opq_buf) abort();
        forge_ghost(opq_buf, &opq_len, val, rng);
        memmove(tmp + opq_len, tmp, out);
        memcpy(tmp, opq_buf, opq_len);
        free(opq_buf);
        out += opq_len;
    }

  
    size_t copy_len = out > size ? size : out;
    memcpy(code, tmp, copy_len);
    if (copy_len < size) memset(code + copy_len, 0, size - copy_len);

    free(tmp);
    free(order);
    free(cfg->blocks);
    free(cfg->visited);
    free(cfg);
}

#endif
