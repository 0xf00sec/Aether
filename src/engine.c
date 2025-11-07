#include <aether.h>
#include <forge.h>
#include <decoder_arm64.h>
#include <decoder_x86.h>

#if defined(__aarch64__) || defined(_M_ARM64)
static bool sketch_flow_arm64(uint8_t *code, size_t size, flowmap *cfg);
static void shuffle_blocks_arm64(uint8_t *code, size_t size, chacha_state_t *rng);
static void flatline_flow_arm64(uint8_t *code, size_t size, flowmap *cfg, chacha_state_t *rng);
#endif


static inline uint8_t get_current_arch(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return ARCH_X86;
#elif defined(__aarch64__) || defined(_M_ARM64)
    return ARCH_ARM;
#else
    return ARCH_X86;
#endif
}

static inline const char* get_arch_name(void) {
#if defined(__x86_64__) || defined(_M_X64)
    return "x86-64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    return "ARM64";
#else
    return "Unknown";
#endif
}

void init_engine(engine_context_t *ctx) {
    if (!ctx) return;
    
    memset(ctx, 0, sizeof(*ctx));
    ctx->debug_code = NULL;
    ctx->debug_code_size = 0;
    ctx->unsafe_mode = false;
    ctx->arch_type = get_current_arch();
    ctx->mutation_count = 0;
    ctx->generation = 0;
    ctx->protected_ranges = NULL;
    ctx->num_protected = 0;
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
    
#if defined(ARCH_X86)
    state->num_regs = 16;
    state->arch_type = ARCH_X86;
    
    for (int i = 0; i < state->num_regs; i++) {
        state->regs[i].reg = i;
        state->regs[i].iz_live = false;
        state->regs[i].iz_vol = arch_vols[i];
        state->regs[i].def_offset = 0;
        state->regs[i].last_use = 0;
        state->regs[i].is_callee_saved = !arch_vols[i];
    }
    
    state->regs[4].iz_live = true;
    state->regs[5].iz_live = true;
    
#elif defined(ARCH_ARM)
    state->num_regs = 32;
    state->arch_type = ARCH_ARM;
    
    for (int i = 0; i < state->num_regs; i++) {
        state->regs[i].reg = i;
        state->regs[i].iz_live = false;
        state->regs[i].iz_vol = arm64_vols[i];
        state->regs[i].def_offset = 0;
        state->regs[i].last_use = 0;
        state->regs[i].is_callee_saved = !arm64_vols[i];
    }
    
    state->regs[29].iz_live = true;
    state->regs[30].iz_live = true;
    state->regs[31].iz_live = true;
    
#else
    state->num_regs = 16;
    state->arch_type = ARCH_X86;
#endif
}

void pulse_live(liveness_state_t *state, size_t offset, const void *inst_ptr) {
    if (!state || !inst_ptr) return;
    
#if defined(ARCH_X86)
    const x86_inst_t *inst = (const x86_inst_t *)inst_ptr;
    if (!inst || !inst->valid) return;
    
    if (state->num_regs > 4) {
        state->regs[4].iz_live = true;
        state->regs[4].last_use = offset;
    }
    
    if (inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        uint8_t mod = (inst->modrm >> 6) & 3;
        
        if (reg >= state->num_regs || rm >= state->num_regs) return;
        
        if (mod != 3) {
            if (inst->has_sib) {
                uint8_t base = inst->sib & 7;
                uint8_t index = (inst->sib >> 3) & 7;
                if (base < 16 && base != 5) {
                    state->regs[base].last_use = offset;
                    state->regs[base].iz_live = true;
                }
                if (index < 16 && index != 4) {
                    state->regs[index].last_use = offset;
                    state->regs[index].iz_live = true;
                }
            } else if (rm < 16) {
                state->regs[rm].last_use = offset;
                state->regs[rm].iz_live = true;
            }
        }
        
        switch (inst->opcode[0]) {
            case 0x89:
                if (mod == 3 && rm < 16) {
                    state->regs[rm].iz_live = true;
                    state->regs[rm].def_offset = offset;
                }
                if (reg < 16) {
                    state->regs[reg].last_use = offset;
                }
                break;
            case 0x8B:
                if (reg < 16) {
                    state->regs[reg].iz_live = true;
                    state->regs[reg].def_offset = offset;
                }
                if (mod == 3 && rm < 16) {
                    state->regs[rm].last_use = offset;
                }
                break;
            case 0x01: case 0x03:
            case 0x29: case 0x2B:
            case 0x31: case 0x33:
            case 0x21: case 0x23:
            case 0x09: case 0x0B:
                if (reg < 16) {
                    state->regs[reg].last_use = offset;
                }
                if (mod == 3 && rm < 16) {
                    state->regs[rm].last_use = offset;
                    state->regs[rm].iz_live = true;
                    state->regs[rm].def_offset = offset;
                }
                break;
            default:
                if (reg < 16) state->regs[reg].last_use = offset;
                if (mod == 3 && rm < 16) state->regs[rm].last_use = offset;
                break;
        }
    }
    
    if ((inst->opcode[0] & 0xF8) == 0xB8) {
        uint8_t reg = inst->opcode[0] & 0x7;
        if (reg < 16) {
            state->regs[reg].iz_live = true;
            state->regs[reg].def_offset = offset;
        }
    }
    
    if ((inst->opcode[0] & 0xF8) == 0x50) {
        uint8_t reg = inst->opcode[0] & 0x7;
        if (reg < 16) {
            state->regs[reg].last_use = offset;
        }
        if (state->num_regs > 4) {
            state->regs[4].last_use = offset;
            state->regs[4].def_offset = offset;
        }
    } else if ((inst->opcode[0] & 0xF8) == 0x58) {
        uint8_t reg = inst->opcode[0] & 0x7;
        if (reg < 16) {
            state->regs[reg].iz_live = true;
            state->regs[reg].def_offset = offset;
        }
        if (state->num_regs > 4) {
            state->regs[4].last_use = offset;
            state->regs[4].def_offset = offset;
        }
    }
    
    if (inst->opcode[0] == 0xE8 || inst->opcode[0] == 0xC3 || 
        inst->opcode[0] == 0xC2 || inst->opcode[0] == 0xCB || inst->opcode[0] == 0xCA) {
        if (state->num_regs > 4) {
            state->regs[4].last_use = offset;
            state->regs[4].def_offset = offset;
        }
    }
    
    if (inst->opcode[0] == 0xF7 || inst->opcode[0] == 0xF6) {
        if (state->num_regs > 0) state->regs[0].last_use = offset;
        if (state->num_regs > 2) state->regs[2].last_use = offset;
    }
    
#elif defined(ARCH_ARM)
    const arm64_inst_t *inst = (const arm64_inst_t *)inst_ptr;
    if (!inst || !inst->valid) return;
    
    if (state->num_regs > 31) {
        state->regs[31].iz_live = true;
        state->regs[31].last_use = offset;
    }
    
    for (uint8_t i = 0; i < inst->num_regs_read; i++) {
        uint8_t reg = inst->regs_read[i];
        if (reg < 32) {
            state->regs[reg].last_use = offset;
            state->regs[reg].iz_live = true;
        }
    }
    
    for (uint8_t i = 0; i < inst->num_regs_written; i++) {
        uint8_t reg = inst->regs_written[i];
        if (reg < 32) {
            state->regs[reg].iz_live = true;
            state->regs[reg].def_offset = offset;
        }
    }
    
    if (inst->is_control_flow) {
        if (inst->type == ARM_OP_BRANCH_LINK) {
            if (state->num_regs > 30) {
                state->regs[30].iz_live = true;
                state->regs[30].def_offset = offset;
            }
        }
        
        if (inst->type == ARM_OP_RET && inst->rn == 30) {
            if (state->num_regs > 30) {
                state->regs[30].last_use = offset;
            }
        }
    }
    
    if (inst->type == ARM_OP_LDR || inst->type == ARM_OP_STR ||
        inst->type == ARM_OP_LDP || inst->type == ARM_OP_STP) {
        if (inst->rn == 31 && state->num_regs > 31) {
            state->regs[31].last_use = offset;
            state->regs[31].iz_live = true;
        }
    }
    
#endif
}

static inline bool is_stackp(uint8_t reg) { 
#if defined(ARCH_X86)
    return reg == 4 || reg == 5; /*  RSP or RBP */
#elif defined(ARCH_ARM)
    return reg == 31 || reg == 29 || reg == 30; /* SP, FP, LR */
#else
    return reg == 4 || reg == 5;
#endif
}

static inline bool is_protected(size_t offset, const engine_context_t *ctx) { 
    if (!ctx || !ctx->protected_ranges || ctx->num_protected == 0) return false;
    
    for (size_t i = 0; i < ctx->num_protected; i++) {
        uint64_t start = ctx->protected_ranges[i * 2];
        uint64_t end = ctx->protected_ranges[i * 2 + 1];
        if (offset >= start && offset < end) return true;
    }
    return false;
}

#if defined(ARCH_ARM)
static inline bool arm64_volatile(uint8_t reg) {
    return reg <= 18;
}

static inline bool callee_saved(uint8_t reg) {
    return reg >= 19 && reg <= 28;
}

static inline bool arm64_special(uint8_t reg) {
    return reg >= 29;
}

static inline bool cool_tmutation(uint8_t reg) {
    return reg < 16 || (reg >= 19 && reg <= 28);
}

static uint8_t jack_reg_arm64(const liveness_state_t *state, uint8_t original_reg,
                              size_t current_offset, chacha_state_t *rng) {
    if (!state || !rng) return original_reg;
    
    if (original_reg >= 29) return original_reg;
    
    if (original_reg >= 32) return original_reg;
    
    uint8_t candidates[19] = {0};
    uint8_t num_candidates = 0;
    
    for (uint8_t reg = 19; reg <= 28; reg++) {
        if (reg == original_reg) continue;
        
        bool is_safe = false;
        if (!state->regs[reg].iz_live) {
            is_safe = true;
        } else if (state->regs[reg].last_use > 0 &&
                   current_offset > state->regs[reg].last_use &&
                   (current_offset - state->regs[reg].last_use) > 32) {
            is_safe = true;
        }
        
        if (is_safe) {
            candidates[num_candidates++] = reg;
        }
    }
    
    if (num_candidates == 0) {
        for (uint8_t reg = 0; reg <= 18; reg++) {
            if (reg == original_reg) continue;
            
            if (reg == 16 || reg == 17) continue;
            
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
#endif

static inline bool has_implicit_rsp_use(uint8_t opcode) {
    return ((opcode & 0xF8) == 0x50) ||
           ((opcode & 0xF8) == 0x58) ||
           (opcode == 0xE8) ||
           (opcode == 0xC3) || (opcode == 0xCB) ||
           (opcode == 0xC2) || (opcode == 0xCA) ||
           (opcode == 0xC8) ||
           (opcode == 0xC9) ||
           (opcode == 0x9C) || (opcode == 0x9D) ||
           (opcode == 0x60) || (opcode == 0x61);
}

uint8_t jack_reg(const liveness_state_t *state, uint8_t original_reg, 
                                              size_t current_offset, chacha_state_t *rng) {
    if (!state || !rng) return original_reg;
    
    if (is_stackp(original_reg)) {
        return original_reg;
    }
    
#if defined(ARCH_ARM)
    return jack_reg_arm64(state, original_reg, current_offset, rng);
    
#elif defined(ARCH_X86)
    if (original_reg >= 16) {
        return original_reg;
    }
    
    uint8_t candidates[8] = {0};
    uint8_t num_candidates = 0;
    
    /* Prefer volatile (caller-saved), non-live registers */
    for (uint8_t reg = 0; reg < 8; reg++) {
        if (reg == original_reg) continue;
        if (reg == 3 || reg == 4 || reg == 5) continue;  /*  Never RBX/RSP/RBP */
        
        bool is_safe = false;
        if (!state->regs[reg].iz_live) {
            is_safe = true;
        } else if (state->regs[reg].last_use > 0 && 
                   current_offset > state->regs[reg].last_use &&
                   (current_offset - state->regs[reg].last_use) > 32) {
            is_safe = true;
        }
        
        if (is_safe && state->regs[reg].iz_vol) {
            candidates[num_candidates++] = reg;
        }
    }
    
    if (num_candidates == 0) {
        for (uint8_t reg = 0; reg < 8; reg++) {
            if (reg == original_reg) continue;
            if (reg == 3 || reg == 4 || reg == 5) continue; 
            
            if (!state->regs[reg].iz_live || 
                (current_offset > state->regs[reg].last_use &&
                 (current_offset - state->regs[reg].last_use) > 64)) { 
                candidates[num_candidates++] = reg;
            }
        }
    }
    
    /*  Validate selected register */
    if (num_candidates > 0) {
        uint8_t selected = candidates[chacha20_random(rng) % num_candidates];
        /*  Paranoid  */
        if (is_stackp(selected)) {
            return original_reg;
        }
        return selected;
    }
    
    return original_reg;
           
#else
    return original_reg;
#endif
}

__attribute__((always_inline)) inline bool is_op_ok(const uint8_t *code) {
#if defined(ARCH_X86)
    x86_inst_t inst;
    if (!decode_x86_withme(code, 16, 0, &inst, NULL)) return false;
    return !inst.ring0 && inst.valid;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (!decode_arm64(code, &inst)) return false;
    return inst.valid && !inst.ring0;
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

/* Validate a chunk of code */
__attribute__((always_inline)) inline bool is_chunk_ok(const uint8_t *code, size_t max_len) {
    if (!code || max_len == 0) return false;

#if defined(ARCH_ARM) && defined(__aarch64__)
    /*  Must be 4-byte aligned */
    if ((max_len % 4) != 0) return false;
    
    size_t valid_count = 0;
    size_t invalid_count = 0;
    const size_t max_invalid_ratio = max_len / 16;  /*  Stricter for ARM64 */
    
    for (size_t offset = 0; offset + 4 <= max_len; offset += 4) {
        arm64_inst_t inst;
        if (decode_arm64(code + offset, &inst) && inst.valid && !inst.ring0) {
            valid_count++;
            invalid_count = 0;
        } else {
            invalid_count++;
            if (invalid_count > max_invalid_ratio) return false;
        }
    }
    
    return valid_count > 0 && (invalid_count * 10 < valid_count);
    
#else
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
    /* allow max 2% invalid instructions */
    return valid_count > 0 && (invalid_count * 50 < valid_count);
#endif
}

#if defined(ARCH_ARM)
/* Generate ARM64 junk instructions semantically useless but valid code */
static void spew_trash_arm64(uint8_t *buf, size_t *len, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;
    
    uint8_t r1 = random_arm_reg(rng);
    uint8_t r2 = random_arm_reg(rng);
    while (r2 == r1) r2 = random_arm_reg(rng);
    
    uint8_t choice = chacha20_random(rng) % 15;
    uint32_t insn = 0;
    
    switch (choice) {
        case 0:
            insn = 0xD503201F;
            break;
        case 1:
            insn = 0xAA0003E0 | (1u << 31) | r1 | (r1 << 16) | (31 << 5);
            break;
        case 2:
            insn = 0x91000000 | (1u << 31) | r1 | (r1 << 5);
            break;
        case 3:
            insn = 0xD1000000 | (1u << 31) | r1 | (r1 << 5);
            break;
        case 4:
            insn = 0xAA1F0000 | (1u << 31) | r1 | (r1 << 5);
            break;
        case 5:
            insn = 0xCA1F0000 | (1u << 31) | r1 | (r1 << 5);
            break;
        case 6:
            insn = 0x8A000000 | (1u << 31) | r1 | (r1 << 5) | (r1 << 16);
            break;
        case 7:
            insn = 0xAA000000 | (1u << 31) | r1 | (r1 << 5) | (r1 << 16);
            break;
        case 8:
            insn = 0xAA0003E0 | (1u << 31) | r1 | (r2 << 16) | (31 << 5);
            break;
        case 9:
            insn = 0xD3400000 | (1u << 31) | r1 | (r1 << 5);
            break;
        case 10:
            insn = 0xD340FC00 | (1u << 31) | r1 | (r1 << 5);
            break;
        case 11:
            insn = 0xD2800000 | (1u << 31) | r1;
            break;
        case 12:
            insn = 0xCA1F03E0 | (1u << 31) | r1 | (31 << 5);
            break;
        case 13:
            insn = 0xAA1F03E0 | (1u << 31) | r1 | (31 << 5);
            break;
        case 14:
            insn = 0x8B1F03E0 | (1u << 31) | r1 | (31 << 5);
            break;
    }
    
    *(uint32_t*)buf = insn;
    *len = 4;
}
#endif

void spew_trash(uint8_t *buf, size_t *len, chacha_state_t *rng) {
    if (!buf || !len || !rng) return;

#if defined(ARCH_ARM)
    spew_trash_arm64(buf, len, rng);
#elif defined(ARCH_X86)
    /* Only use volatile regs to avoid save/restore overhead */
    const uint8_t usable_regs[] = {0,1,2,6,7,8,9,10,11};
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
#else
    buf[0] = 0x90;
    *len = 1;
#endif
}

static inline bool cfg_terminator(const x86_inst_t *inst) { 
    if (!inst || !inst->valid) return false;
    uint8_t op = inst->opcode[0];
    
    if (op == 0xE9 || op == 0xEB) return true;
    if (op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCA) return true;
    
    if (op == 0xFF && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        if (reg == 4 || reg == 5) return true;
    }
    
    return false;
}

static inline bool branch_if(const x86_inst_t *inst) { 
    if (!inst || !inst->valid) return false;
    uint8_t op = inst->opcode[0];
    
    if (op >= 0x70 && op <= 0x7F) return true;
    if (op == 0xE0 || op == 0xE1 || op == 0xE2 || op == 0xE3) return true;
    if (op == 0x0F && inst->opcode_len > 1 && 
        inst->opcode[1] >= 0x80 && inst->opcode[1] <= 0x8F) return true;
    
    return false;
}

#if defined(__aarch64__) || defined(_M_ARM64)
/* Build control flow graph for ARM64 identifies basic blocks and successors */
static bool sketch_flow_arm64(uint8_t *code, size_t size, flowmap *cfg) {
    if (!code || !cfg || size < 4 || (size % 4) != 0) {
        if (cfg) *cfg = (flowmap){0};
        return false;
    }

    /* Mark block leaders (entry point + branch targets) */
    bool *leaders = calloc(size, sizeof(bool));
    if (!leaders) return false;
    
    leaders[0] = true;
    
    for (size_t offset = 0; offset + 4 <= size; offset += 4) {
        arm64_inst_t inst;
        
        if (offset + 4 > size) break;
        
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            continue;
        }
        
        if (inst.is_control_flow) {
            if (inst.type == ARM_OP_BRANCH_COND || inst.type == ARM_OP_CBZ || 
                inst.type == ARM_OP_CBNZ || inst.type == ARM_OP_TBZ || 
                inst.type == ARM_OP_TBNZ || inst.type == ARM_OP_BRANCH_LINK) {
                size_t next_offset = offset + 4;
                if (next_offset < size) {
                    leaders[next_offset] = true;
                }
            }
            
            if (inst.type == ARM_OP_BRANCH || inst.type == ARM_OP_BRANCH_LINK ||
                inst.type == ARM_OP_BRANCH_COND || inst.type == ARM_OP_CBZ ||
                inst.type == ARM_OP_CBNZ || inst.type == ARM_OP_TBZ || 
                inst.type == ARM_OP_TBNZ) {
                
                int64_t target = (int64_t)offset + inst.target;
                
                if (target >= 0 && (size_t)target < size && ((size_t)target % 4) == 0) {
                    leaders[(size_t)target] = true;
                }
            }
        }
    }
    
    /* Create blocks from leaders */
    const size_t initial_cap = 1024;
    cfg->blocks = calloc(initial_cap, sizeof(blocknode));
    if (!cfg->blocks) {
        free(leaders);
        return false;
    }
    
    cfg->num_blocks = 0;
    cfg->cap_blocks = initial_cap;
    
    size_t block_start = 0;
    for (size_t i = 4; i < size; i += 4) {
        if (leaders[i]) {
            if (cfg->num_blocks < cfg->cap_blocks) {
                cfg->blocks[cfg->num_blocks].start = block_start;
                cfg->blocks[cfg->num_blocks].end = i;
                cfg->blocks[cfg->num_blocks].id = cfg->num_blocks;
                cfg->blocks[cfg->num_blocks].num_successors = 0;
                cfg->blocks[cfg->num_blocks].is_exit = false;
                cfg->num_blocks++;
            }
            block_start = i;
        }
    }
    
    if (block_start < size && cfg->num_blocks < cfg->cap_blocks) {
        cfg->blocks[cfg->num_blocks].start = block_start;
        cfg->blocks[cfg->num_blocks].end = size;
        cfg->blocks[cfg->num_blocks].id = cfg->num_blocks;
        cfg->blocks[cfg->num_blocks].num_successors = 0;
        cfg->blocks[cfg->num_blocks].is_exit = false;
        cfg->num_blocks++;
    }
    
    /* Build successor relationships */
    for (size_t bi = 0; bi < cfg->num_blocks; bi++) {
        blocknode *block = &cfg->blocks[bi];
        
        /*  Find last instruction in block */
        if (block->end <= block->start || block->end > size) continue;
        
        size_t last_insn_offset = block->end - 4;
        if (last_insn_offset < block->start) continue;
        
        arm64_inst_t inst;
        if (!decode_arm64(code + last_insn_offset, &inst) || !inst.valid) {
            /*  If we can't decode last instruction, assume fall-through */
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
            continue;
        }
        
        if (inst.type == ARM_OP_RET) {
            block->is_exit = true;
        }
        else if (inst.type == ARM_OP_BRANCH) {
            int64_t target = (int64_t)last_insn_offset + inst.target;
            if (target >= 0 && (size_t)target < size) {
                for (size_t ti = 0; ti < cfg->num_blocks; ti++) {
                    if ((size_t)target >= cfg->blocks[ti].start && 
                        (size_t)target < cfg->blocks[ti].end) {
                        if (block->num_successors < 4) {
                            block->successors[block->num_successors++] = ti;
                        }
                        break;
                    }
                }
            }
        }
        else if (inst.type == ARM_OP_BRANCH_COND || inst.type == ARM_OP_CBZ ||
                 inst.type == ARM_OP_CBNZ || inst.type == ARM_OP_TBZ || 
                 inst.type == ARM_OP_TBNZ) {
            int64_t target = (int64_t)last_insn_offset + inst.target;
            
            if (target >= 0 && (size_t)target < size) {
                for (size_t ti = 0; ti < cfg->num_blocks; ti++) {
                    if ((size_t)target >= cfg->blocks[ti].start && 
                        (size_t)target < cfg->blocks[ti].end) {
                        if (block->num_successors < 4) {
                            block->successors[block->num_successors++] = ti;
                        }
                        break;
                    }
                }
            }
            
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
        }
        else if (inst.type == ARM_OP_BRANCH_LINK) {
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
        }
        else if (inst.type == ARM_OP_BR || inst.type == ARM_OP_BLR) {
            /* Indirect branches can't determine target statically */
            if (inst.type == ARM_OP_BR) {
                block->is_exit = true;
            } else {
                if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                    block->successors[block->num_successors++] = bi + 1;
                }
            }
        }
        else {
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
        }
    }
    
    cfg->entry_block = 0;
    cfg->exit_block = cfg->num_blocks > 0 ? cfg->num_blocks - 1 : 0;
    
    free(leaders);
    
    DBG("Built CFG with %zu blocks\n", cfg->num_blocks);
    return cfg->num_blocks > 0;
}
#endif  // __aarch64__ || _M_ARM64

bool sketch_flow(uint8_t *code, size_t size, flowmap *cfg) {
#if defined(__aarch64__) || defined(_M_ARM64)
    return sketch_flow_arm64(code, size, cfg);
#elif defined(__x86_64__) || defined(_M_X64)
    if (!code || !cfg || size < 16) {
        if (cfg) *cfg = (flowmap){0};
        return false;
    }

    bool *leaders = calloc(size, sizeof(bool));
    if (!leaders) return false;
    
    leaders[0] = true;
    
    size_t offset = 0;
    while (offset < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || 
            !inst.valid || inst.len == 0) {
            offset++;
            continue;
        }
        
        if (cfg_terminator(&inst) || branch_if(&inst)) {
            if (offset + inst.len < size) {
                leaders[offset + inst.len] = true;
            }
            
            int64_t target = -1;
            if (inst.opcode[0] == 0xE9 || inst.opcode[0] == 0xE8) {  /*  JMP/CALL rel32 */
                target = offset + inst.len + (int32_t)inst.imm;
            } else if (inst.opcode[0] == 0xEB) {  /*  JMP rel8 */
                target = offset + inst.len + (int8_t)inst.imm;
            } else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) {  /*  Jcc rel8 */
                target = offset + inst.len + (int8_t)inst.imm;
            } else if (inst.opcode[0] == 0x0F && inst.opcode_len > 1 &&
                       inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) {  /*  Jcc rel32 */
                target = offset + inst.len + (int32_t)inst.imm;
            }
            
            /*  Mark jump target as a leader */
            if (target >= 0 && target < (int64_t)size) {
                leaders[target] = true;
            }
        }
        
        offset += inst.len;
    }
    
    const size_t initial_cap = 1024;
    cfg->blocks = calloc(initial_cap, sizeof(blocknode));
    if (!cfg->blocks) {
        free(leaders);
        return false;
    }
    
    cfg->num_blocks = 0;
    cfg->cap_blocks = initial_cap;
    
    size_t block_start = 0;
    for (size_t i = 0; i < size; i++) {
        if (leaders[i] && i > block_start) {
            if (cfg->num_blocks < cfg->cap_blocks) {
                cfg->blocks[cfg->num_blocks].start = block_start;
                cfg->blocks[cfg->num_blocks].end = i;
                cfg->blocks[cfg->num_blocks].id = cfg->num_blocks;
                cfg->blocks[cfg->num_blocks].num_successors = 0;
                cfg->blocks[cfg->num_blocks].is_exit = false;
                cfg->num_blocks++;
            }
            block_start = i;
        }
    }
    
    if (block_start < size && cfg->num_blocks < cfg->cap_blocks) {
        cfg->blocks[cfg->num_blocks].start = block_start;
        cfg->blocks[cfg->num_blocks].end = size;
        cfg->blocks[cfg->num_blocks].id = cfg->num_blocks;
        cfg->blocks[cfg->num_blocks].num_successors = 0;
        cfg->blocks[cfg->num_blocks].is_exit = false;
        cfg->num_blocks++;
    }
    
    for (size_t bi = 0; bi < cfg->num_blocks; bi++) {
        blocknode *block = &cfg->blocks[bi];
        
        if (block->end <= block->start || block->end > size) continue;
        
        size_t last_insn_offset = block->end;
        x86_inst_t last_inst = {0};
        bool found_last = false;
        
        size_t scan_offset = block->start;
        while (scan_offset < block->end) {
            x86_inst_t inst;
            if (decode_x86_withme(code + scan_offset, block->end - scan_offset, 0, &inst, NULL) &&
                inst.valid && inst.len > 0) {
                last_insn_offset = scan_offset;
                last_inst = inst;
                found_last = true;
                scan_offset += inst.len;
            } else {
                scan_offset++;
            }
        }
        
        if (!found_last) {
            /* Try scanning backwards to find a valid last instruction */
            size_t back = block->end;
            x86_inst_t back_inst = {0};
            bool back_found = false;
            while (back > block->start) {
                size_t try_off = back - 1;
                x86_inst_t tmp;
                if (decode_x86_withme(code + try_off, block->end - try_off, 0, &tmp, NULL) && tmp.valid && tmp.len > 0 && try_off + tmp.len <= block->end) {
                    back_inst = tmp;
                    last_insn_offset = try_off;
                    back_found = true;
                    break;
                }
                back--;
            }
            if (!back_found) {
                if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                    block->successors[block->num_successors++] = bi + 1;
                }
                continue;
            }
            last_inst = back_inst;
        }
        
        uint8_t op = last_inst.opcode[0];
        
        if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA) {
            block->is_exit = true;
        }
        else if (op == 0xE9 || op == 0xEB) {
            int64_t target = last_insn_offset + last_inst.len;
            if (op == 0xE9) {
                target += (int32_t)last_inst.imm;
            } else {
                target += (int8_t)last_inst.imm;
            }
            
            if (target >= 0 && (size_t)target < size) {
                for (size_t ti = 0; ti < cfg->num_blocks; ti++) {
                    if ((size_t)target >= cfg->blocks[ti].start && 
                        (size_t)target < cfg->blocks[ti].end) {
                        if (block->num_successors < 4) {
                            block->successors[block->num_successors++] = ti;
                        }
                        break;
                    }
                }
            }
        }
        else if ((op >= 0x70 && op <= 0x7F) || 
                 (op == 0x0F && last_inst.opcode_len > 1 && 
                  last_inst.opcode[1] >= 0x80 && last_inst.opcode[1] <= 0x8F)) {
            int64_t target = last_insn_offset + last_inst.len;
            
            if (op >= 0x70 && op <= 0x7F) {
                target += (int8_t)last_inst.imm;
            } else {
                target += (int32_t)last_inst.imm;
            }
            
            /*  Add branch target */
            if (target >= 0 && (size_t)target < size) {
                for (size_t ti = 0; ti < cfg->num_blocks; ti++) {
                    if ((size_t)target >= cfg->blocks[ti].start && 
                        (size_t)target < cfg->blocks[ti].end) {
                        if (block->num_successors < 4) {
                            block->successors[block->num_successors++] = ti;
                        }
                        break;
                    }
                }
            }
            
            /* Add fall-through */
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
        }
        else if (op == 0xE8) {
            /*  CALL  */
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
        }
        else if (op == 0xFF && last_inst.has_modrm) {
            /* Indirect jump/call (FF /4 = JMP, FF /2 = CALL) */
            uint8_t reg = modrm_reg(last_inst.modrm);
            if (reg == 4 || reg == 5) {
                /* Indirect JMP - mark as potential exit */
                block->is_exit = true;
            } else if (reg == 2 || reg == 3) {
                /* Assume it returns */
                if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                    block->successors[block->num_successors++] = bi + 1;
                }
            }
        }
        else {
            if (bi + 1 < cfg->num_blocks && block->num_successors < 4) {
                block->successors[block->num_successors++] = bi + 1;
            }
        }
    }
    
    cfg->entry_block = 0;
    cfg->exit_block = cfg->num_blocks > 0 ? cfg->num_blocks - 1 : 0;
    
    free(leaders);
    
    DBG("Built CFG with %zu blocks\n", cfg->num_blocks);
    return cfg->num_blocks > 0;
#else
    /* Fallback for unknown architectures */
    if (cfg) *cfg = (flowmap){0};
    return false;
#endif
}

#if defined(__aarch64__) || defined(_M_ARM64)
/* Flatten control flow for ARM64 currently just shuffles blocks */
static void flatline_flow_arm64(uint8_t *code, size_t size, flowmap *cfg, chacha_state_t *rng) {
    if (!code || !cfg || !rng || cfg->num_blocks < 3) return;
    if ((size % 4) != 0) return;
    
    shuffle_blocks_arm64(code, size, rng);
}
#endif

void flatline_flow(uint8_t *code, size_t size, flowmap *cfg, chacha_state_t *rng) {
#if defined(__aarch64__) || defined(_M_ARM64)
    flatline_flow_arm64(code, size, cfg, rng);
#elif defined(__x86_64__) || defined(_M_X64)
    if (!code || !cfg || !rng || cfg->num_blocks < 3) return;
    
    patch_t patch[64]; 
    size_t np = 0;
    size_t out = 0;
    size_t max_blocks = cfg->num_blocks;
    
    if (max_blocks > 0 && max_blocks > (SIZE_MAX - 128 - size) / 8) {
        return; 
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
        size_t j = 1 + (chacha20_random(rng) % i); /* keep block 0 pinned at index 0 */
        size_t t = order[i]; order[i] = order[j]; order[j] = t;
    }
    
    if (order[0] != 0) {
        size_t idx0 = 0;
        for (size_t k = 1; k < max_blocks; k++) { 
            if (order[k] == 0) { idx0 = k; break; } 
        }
        size_t t = order[0]; order[0] = order[idx0]; order[idx0] = t;
    }

    /* Copy blocks and collect control flow instructions for patching */
    for (size_t i = 0; i < max_blocks; i++) {
        size_t bi = order[i];
        blocknode *b = &cfg->blocks[bi];
        bmap[bi] = out;
        size_t blen = b->end - b->start;
        
        memcpy(nbuf + out, code + b->start, blen);

        /* Scan entire block */
        size_t block_offset = 0;
        while (block_offset < blen && np < (sizeof(patch)/sizeof(patch[0]))) {
            x86_inst_t inst;
            if (!decode_x86_withme(nbuf + out + block_offset, blen - block_offset, 0, &inst, NULL) || 
                !inst.valid || inst.len == 0) {
                block_offset++;
                continue;
            }
            
            size_t instruction_addr_in_new_buffer = out + block_offset;
            size_t instruction_addr_in_og = b->start + block_offset; 
            uint64_t current_absolute_target = 0; 
            bool should_patch = false;
            int patch_type = 0;

            if (inst.opcode[0] == 0xE8) {  /* CALLrel32 */
                current_absolute_target = instruction_addr_in_og + inst.len + (int32_t)inst.imm;
                should_patch = true;
                patch_type = 2;
            } 
            else if (inst.opcode[0] == 0xE9) {  /* JMP rel32 */
                current_absolute_target = instruction_addr_in_og + inst.len + (int32_t)inst.imm;
                should_patch = true;
                patch_type = 1;
            }
            else if (inst.opcode[0] == 0xEB) {  /* JMP rel8 */
                current_absolute_target = instruction_addr_in_og + inst.len + (int8_t)inst.imm;
                should_patch = true;
                patch_type = 5;
            }
            else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) {  /* Jcc rel8 */
                current_absolute_target = instruction_addr_in_og + inst.len + (int8_t)inst.imm;
                should_patch = true;
                patch_type = 3;
            } 
            else if (inst.opcode[0] == 0x0F && inst.opcode_len > 1 && 
                     inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) {  /* Jcc rel32 */
                current_absolute_target = instruction_addr_in_og + inst.len + (int32_t)inst.imm;
                should_patch = true;
                patch_type = 4;
            }

            if (should_patch) {
                patch[np].off = instruction_addr_in_new_buffer;
                patch[np].blki = bi;
                patch[np].abs_target = current_absolute_target;
                patch[np].inst_len = inst.len;
                patch[np].typ = patch_type;
                np++;
            }
            
            block_offset += inst.len;
        }
        
        out += blen;
    }

    if (np > 1) {
        for (size_t i = 0; i < np - 1; i++) {
            for (size_t j = i + 1; j < np; j++) {
                if (patch[i].off < patch[j].off) {
                    patch_t t = patch[i]; patch[i] = patch[j]; patch[j] = t;
                }
            }
        }
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
            case 1: /* JMP rel32 (opcode E9) */
            case 2: /* CALL rel32 (opcode E8) */
                if (src + 5 > buf_sz) continue;
                new_disp = (int32_t)(new_tgt - (src + 5));
                if (src + 1 + sizeof(int32_t) <= buf_sz) {
                    memcpy(nbuf + src + 1, &new_disp, sizeof(new_disp));
                }
                break;
                
            case 3: /* Jcc rel8 (opcode 70-7F) */
                if (src + 2 > buf_sz) continue;
                new_disp = (int32_t)(new_tgt - (src + 2));
                
                if (new_disp >= -128 && new_disp <= 127 && src + 1 < buf_sz) {
                    nbuf[src + 1] = (uint8_t)new_disp;
                } else {
                    /* Expand Jcc rel8 to Jcc rel32 (0F 8x) */
                    if (src + 6 <= buf_sz && out + 4 <= buf_sz) {
                        uint8_t cc = nbuf[src] & 0x0F;
                        
                        /* Shift everything */
                        memmove(nbuf + src + 6, nbuf + src + 2, out - src - 2);
                        nbuf[src] = 0x0F;
                        nbuf[src + 1] = 0x80 | cc;
                        new_disp = (int32_t)(new_tgt - (src + 6));
                        memcpy(nbuf + src + 2, &new_disp, 4);
                        out += 4;
                        p->inst_len = 6;
                    }
                }
                break;
                
            case 4: /* Jcc rel32 (opcode 0F 80-8F) */
                if (src + 6 > buf_sz) continue;
                new_disp = (int32_t)(new_tgt - (src + 6));
                if (src + 2 + sizeof(int32_t) <= buf_sz) {
                    memcpy(nbuf + src + 2, &new_disp, sizeof(new_disp));
                }
                break;
                
            case 5: /* JMP rel8 (opcode EB) */
                if (src + 2 > buf_sz) continue;
                new_disp = (int32_t)(new_tgt - (src + 2));
                
                if (new_disp >= -128 && new_disp <= 127 && src + 1 < buf_sz) {
                    nbuf[src + 1] = (uint8_t)new_disp;
                } else {
                    /* Expand JMP rel8 to JMP rel32 (E9) */
                    if (src + 5 <= buf_sz && out + 3 <= buf_sz) {
                        /* Shift everything after this instruction forward by 3 bytes */
                        memmove(nbuf + src + 5, nbuf + src + 2, out - src - 2);
                        
                        /* Write expanded instruction */
                        nbuf[src] = 0xE9;
                        new_disp = (int32_t)(new_tgt - (src + 5));
                        memcpy(nbuf + src + 1, &new_disp, 4);
                        
                        /* Update size tracking */
                        out += 3;
                        p->inst_len = 5;
                    }
                }
                break;
        }

        /* Validate */
        if (src < buf_sz) {
            size_t remaining = buf_sz - src;
            x86_inst_t test_inst;
            if (!decode_x86_withme(nbuf + src, remaining > 16 ? 16 : remaining, 0, &test_inst, NULL) || !test_inst.valid) {
                /* Rollback */
                if (src < size && p->inst_len > 0 && src + p->inst_len <= size) {
                    memcpy(nbuf + src, code + cfg->blocks[p->blki].start + (src - bmap[p->blki]), p->inst_len);
                }
            }
        }
    }

    /* Decode all */
    bool all_valid = true;
    for (size_t i = 0; i < np; i++) {
        patch_t *p = &patch[i];
        if (p->off >= buf_sz) {
            all_valid = false;
            break;
        }
        
        x86_inst_t inst;
        size_t remaining = buf_sz - p->off;
        if (!decode_x86_withme(nbuf + p->off, remaining > 16 ? 16 : remaining, 0, &inst, NULL) || 
            !inst.valid) {
            all_valid = false;
            break;
        }
    }

    if (all_valid && out <= size) {
        memcpy(code, nbuf, out);
        if (out < size) memset(code + out, 0, size - out);
    }
    
    free(nbuf); 
    free(bmap); 
    free(order);
#else
    (void)code; (void)size; (void)cfg; (void)rng;
#endif
}

#if defined(__aarch64__) || defined(_M_ARM64)
/* Generate ARM64 trampoline for out-of-range branches loads 64-bit address into X16 then branches */
static inline void emit_trampoline_arm64(uint8_t *buf, size_t *off, uint64_t target, bool is_call) {
    if (!buf || !off) return;
    
    *(uint32_t*)(buf + *off) = 0xD2800000 | (1u << 31) | 16 | ((target & 0xFFFF) << 5);
    *off += 4;
    
    *(uint32_t*)(buf + *off) = 0xF2A00000 | (1u << 31) | 16 | (((target >> 16) & 0xFFFF) << 5);
    *off += 4;
    
    *(uint32_t*)(buf + *off) = 0xF2C00000 | (1u << 31) | 16 | (((target >> 32) & 0xFFFF) << 5);
    *off += 4;
    
    if (is_call) {
        *(uint32_t*)(buf + *off) = 0xD63F0200;
    } else {
        *(uint32_t*)(buf + *off) = 0xD61F0200;
    }
    *off += 4;
}

/* Reorder ARM64 basic blocks and fix up all branch instructions */
static void shuffle_blocks_arm64(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (!code || !rng || size < 8 || (size % 4) != 0) return;
    
    flowmap cfg;
    if (!sketch_flow_arm64(code, size, &cfg)) return;
    if (cfg.num_blocks < 2) { free(cfg.blocks); return; }

    size_t nb = cfg.num_blocks;
    size_t *order = malloc(nb * sizeof(size_t));
    if (!order) { free(cfg.blocks); return; }
    
    for (size_t i = 0; i < nb; i++) order[i] = i;
    for (size_t i = nb - 1; i > 1; i--) {
        size_t j = 1 + (chacha20_random(rng) % i);
        size_t t = order[i]; order[i] = order[j]; order[j] = t;
    }

    size_t nbuf_size = size * 2;
    uint8_t *nbuf = malloc(nbuf_size);
    if (!nbuf) { free(order); free(cfg.blocks); return; }
    
    size_t *new_off = malloc(nb * sizeof(size_t));
    if (!new_off) { free(order); free(nbuf); free(cfg.blocks); return; }
    
    size_t out = 0;
    for (size_t oi = 0; oi < nb; oi++) {
        size_t bi = order[oi];
        blocknode *b = &cfg.blocks[bi];
        size_t blen = b->end - b->start;
        
        if (out + blen > nbuf_size) break;
        memcpy(nbuf + out, code + b->start, blen);
        new_off[bi] = out;
        out += blen;
    }

    /* Fix up all branch instructions */
    size_t tramp_base = out;
    size_t tramp_off = tramp_base;
    for (size_t oi = 0; oi < nb; oi++) {
        size_t bi = order[oi];
        blocknode *b = &cfg.blocks[bi];
        size_t blen = b->end - b->start;
        size_t block_new_offset = new_off[bi];
        
        for (size_t off = 0; off + 4 <= blen; off += 4) {
            size_t abs_off = block_new_offset + off;
            if (abs_off + 4 > out) break;
            
            arm64_inst_t inst;
            if (!decode_arm64(nbuf + abs_off, &inst) || !inst.valid) continue;
            
            if (!inst.is_control_flow) continue;
            
            size_t old_offset = b->start + off;
            int64_t old_target = old_offset + inst.target;
            
            size_t tgt_block = SIZE_MAX;
            for (size_t k = 0; k < nb; k++) {
                if (old_target >= (int64_t)cfg.blocks[k].start && 
                    old_target < (int64_t)cfg.blocks[k].end) {
                    tgt_block = k;
                    break;
                }
            }
            
            if (tgt_block == SIZE_MAX) continue;
            
            size_t new_target = new_off[tgt_block];
            int64_t new_disp = (int64_t)new_target - (int64_t)(abs_off + 4);
            
            bool fixed = false;
            
            if (inst.type == ARM_OP_BRANCH || inst.type == ARM_OP_BRANCH_LINK) {
                int64_t max_range = (1LL << 27);
                if (new_disp >= -max_range && new_disp < max_range && (new_disp % 4) == 0) {
                    uint32_t new_insn = inst.raw & 0xFC000000;
                    uint32_t imm26 = ((new_disp / 4) & 0x3FFFFFF);
                    new_insn |= imm26;
                    *(uint32_t*)(nbuf + abs_off) = new_insn;
                    fixed = true;
                } else {
                    /* Out-of-range B/BL: emit trampoline and re-point */
                    size_t tramp_start = tramp_off;
                    bool is_call = (inst.type == ARM_OP_BRANCH_LINK);
                    emit_trampoline_arm64(nbuf, &tramp_off, (uint64_t)old_target, is_call);
                    int64_t disp_to_tramp = (int64_t)tramp_start - (int64_t)(abs_off + 4);
                    if ((disp_to_tramp % 4) == 0) {
                        uint32_t new_insn = inst.raw & 0xFC000000;
                        uint32_t imm26 = ((disp_to_tramp / 4) & 0x3FFFFFF);
                        new_insn |= imm26;
                        *(uint32_t*)(nbuf + abs_off) = new_insn;
                        fixed = true;
                    }
                }
            } else if (inst.type == ARM_OP_BRANCH_COND || inst.type == ARM_OP_CBZ || 
                       inst.type == ARM_OP_CBNZ) {
                int64_t max_range = (1LL << 20);
                if (new_disp >= -max_range && new_disp < max_range && (new_disp % 4) == 0) {
                    uint32_t new_insn = inst.raw & 0xFF00001F;
                    uint32_t imm19 = ((new_disp / 4) & 0x7FFFF) << 5;
                    new_insn |= imm19;
                    *(uint32_t*)(nbuf + abs_off) = new_insn;
                    fixed = true;
                } else {
                    /* Leave conditional out-of-range unchanged for now */
                }
            } else if (inst.type == ARM_OP_TBZ || inst.type == ARM_OP_TBNZ) {
                int64_t max_range = (1LL << 15);
                if (new_disp >= -max_range && new_disp < max_range && (new_disp % 4) == 0) {
                    uint32_t new_insn = inst.raw & 0xFFF8001F;
                    uint32_t imm14 = ((new_disp / 4) & 0x3FFF) << 5;
                    new_insn |= imm14;
                    *(uint32_t*)(nbuf + abs_off) = new_insn;
                    fixed = true;
                }
            }
        }
    }
    size_t final_size = tramp_off;
    if (final_size <= size) {
        memcpy(code, nbuf, final_size);
        if (final_size < size) memset(code + final_size, 0, size - final_size);
    }

    free(order);
    free(new_off);
    free(nbuf);
    free(cfg.blocks);
}
#endif  // __aarch64__ || _M_ARM64

#if defined(__x86_64__) || defined(_M_X64)
/* Generate x86-64 trampoline mov rax, imm64 ; jmp/call rax */
static inline void emit_trampoline(uint8_t *buf, size_t *off, uint64_t target, bool is_call) {
    if (!buf || !off) return;
    
    buf[(*off)++] = 0x48; buf[(*off)++] = 0xB8;
    memcpy(buf + *off, &target, 8);
    *off += 8;
    if (is_call) { buf[(*off)++] = 0xFF; buf[(*off)++] = 0xD0; }
    else         { buf[(*off)++] = 0xFF; buf[(*off)++] = 0xE0; }
}

void shuffle_blocks(uint8_t *code, size_t size, void *rng) {
    if (!code || !rng) return;
    
#if defined(__aarch64__) || defined(_M_ARM64)
    shuffle_blocks_arm64(code, size, (chacha_state_t*)rng);
    return;
#elif defined(__x86_64__) || defined(_M_X64)
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

    if (size > SIZE_MAX / 2) { free(order); free(cfg.blocks); return; }
    
    uint8_t *nbuf = malloc(size * 2);
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
    
    info_t *patches = malloc(nb * 100 * sizeof(info_t));
    if (!patches) { free(order); free(new_off); free(nbuf); free(cfg.blocks); return; }
    size_t num_patches = 0;

    /* Collect all */
    for (size_t oi=0; oi<nb; oi++) {
        size_t bi=order[oi];
        blocknode *b=&cfg.blocks[bi];
        size_t blen=b->end-b->start;
        size_t off=new_off[bi];
        size_t cur=0;
        while (cur<blen && num_patches < nb * 100) {
            x86_inst_t inst;
            if (!decode_x86_withme(nbuf+off+cur, blen-cur, 0, &inst, NULL) || !inst.valid) { cur++; continue; }
            size_t inst_off = off+cur;
            size_t og_inst_off = b->start+cur; 
            int typ=0;
            if (inst.opcode[0]==0xE8) typ=2;
            else if (inst.opcode[0]==0xE9) typ=1;
            else if (inst.opcode[0]==0xEB) typ=5;
            else if (inst.opcode[0]>=0x70 && inst.opcode[0]<=0x7F) typ=3;
            else if (inst.opcode[0]==0x0F && inst.opcode_len>1 && inst.opcode[1]>=0x80) typ=4;
            if (!typ) { cur+=inst.len; continue; }

            int64_t oldtgt=0;
            if (typ==1||typ==2) oldtgt=og_inst_off+inst.len+(int32_t)inst.imm;
            else if (typ==3||typ==5) oldtgt=og_inst_off+inst.len+(int8_t)inst.imm;
            else if (typ==4) oldtgt=og_inst_off+inst.len+(int32_t)inst.imm;

            size_t tgt_blk=SIZE_MAX;
            for (size_t k=0;k<nb;k++) {
                if (oldtgt>=(int64_t)cfg.blocks[k].start && oldtgt<(int64_t)cfg.blocks[k].end) { tgt_blk=k; break; }
            }

            patches[num_patches].inst_off = inst_off;
            patches[num_patches].typ = typ;
            patches[num_patches].tgt = (tgt_blk!=SIZE_MAX) ? new_off[tgt_blk] : SIZE_MAX;
            patches[num_patches].oldtgt = oldtgt;
            patches[num_patches].is_call = (typ==2);
            num_patches++;
            
            cur+=inst.len;
        }
    }
    
    /* Apply patches in descending order to avoid overlap when expanding */
    if (num_patches > 1) {
        for (size_t i = 0; i < num_patches - 1; i++) {
            for (size_t j = i + 1; j < num_patches; j++) {
                if (patches[i].inst_off < patches[j].inst_off) {
                    info_t t = patches[i]; patches[i] = patches[j]; patches[j] = t;
                }
            }
        }
    }

    for (size_t i=0; i<num_patches; i++) {
        info_t *p = &patches[i];
        size_t inst_off = p->inst_off;
        int typ = p->typ;
        size_t tgt = p->tgt;
        
        if (tgt != SIZE_MAX) {
            /* Internal branch */
            int32_t rel=0;
            if (typ==1||typ==2) { 
                rel=(int32_t)(tgt-(inst_off+5)); 
                memcpy(nbuf+inst_off+1,&rel,4); 
            }
            else if (typ==3||typ==5) {
                int32_t d=(int32_t)(tgt-(inst_off+2));
                if (d>=-128 && d<=127) {
                    nbuf[inst_off+1]=(uint8_t)d;
                } else {
                    /* Expand! */
                    if (typ==3) {
                        /* Jcc rel8 -> Jcc rel32 */
                        uint8_t cc=nbuf[inst_off]&0x0F;
                        memmove(nbuf+inst_off+6, nbuf+inst_off+2, out - inst_off - 2);
                        nbuf[inst_off]=0x0F;
                        nbuf[inst_off+1]=0x80|cc;
                        rel=(int32_t)(tgt-(inst_off+6));
                        memcpy(nbuf+inst_off+2,&rel,4);
                        out += 4;
                    } else {
                        /* JMP rel8 -> JMP rel32 */
                        memmove(nbuf+inst_off+5, nbuf+inst_off+2, out - inst_off - 2);
                        nbuf[inst_off]=0xE9;
                        rel=(int32_t)(tgt-(inst_off+5));
                        memcpy(nbuf+inst_off+1,&rel,4);
                        out += 3;
                    }
                }
            }
            else if (typ==4) { 
                rel=(int32_t)(tgt-(inst_off+6)); 
                memcpy(nbuf+inst_off+2,&rel,4); 
            }
        } else {
            size_t tramp_start = tramp_off;
            emit_trampoline(nbuf,&tramp_off,(uint64_t)p->oldtgt,p->is_call);
            
            int32_t rel=(int32_t)(tramp_start-(inst_off+(typ==2||typ==1?5:2)));
            if (typ==2||typ==1) { 
                nbuf[inst_off]=p->is_call?0xE8:0xE9; 
                memcpy(nbuf+inst_off+1,&rel,4); 
            }
            else if (typ==3||typ==5) {
                int32_t d=(int32_t)(tramp_start-(inst_off+2));
                if (d>=-128 && d<=127) {
                    nbuf[inst_off+1]=(uint8_t)d;
                }
            }
            else if (typ==4) { 
                rel=(int32_t)(tramp_start-(inst_off+6)); 
                memcpy(nbuf+inst_off+2,&rel,4); 
            }
        }
    }
    
    free(patches);

    size_t final_size=tramp_off;
    if (final_size<=size) {
        memcpy(code,nbuf,final_size);
        if (final_size<size) memset(code+final_size,0,size-final_size);
    }

    free(order); free(new_off); free(nbuf); free(cfg.blocks);
#else
    (void)code; (void)size; (void)rng; /* no idea  */
#endif
}

static inline bool is_control_flow(const x86_inst_t *i) { 
    if (!i) return false;
    uint8_t op = i->opcode[0];
    if (op == 0xE8 || op == 0xE9 || op == 0xEB) return true; /*  call/jmp/shortjmp */
    if (op == 0xC3 || op == 0xCB || op == 0xC2 || op == 0xCA) return true; /*  ret */
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
    if ((op & 0xF8) == 0xB8) { /* mov reg, imm -> writes reg */
        uint8_t reg = op & 0x7;
        m |= (1u << reg);
    }
    if ((op & 0xF8) == 0x50) { /* push/pop family touches reg (and rsp) */
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

static inline bool has_memory_access(const x86_inst_t *i) {
    if (!i || !i->has_modrm) return false;
    uint8_t mod = (i->modrm >> 6) & 3;
    return mod != 3;  /* mod != 11 means memory operand */
}

static inline bool independent_inst(const x86_inst_t *a, const x86_inst_t *b) {
    if (!a || !b) return false;
    if (is_control_flow(a) || is_control_flow(b)) return false;
    
    /* Check register dependencies */
    uint16_t ma = inst_reg_mask(a);
    uint16_t mb = inst_reg_mask(b);
    if (ma & mb) return false;
    
    /* if both access memory, assume dependent */
    if (has_memory_access(a) && has_memory_access(b)) return false;
    
    /* If one writes memory and other reads/writes memory, assume dependent */
    if (has_memory_access(a) || has_memory_access(b)) {
        /* Check if either is a store (MOV to memory, ...) */
        uint8_t op_a = a->opcode[0];
        uint8_t op_b = b->opcode[0];
        if ((op_a == 0x89 || op_a == 0x88 || op_a == 0xC7) ||  /* Stores */
            (op_b == 0x89 || op_b == 0x88 || op_b == 0xC7)) {
            return false;  /* Assume  */
        }
    }
    
    return true;
}

static inline bool swap_adjacent_ranges(uint8_t *code, size_t size, size_t a_off, size_t a_len, size_t b_len) {
    if (a_off + a_len + b_len > size) return false;
    uint8_t *tmp = (uint8_t*)malloc(a_len);
    if (!tmp) return false;
    memcpy(tmp, code + a_off, a_len);
    memmove(code + a_off, code + a_off + a_len, b_len); /* move B forward into A's crib */
    memcpy(code + a_off + b_len, tmp, a_len);
    free(tmp);
    return true;
}

static int build_instr_win(uint8_t *code, size_t size, size_t offset,  /* long ass name  */
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

static void win_reorder(uint8_t *code, size_t size, x86_inst_t *win, 
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

#if defined(__aarch64__) || defined(_M_ARM64)
/* Apply ARM64-specific mutations register substitution, equivalences, expansions */
void scramble_arm64(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen,
                    muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity,
                    const engine_context_t *ectx) {
    if (!code || !rng || size < 4) return;
    
    size_t offset = 0;
    size_t changes = 0;
    size_t max_changes = (size / 4) / 10 + 1;
    
    if (liveness) boot_live(liveness);
    
    while (offset + 4 <= size && changes < max_changes) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            offset += 4;
            continue;
        }
        
        if (liveness) pulse_live(liveness, offset, &inst);
        
        /* Skip protected regions */
        if (is_protected(offset, ectx)) {
            offset += 4;
            continue;
        }
        
        bool mutated = false;
        uint32_t backup = inst.raw;
        
        if (!mutated && gen >= 3 && (chacha20_random(rng) % 100) < (mutation_intensity * 5)) {
            size_t temp_size = size;
            if (apply_arm64(code, &temp_size, size * 2, offset, &inst, liveness, rng)) {
                size_t expansion_len = temp_size - size;
                size = temp_size;
                mutated = true;
                changes++;
                if (log) drop_mut(log, offset, expansion_len + 4, MUT_EXPAND, gen, "arm64 expand");
                
                offset += expansion_len + 4;
                continue;
            }
        }
        
        if (inst.ring0 || inst.is_control_flow) {
            offset += 4;
            continue;
        }
        
        /* Register substitution */
        if (!mutated && liveness && (chacha20_random(rng) % 100) < (mutation_intensity * 10)) {
            bool can_substitute = false;
            uint8_t new_rd = inst.rd;
            uint8_t new_rn = inst.rn;
            uint8_t new_rm = inst.rm;
            
            if (inst.type == ARM_OP_MOV || inst.type == ARM_OP_ADD || 
                inst.type == ARM_OP_SUB || inst.type == ARM_OP_AND ||
                inst.type == ARM_OP_ORR || inst.type == ARM_OP_EOR) {
                
                if (inst.rd < 29 && cool_tmutation(inst.rd)) {
                    new_rd = jack_reg(liveness, inst.rd, offset, rng);
                    if (new_rd != inst.rd) can_substitute = true;
                }
                
                if (inst.rm < 32 && inst.rm < 29 && cool_tmutation(inst.rm)) {
                    new_rm = jack_reg(liveness, inst.rm, offset, rng);
                    if (new_rm != inst.rm) can_substitute = true;
                }
            }
            
            if (can_substitute) {
                uint32_t new_insn = inst.raw;
                new_insn = (new_insn & ~0x1F) | (new_rd & 0x1F);
                if (inst.rm < 32) {
                    new_insn = (new_insn & ~(0x1F << 16)) | ((new_rm & 0x1F) << 16);
                }
                
                arm64_inst_t test;
                uint8_t test_buf[4];
                *(uint32_t*)test_buf = new_insn;
                if (decode_arm64(test_buf, &test) && test.valid && !test.ring0) {
                    *(uint32_t*)(code + offset) = new_insn;
                    mutated = true;
                    changes++;
                    if (log) drop_mut(log, offset, 4, MUT_REG, gen, "arm64 reg subst");
                }
            }
        }
        
        /* MOV equivalents */
        if (!mutated && inst.type == ARM_OP_MOV && (chacha20_random(rng) % 100) < (mutation_intensity * 8)) {
            /* MOV Xd, Xm > ORR Xd, XZR, Xm */
            if (inst.rd < 29 && inst.rm < 29) {
                uint32_t new_insn = 0xAA0003E0;  /* ORR base encoding */
                new_insn |= (inst.is_64bit ? (1u << 31) : 0);
                new_insn |= (inst.rd & 0x1F);
                new_insn |= ((inst.rm & 0x1F) << 16);
                new_insn |= (31 << 5);  /* Rn = XZR */
                
                *(uint32_t*)(code + offset) = new_insn;
                mutated = true;
                changes++;
                if (log) drop_mut(log, offset, 4, MUT_EQUIV, gen, "mov->orr");
            }
        }
        
        /*  Zero Reg  */
        if (!mutated && inst.type == ARM_OP_MOV && inst.imm == 0 && 
            (chacha20_random(rng) % 100) < (mutation_intensity * 8)) {
            
            switch (chacha20_random(rng) % 4) {
                case 0: {  /* MOV Xd, #0 > EOR Xd, Xd, Xd */
                    uint32_t new_insn = 0xCA000000;
                    new_insn |= (inst.is_64bit ? (1u << 31) : 0);
                    new_insn |= (inst.rd & 0x1F);
                    new_insn |= ((inst.rd & 0x1F) << 5);
                    new_insn |= ((inst.rd & 0x1F) << 16);
                    *(uint32_t*)(code + offset) = new_insn;
                    mutated = true;
                    break;
                }
                case 1: {  /* MOV Xd, #0 > SUB Xd, Xd, Xd */
                    uint32_t new_insn = 0xCB000000;
                    new_insn |= (inst.is_64bit ? (1u << 31) : 0);
                    new_insn |= (inst.rd & 0x1F);
                    new_insn |= ((inst.rd & 0x1F) << 5);
                    new_insn |= ((inst.rd & 0x1F) << 16);
                    *(uint32_t*)(code + offset) = new_insn;
                    mutated = true;
                    break;
                }
                case 2: {  /* MOV Xd, #0 > AND Xd, Xd, #0 */
                    uint32_t new_insn = 0x92400000;
                    new_insn |= (inst.is_64bit ? (1u << 31) : 0);
                    new_insn |= (inst.rd & 0x1F);
                    new_insn |= ((inst.rd & 0x1F) << 5);
                    *(uint32_t*)(code + offset) = new_insn;
                    mutated = true;
                    break;
                }
                case 3: {  /* MOV Xd, #0 > MOVZ Xd, #0 */
                    uint32_t new_insn = 0xD2800000;
                    new_insn |= (inst.is_64bit ? (1u << 31) : 0);
                    new_insn |= (inst.rd & 0x1F);
                    *(uint32_t*)(code + offset) = new_insn;
                    mutated = true;
                    break;
                }
            }
            
            if (mutated) {
                changes++;
                if (log) drop_mut(log, offset, 4, MUT_EQUIV, gen, "zero equiv");
            }
        }
        
        /*  ADD/SUB Equivalents  */
        if (!mutated && (inst.type == ARM_OP_ADD || inst.type == ARM_OP_SUB) && 
            inst.imm == 0 && (chacha20_random(rng) % 100) < (mutation_intensity * 6)) {
            
            if (inst.type == ARM_OP_ADD && inst.rd < 29 && inst.rn < 29) {
                uint32_t new_insn = 0xAA0003E0;
                new_insn |= (inst.is_64bit ? (1u << 31) : 0);
                new_insn |= (inst.rd & 0x1F);
                new_insn |= ((inst.rn & 0x1F) << 16);
                new_insn |= (31 << 5);  
                *(uint32_t*)(code + offset) = new_insn;
                mutated = true;
                changes++;
                if (log) drop_mut(log, offset, 4, MUT_EQUIV, gen, "add0->mov");
            }
        }
        
        if (!mutated && inst.type == ARM_OP_CMP && inst.imm == 0 &&
            (chacha20_random(rng) % 100) < (mutation_intensity * 5)) {
            
            /* CMP Xn, #0 > SUBS XZR, Xn, #0 */
            /* Already in, we can swap to CMN tho! */
            /* CMP Xn, #0 ≡ CMN Xn, #0 (for zero) */
            uint32_t new_insn = 0xB1000000;  /*  CMN (adds) base */
            new_insn |= (inst.is_64bit ? (1u << 31) : 0);
            new_insn |= (31);  /*  Rd = XZR */
            new_insn |= ((inst.rn & 0x1F) << 5);
            *(uint32_t*)(code + offset) = new_insn;
            mutated = true;
            changes++;
            if (log) drop_mut(log, offset, 4, MUT_EQUIV, gen, "cmp->cmn");
        }
        
        /* NOP Insertion (if space allows) */
        if (!mutated && (chacha20_random(rng) % 100) < (mutation_intensity * 3)) {
            /* Insert NOP before current instruction  */
            /* For now, replace current instruction with NOP if it's cool */
            if (inst.type == ARM_OP_NOP || 
                (inst.type == ARM_OP_MOV && inst.rd == inst.rm)) {
                *(uint32_t*)(code + offset) = 0xD503201F;  /*  NOP */
                mutated = true;
                changes++;
                if (log) drop_mut(log, offset, 4, MUT_JUNK, gen, "nop");
            }
        }
        
        /* Validate mutation */
        if (mutated) {
            arm64_inst_t verify;
            if (!decode_arm64(code + offset, &verify) || !verify.valid || verify.ring0) {
                /* Rollback */
                *(uint32_t*)(code + offset) = backup;
                changes--;
            }
        }
        
        offset += 4;
    }
}
#endif  // __aarch64__ || _M_ARM64

void scramble_x86(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen,
                        muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity,
                        const engine_context_t *ectx) {
    if (!code || !rng) return;
    
    size_t offset = 0;
    size_t view_size = size; /* track effective size for memmove bounds */

    if (liveness) boot_live(liveness);

    if (gen >= 5 && (chacha20_random(rng) % 10) < (gen > 10 ? 6 : 3)) {
        unsigned chain_depth = 1 + (gen / 10);  
        if (chain_depth > 3) chain_depth = 3;   /*  Ka-Boom */
        
        size_t new_size = expand_chains(code, size, size * 2, liveness, rng, 
                                             chain_depth, mutation_intensity * 2);
        if (new_size > size && new_size <= size * 2) {
            if (log) drop_mut(log, 0, new_size, MUT_EXPAND, gen, "chain expand");
            /*  Note: size parameter is const, so we can't update it here */
            /*  when called needs to handle size changes */
        }
    }

    while (offset < size) {
        const int WINDOW_MAX = 8;
        x86_inst_t win[WINDOW_MAX];
        size_t win_offs[WINDOW_MAX];
        
        int win_cnt = build_instr_win(code, view_size, offset, win, win_offs, WINDOW_MAX);
        
        win_reorder(code, view_size, win, win_offs, win_cnt, rng, 
                                mutation_intensity, log, gen);

        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, view_size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0 || offset + inst.len > view_size) {
            offset++;
            continue;
        }

        if (liveness) pulse_live(liveness, offset, &inst);

        /* Skip protected regions (entry point, external calls, critical functions) */
        if (is_protected(offset, ectx)) {
            offset += inst.len;
            continue;
        }

        bool is_indirect_call = false;
        if (inst.has_modrm) {
            uint8_t mod = (inst.modrm >> 6) & 3;
            if (inst.opcode[0] == 0xFF && (mod != 0 || inst.has_sib)) {
                uint8_t reg = modrm_reg(inst.modrm);
                if (reg == 2 || reg == 4) {
                    is_indirect_call = true;
                }
            }
        }
        
        if (is_indirect_call) {
            offset += inst.len;
            continue;
        }

        bool mutated = false;

        if (inst.has_modrm && inst.len <= 8 && inst.len >= 2) {
            uint8_t reg = modrm_reg(inst.modrm);
            uint8_t rm = modrm_rm(inst.modrm);
            uint8_t mod = (inst.modrm >> 6) & 3;
            
            if (reg == 4 || reg == 5 || rm == 4 || rm == 5) {
                goto skip;
            }
            
            /* Only mutate MOV-like instructions, not arithmetic/shifts */
            bool is_safe_opcode = (inst.opcode[0] >= 0x88 && inst.opcode[0] <= 0x8F);
            
            /* Only substitute in reg-to-reg ops (mod==3) */
            if (mod == 3 && liveness && is_safe_opcode) {
                uint8_t new_reg = jack_reg(liveness, reg, offset, rng);
                uint8_t new_rm = jack_reg(liveness, rm, offset, rng);
                
                if (is_stackp(new_reg) || is_stackp(new_rm)) {
                    goto skip;
                }
                
                if (new_reg == reg && new_rm == rm) {
                    goto skip;
                }
                
                if (!has_implicit_rsp_use(inst.opcode[0]) &&
                    (inst.opcode[0] & 0xF8) != 0x50 && 
                    (inst.opcode[0] & 0xF8) != 0x58) {
                    
                    uint8_t temp_modrm = (inst.modrm & 0xC0) | (new_reg << 3) | new_rm;
                    
                    /* After prefixes + REX + opcode */
                    size_t modrm_pos_in_raw = 0;
                    modrm_pos_in_raw += inst.prefixes;
                    if (inst.rex) modrm_pos_in_raw++;
                    modrm_pos_in_raw += inst.opcode_len;
                    
                    if (modrm_pos_in_raw >= inst.len || modrm_pos_in_raw >= 15) {
                        goto skip;
                    }
                    
                    if (inst.raw[modrm_pos_in_raw] != inst.modrm) {
                        goto skip;
                    }
                    
                    size_t modrm_offset = offset + modrm_pos_in_raw;
                    
                    if (modrm_offset < size) {
                        uint8_t orig_byte = code[modrm_offset];
                        code[modrm_offset] = temp_modrm;
                        
                        x86_inst_t verify;
                        if (decode_x86_withme(code + offset, size - offset, 0, &verify, NULL) &&
                            verify.valid && 
                            !verify.ring0 &&
                            verify.has_modrm &&
                            verify.len == inst.len &&
                            verify.opcode[0] == inst.opcode[0] &&
                            ((verify.modrm >> 6) & 3) == 3) {
                            mutated = true;
                        } else {
                            code[modrm_offset] = orig_byte;
                        }
                    }
                }
            }
        }
        skip:
        if (!mutated) {
            /* XOR reg,reg equivalence */
            if (inst.opcode[0] == 0x31 && inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm)) {
                uint8_t mod = (inst.modrm >> 6) & 3;
                uint8_t reg = modrm_reg(inst.modrm);
                
                if (mod == 3 && reg != 4 && reg != 5) {
                    if (chacha20_random(rng) % 2) {
                        code[offset] = 0x29;
                    } else {
                        code[offset] = 0xB8 + reg;
                        if (offset + 5 <= view_size) memset(code + offset + 1, 0, 4);
                    }
                    if (!is_op_ok(code + offset)) {
                        if (offset + inst.len <= size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                    } else {
                        mutated = true;
                    }
                }
            }
            else if ((inst.opcode[0] & 0xF8) == 0xB8 && inst.imm == 0) {
                uint8_t reg = inst.opcode[0] & 0x7;
                if (reg != 4 && reg != 5) {
                    size_t new_len = 0;
                    
                    switch(chacha20_random(rng) % 3) {
                        case 0:
                            code[offset] = 0x31;
                            code[offset+1] = 0xC0 | (reg << 3) | reg;
                            new_len = 2;
                            break;
                        case 1:
                            code[offset] = 0x83;
                            code[offset+1] = 0xE0 | reg;
                            code[offset+2] = 0x00;
                            new_len = 3;
                            break;
                        case 2:
                            code[offset] = 0x29;
                            code[offset+1] = 0xC0 | (reg << 3) | reg;
                            new_len = 2;
                            break;
                    }
                    
                    if (new_len < inst.len && offset + inst.len <= view_size) {
                        memset(code + offset + new_len, 0x90, inst.len - new_len);
                    }
                    
                    if (!is_op_ok(code + offset)) {
                        if (offset + inst.len <= view_size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                    } else mutated = true;
                }
            }
            else if (inst.opcode[0] == 0x83 && inst.has_modrm && inst.raw[2] == 0x01) {
                uint8_t reg = modrm_rm(inst.modrm);
                uint8_t mod = (inst.modrm >> 6) & 3;
                
                if (mod == 3 && reg != 4 && reg != 5 && offset + 3 <= size) {
                    if (chacha20_random(rng) % 2) {
                        code[offset] = 0x48;
                        code[offset+1] = 0xFF;
                        code[offset+2] = 0xC0 | reg;
                        if (offset + 3 < size && inst.len > 3) {
                            size_t fill_len = (inst.len - 3 < size - offset - 3) ? inst.len - 3 : size - offset - 3;
                            if (fill_len > 0) memset(code + offset + 3, 0x90, fill_len);
                        }
                    } else {
                        if (offset + 4 <= size) {
                            code[offset] = 0x48;
                            code[offset+1] = 0x8D;
                            code[offset+2] = 0x40 | (reg << 3) | reg;
                            code[offset+3] = 0x01;
                            if (offset + 4 < size && inst.len > 4) {
                                size_t fill_len = (inst.len - 4 < size - offset - 4) ? inst.len - 4 : size - offset - 4;
                                if (fill_len > 0) memset(code + offset + 4, 0x90, fill_len);
                            }
                        }
                    }
                    if (!is_op_ok(code + offset)) {
                        if (offset + inst.len <= view_size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
                    } else mutated = true;
                }
            }
            else if (inst.opcode[0] == 0x8D && inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                uint8_t mod = (inst.modrm >> 6) & 3;
                
                if (reg == rm && reg != 4 && reg != 5 && rm != 4 && rm != 5 && inst.disp == 0 && !inst.has_sib && mod != 0) {
                    code[offset] = 0x89;
                    if (!is_op_ok(code + offset)) code[offset] = 0x8D;
                    else mutated = true;
                }
            }
            else if (inst.opcode[0] == 0x85 && inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == rm && reg != 4 && reg != 5) {
                    code[offset] = 0x39;
                    if (!is_op_ok(code + offset)) code[offset] = 0x85;
                    else mutated = true;
                }
            }
        }

        if (!mutated && (chacha20_random(rng) % 10) < mutation_intensity) {
            bool cool_to_insert = true; /*  PAUSE!! */
            if (liveness) {
                const uint8_t opaque_regs[] = {0, 1, 2, 6, 7};
                for (size_t i = 0; i < sizeof(opaque_regs); i++) {
                    if (liveness->regs[opaque_regs[i]].iz_live) {
                        cool_to_insert = false;
                        break;
                    }
                }
            }
            
            if (cool_to_insert) {
                uint8_t opq_buf[64];
                size_t opq_len;
                uint32_t random_seed = chacha20_random(rng);
                forge_ghost(opq_buf, &opq_len, random_seed, rng);

                uint8_t junk_buf[32];
                size_t junk_len;
                spew_trash(junk_buf, &junk_len, rng);

                if (opq_len + junk_len <= view_size - offset && offset + inst.len <= view_size) {
                    size_t move_len = view_size - offset - opq_len - junk_len;
                    /* Verify no buffer overflow */
                    if (offset + opq_len + junk_len <= view_size && 
                        move_len <= view_size &&
                        offset + opq_len + junk_len + move_len <= view_size) {
                        memmove(code + offset + opq_len + junk_len, code + offset, move_len);
                        memcpy(code + offset, opq_buf, opq_len);
                        memcpy(code + offset + opq_len, junk_buf, junk_len);
                        offset += opq_len + junk_len;
                        view_size += opq_len + junk_len;
                        mutated = true;
                        continue;
                    }
                }
            }
        }

        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 2)) {
            uint8_t junk_buf[32];
            size_t junk_len;
            spew_trash(junk_buf, &junk_len, rng);
            if (junk_len <= view_size - offset && offset + inst.len <= view_size) {
                size_t move_len = view_size - offset - junk_len;
                /* Verify no buffer overflow */
                if (offset + junk_len <= view_size && 
                    move_len <= view_size &&
                    offset + junk_len + move_len <= view_size) {
                    memmove(code + offset + junk_len, code + offset, move_len);
                    memcpy(code + offset, junk_buf, junk_len);
                    offset += junk_len;
                    view_size += junk_len;
                    mutated = true;
                    continue;
                }
            }
        }

        /* Instruction splitting expand MOV reg,imm into equivalent sequences */
        if (!mutated && (inst.opcode[0] & 0xF8) == 0xB8 && inst.imm != 0 && inst.len >= 5) {
            uint8_t target_reg = inst.opcode[0] & 0x7;
            if (target_reg == 4 || target_reg == 5) {
                offset += inst.len;
                continue;
            }
            switch(chacha20_random(rng) % 30) {
                case 0:  /* XOR + ADD */
                    if (offset + 10 <= view_size) {
                        code[offset] = 0x48; 
                        code[offset+1] = 0x31;
                        code[offset+2] = 0xC0 | (target_reg << 3) | target_reg;
                        code[offset+3] = 0x48;
                        code[offset+4] = 0x81;
                        code[offset+5] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 6) = (uint32_t)inst.imm;
                    }
                    break;
                case 1: 
                    if (offset + 13 <= view_size) {
                        uint32_t half = (uint32_t)inst.imm / 2;
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 3) = half;
                        code[offset+7] = 0x48; code[offset+8] = 0x81;
                        code[offset+9] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 10) = (uint32_t)inst.imm - half;
                    }
                    break;
                case 2: 
                    if (offset + 10 <= view_size) {
                        code[offset] = 0x48; code[offset+1] = 0x31;
                        code[offset+2] = 0xC0 | (target_reg << 3) | target_reg;
                        code[offset+3] = 0x48; code[offset+4] = 0x81;
                        code[offset+5] = 0xF0 | target_reg;
                        *(uint32_t*)(code + offset + 6) = ~(uint32_t)inst.imm;
                    }
                    break;
                case 3:
                    break;
                case 4:
                    if (offset + 10 <= view_size && inst.imm != 0x80000000 && inst.imm != 0) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 3) = -(int32_t)inst.imm;
                        code[offset+7] = 0x48; code[offset+8] = 0xF7;
                        code[offset+9] = 0xD8 | target_reg;
                    }
                    break;
                case 5: 
                    if (offset + 10 <= view_size && inst.imm > 0) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm - 1;
                        code[offset+7] = 0x48; code[offset+8] = 0xFF;
                        code[offset+9] = 0xC0 | target_reg;  /*  INC */
                    }
                    break;
                case 6: /* XOR reg,reg + XOR reg,imm (double XOR = value) */
                    if (offset + 17 <= view_size) {  /* Needs 17 bytes, not 14 */
                        code[offset] = 0x48; code[offset+1] = 0x31;
                        code[offset+2] = 0xC0 | (target_reg << 3) | target_reg;
                        code[offset+3] = 0x48; code[offset+4] = 0x81;
                        code[offset+5] = 0xF0 | target_reg;
                        *(uint32_t*)(code + offset + 6) = (uint32_t)inst.imm ^ 0xAAAAAAAA;
                        code[offset+10] = 0x48; code[offset+11] = 0x81;
                        code[offset+12] = 0xF0 | target_reg;
                        *(uint32_t*)(code + offset + 13) = 0xAAAAAAAA;
                    }
                    break;
                case 7: /* MOV reg, imm*2 + SHR reg, 1 */
                    if (offset + 10 <= view_size && (inst.imm & 1) == 0) {  /* Only if even */
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm * 2;
                        code[offset+7] = 0x48; code[offset+8] = 0xD1;
                        code[offset+9] = 0xE8 | target_reg; /* SHR 1 */
                    }
                    break;
                case 8: /* MOV reg, -imm + NEG reg (double NEG) */
                    if (offset + 10 <= view_size && inst.imm != 0x80000000) {
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 3) = -(int32_t)inst.imm;
                        code[offset+7] = 0x48; code[offset+8] = 0xF7;
                        code[offset+9] = 0xD8 | target_reg; /*  NEG */
                    }
                    break;
                case 9: /* MOV reg, part1 + ADD reg, part2 */
                    if (offset + 14 <= view_size) {
                        uint32_t part1 = (uint32_t)inst.imm / 3;
                        uint32_t part2 = (uint32_t)inst.imm - part1;
                        code[offset] = 0x48; code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 3) = part1;
                        code[offset+7] = 0x48; code[offset+8] = 0x81;
                        code[offset+9] = 0xC0 | target_reg;
                        *(uint32_t*)(code + offset + 10) = part2;
                    }
                    break;
            }
        
            if (!is_op_ok(code + offset)) {
                if (offset + inst.len <= view_size && inst.len > 0) memcpy(code + offset, inst.raw, inst.len);
            } else {
                mutated = true;
            }
        }        

        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 4)) {
            if (inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == 4 || reg == 5 || rm == 4 || rm == 5) {
                    offset += inst.len;
                    continue;
                }
            }
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

__attribute__((always_inline)) inline void _mut8(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, const engine_context_t *ectx) {
    if (!code || size == 0 || !rng) return;

    muttt_t mut_log;
    liveness_state_t liveness;
    init_mut(&mut_log);
    boot_live(&liveness);

    unsigned mutation_intensity = gen + 1;
    if (mutation_intensity > 20) mutation_intensity = 20;

#if defined(__x86_64__) || defined(_M_X64)
    size_t offset = 0;
    while (offset < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0 || offset + inst.len > size) {
            offset++;
            continue;
        }
        scramble_x86(code + offset, inst.len, rng, gen, &mut_log, &liveness, mutation_intensity, ectx);
        offset += inst.len;
    }

    if ((chacha20_random(rng) % 10) < (mutation_intensity / 2)) {
        flowmap cfg;
        sketch_flow(code, size, &cfg);
        flatline_flow(code, size, &cfg, rng);
        drop_mut(&mut_log, 0, size, MUT_FLATTEN, gen, "CF BS");
        free(cfg.blocks);
    }

    if ((chacha20_random(rng) % 10) < (mutation_intensity / 3)) {
        shuffle_blocks(code, size, rng);
        drop_mut(&mut_log, 0, size, MUT_REORDER, gen, "Block reorder");
    }

#elif defined(__aarch64__) || defined(_M_ARM64)
    /* Apply batch expansion first (gen 5+) */
    if (gen >= 5 && (chacha20_random(rng) % 10) < (gen > 10 ? 6 : 3)) {
        size_t new_size = expand_arm64(code, size, size * 2, &liveness, rng,
                                                     mutation_intensity * 2);
        if (new_size > size && new_size <= size * 2) {
            DBG("ARM64 batch expansion: %zu -> %zu bytes (+%zu)\n", 
                size, new_size, new_size - size);
            size = new_size;
            drop_mut(&mut_log, 0, new_size, MUT_EXPAND, gen, "arm64 batch expand");
        }
    }
    
    size_t offset = 0;
    while (offset + 4 <= size) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            offset += 4;
            continue;
        }
        
        if (liveness) pulse_live(&liveness, offset, &inst);
        
        /* Apply ARM64 mutations */
        scramble_arm64(code + offset, 4, rng, gen, &mut_log, &liveness, mutation_intensity, ectx);
        
        offset += 4;
    }

    /* Control flow mutations */
    if (gen > 5 && (chacha20_random(rng) % 10) < (gen > 15 ? 8 : 3)) {
        flowmap cfg;
        if (sketch_flow_arm64(code, size, &cfg)) {
            flatline_flow_arm64(code, size, &cfg, rng);
            drop_mut(&mut_log, 0, size, MUT_FLATTEN, gen, "arm64 control flow flattening");
            free(cfg.blocks);
        }
    }
    
    /* Block reordering */
    if (gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 5 : 2)) {
        shuffle_blocks_arm64(code, size, rng);
        drop_mut(&mut_log, 0, size, MUT_REORDER, gen, "arm64 block reorder");
    }
#else
    /* Do nothing */
#endif

    freeme(&mut_log);
}

/* Mutation Entry */
void mutate(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, engine_context_t *ctx) {
#if defined(__aarch64__) || defined(_M_ARM64)
    if (!code || size < 4 || !rng) return;
#else
    if (!code || size < 16 || !rng) return;
#endif

    if (ctx) {
        ctx->debug_code = code;
        ctx->debug_code_size = size;
    }

    _mut8(code, size, rng, gen, ctx);
}

static bool in_check(const uint8_t *code, size_t size, size_t original_size) {
    if (!code || size == 0) return false;
    
    /*  Check size growth (max 3x original) */
    if (size > original_size * 3) {
        DBG("size %zu exceeds 3x original %zu\n", size, original_size);
        return false;
    }
    
#if defined(ARCH_ARM)
    /*  Must be 4-byte aligned */
    if ((size % 4) != 0) {
        DBG("ARM64 size %zu not 4-byte aligned\n", size);
        return false;
    }
    
    size_t valid_count = 0;
    size_t privileged_count = 0;
    
    for (size_t offset = 0; offset + 4 <= size; offset += 4) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst)) {
            DBG("decode error at offset %zu\n", offset);
            return false;
        }
        
        if (!inst.valid) {
            DBG("invalid instruction at offset %zu\n", offset);
            return false;
        }
        
        if (inst.ring0) {
            privileged_count++;
            DBG("Yo: privileged instruction at offset %zu\n", offset);
        }
        
        valid_count++;
    }
    
    if (privileged_count > 0) {
        DBG("Yo: %zu privileged instructions found\n", privileged_count);
    }
    
    DBG("%zu valid ARM64 instructions\n", valid_count);
    return true;
    
#else  /*  x86-64 */
    size_t valid_count = 0;
    size_t offset = 0;
    
    while (offset < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL)) {
            offset++;
            continue;
        }
        
        if (!inst.valid) {
            offset++;
            continue;
        }
        
        if (inst.ring0) {
            DBG("Yo: privileged instruction at offset %zu\n", offset);
        }
        
        valid_count++;
        offset += inst.len;
    }
    
    DBG("%zu valid x86-64 instructions\n", valid_count);
    return valid_count > 0;
#endif
}

size_t decode_map(const uint8_t *code, size_t size, instr_info_t *out, size_t max) {
    size_t n = 0, off = 0;
    size_t cf_count = 0;
    size_t failed_decodes = 0;
    
#if defined(__x86_64__) || defined(_M_X64)
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
#elif defined(__aarch64__) || defined(_M_ARM64)
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
