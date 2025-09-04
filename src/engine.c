#include <wisp.h>

#if defined(ARCH_X86)
static uint8_t modrm_reg(uint8_t m) { return (m >> 3) & 7; }
static uint8_t modrm_rm(uint8_t m) { return m & 7; }
#endif

#if defined(ARCH_X86)
typedef struct {
    uint8_t rd_reegs[8];
    uint8_t wr_reegs[8];
    uint8_t regs_rd;
    uint8_t regs_wr;
    bool mem_rd;
    bool mem_wr;
    bool flag_rd;
    bool falg_wr; 
} x86_shit;

static const struct {
    uint32_t orgi_op;
    uint32_t clos_op;
    const char *desc;
} arm_equiv_table[] = {};
static const size_t arm_equiv_table_size = 0;

static void init_mut(muttt_t *log) { 
    log->cap = 64;
    log->count = 0;
    log->entries = malloc(log->cap * sizeof(mutx_entry_t));
    if (!log->entries) panic();
}

static void logme(muttt_t *log, size_t offset, size_t length,  
                        mutx_type_t type, uint32_t gen, const char *desc) {
    if (log->count >= log->cap) {
        log->cap *= 2;
        void *tmp = realloc(log->entries, log->cap * sizeof(mutx_entry_t));
        if (!tmp) panic();
        log->entries = tmp;
    }
    
    log->entries[log->count].offset = offset;
    log->entries[log->count].length = length;
    log->entries[log->count].type = type;
    log->entries[log->count].gen = gen;
    strncpy(log->entries[log->count].des, desc, 63);
    log->entries[log->count].des[63] = '\0';
    log->count++;
}

static void dump(const muttt_t *log) {
    static const char *tags[] = {
        "SUB", "EQUIV", "PRED", "DEAD",
        "SPLIT", "OBFUSC", "FLATTEN", "REORDER", "JUNK"
    };

    DBG("\n--[Gen %u ]--", log->count ? log->entries[0].gen : 0);
    DBG("%-6s %-6s %-14s %s", "Off", "Len", "Tag", "Note");
    DBG("------ ------ -------------- --------------------");

    for (size_t i = 0; i < log->count; i++) {
        mutx_entry_t *e = &log->entries[i];
        DBG("0x%04zx %-6zu %-14s %s", e->offset, e->length, tags[e->type], e->des);
    }

    DBG("[*] %zu mutations tracked", log->count);
}

static void freeme(muttt_t *log) {
    if (log->entries) {
        free(log->entries);
        log->entries = NULL;
    }
    log->count = 0;
    log->cap = 0;
}

static void init_live(liveness_state_t *state) {
    memset(state, 0, sizeof(*state));
    state->num_regs = 16;
    

    for (int i = 0; i < 16; i++) {
        state->regs[i].reg = i;
        state->regs[i].iz_live = false;
        state->regs[i].iz_vol = (i >= 0 && i <= 5);
        state->regs[i].def_offset = 0;
        state->regs[i].last_use = 0;
    }
}

static void update_liveness(liveness_state_t *state, size_t offset, const void *inst_ptr) {
#if defined(ARCH_X86)
    const x86_inst_t *inst = (const x86_inst_t *)inst_ptr;
    if (!inst->has_modrm) return;
    
    uint8_t reg = modrm_reg(inst->modrm);
    uint8_t rm = modrm_rm(inst->modrm);
    
    bool is_def = false;
    if (inst->opcode[0] == 0x89 || inst->opcode[0] == 0x8B || // MOV
        inst->opcode[0] == 0x01 || inst->opcode[0] == 0x03 || // ADD
        inst->opcode[0] == 0x29 || inst->opcode[0] == 0x2B || // SUB
        inst->opcode[0] == 0x31 || inst->opcode[0] == 0x33 || // XOR
        inst->opcode[0] == 0x21 || inst->opcode[0] == 0x23 || // AND
        inst->opcode[0] == 0x09 || inst->opcode[0] == 0x0B) { // OR
        is_def = true;
    }
    
    if (is_def) {
        state->regs[reg].iz_live = true;
        state->regs[reg].def_offset = offset;
    } else {
        state->regs[reg].last_use = offset;
    }
    
    if (is_def) {
        state->regs[rm].iz_live = true;
        state->regs[rm].def_offset = offset;
    } else {
        state->regs[rm].last_use = offset;
    }
#endif
}

static bool iz_reg_sf(const liveness_state_t *state, uint8_t reg, size_t current_offset) {
    if (reg >= 16) return false;
    
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

static uint8_t pick_live_reg(const liveness_state_t *state, uint8_t original_reg, 
                                              size_t current_offset, chacha_state_t *rng) {
    if (original_reg == 4 || original_reg == 5) { // RSP/RBP
        return original_reg;
    }
    uint8_t candidates[8] = {0};
    uint8_t num_candidates = 0;
    for (uint8_t reg = 0; reg < 8; reg++) {
        if (reg == original_reg) continue;
        if (reg == 4 || reg == 5) continue;
        if (!state->regs[reg].iz_live || 
            (current_offset - state->regs[reg].last_use > 16)) {
            candidates[num_candidates++] = reg;
        }
    }
    return (num_candidates > 0) ? 
           candidates[chacha20_random(rng) % num_candidates] : 
           original_reg;
}

__attribute__((always_inline)) inline bool it_op(const uint8_t *code) {
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

__attribute__((always_inline)) inline bool it_chunk(const uint8_t *code, size_t max_len) {
    size_t offset = 0;
    while (offset < max_len) {
        size_t len = snap_instr_len(code + offset, max_len - offset);
        if (!len || offset + len > max_len || !it_op(code + offset)) return false;
        offset += len;
    }
    return offset == max_len;
}

__attribute__((always_inline)) inline size_t snap_instr_len(const uint8_t *code, size_t maxlen) {
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
__attribute__((always_inline)) inline void ic_opaque_x86(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
    uint8_t reg1 = chacha20_random(rng) % 8;
    uint8_t reg2 = chacha20_random(rng) % 8;
    uint8_t reg3 = chacha20_random(rng) % 8;

    while (reg2 == reg1) reg2 = chacha20_random(rng) % 8;
    while (reg3 == reg1 || reg3 == reg2) reg3 = chacha20_random(rng) % 8;

    switch (chacha20_random(rng) % 8) {
        case 0: { // XOR + TEST + JZ (always taken)
            buf[0] = 0x48; buf[1] = 0x31; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            *(uint32_t*)(buf + 8) = value;
            *len = 12;
            break;
        }
        case 1: { // MOV + XOR + TEST + JNZ (never taken)
            buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xC0 | (reg2 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x31; buf[5] = 0xC0 | (reg2 << 3) | reg2;
            buf[6] = 0x48; buf[7] = 0x85; buf[8] = 0xC0 | (reg2 << 3) | reg2;
            buf[9] = 0x0F; buf[10] = 0x85;
            *(uint32_t*)(buf + 11) = value;
            *len = 15;
            break;
        }
        case 2: { // LEA + CMP + JE (always taken)
            buf[0] = 0x48; buf[1] = 0x8D; buf[2] = 0x00 | (reg1 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x39; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            *(uint32_t*)(buf + 8) = value;
            *len = 12;
            break;
        }
        case 3: { // SUB + TEST + JZ (always taken)
            buf[0] = 0x48; buf[1] = 0x29; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            *(uint32_t*)(buf + 8) = value;
            *len = 12;
            break;
        }
        case 4: { // AND + TEST + JZ (always taken)
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xE0 | reg1; buf[3] = 0x00;
            buf[4] = 0x48; buf[5] = 0x85; buf[6] = 0xC0 | (reg1 << 3) | reg1;
            buf[7] = 0x0F; buf[8] = 0x84;
            *(uint32_t*)(buf + 9) = value;
            *len = 13;
            break;
        }
        case 5: { // PUSH + POP + TEST + JZ (always taken)
            buf[0] = 0x50 | reg1;
            buf[1] = 0x58 | reg1;
            buf[2] = 0x48; buf[3] = 0x85; buf[4] = 0xC0 | (reg1 << 3) | reg1;
            buf[5] = 0x0F; buf[6] = 0x84;
            *(uint32_t*)(buf + 7) = value;
            *len = 11;
            break;
        }
        case 6: { // XCHG + TEST + JZ (always taken)
            buf[0] = 0x48; buf[1] = 0x87; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0 | (reg1 << 3) | reg1;
            buf[6] = 0x0F; buf[7] = 0x84;
            *(uint32_t*)(buf + 8) = value;
            *len = 12;
            break;
        }
        case 7: { // ADD + SUB + TEST + JZ (always taken)
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xC0 | reg1; buf[3] = 0x00;
            buf[4] = 0x48; buf[5] = 0x83; buf[6] = 0xE8 | reg1; buf[7] = 0x00;
            buf[8] = 0x48; buf[9] = 0x85; buf[10] = 0xC0 | (reg1 << 3) | reg1;
            buf[11] = 0x0F; buf[12] = 0x84;
            *(uint32_t*)(buf + 13) = value;
            *len = 17;
            break;
        }
    }
}

static void x86_operands(const x86_inst_t *inst, x86_shit *info) {
    memset(info, 0, sizeof(*info));
    if (inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t rm = modrm_rm(inst->modrm);
        if (inst->opcode[0] == 0x89) {
            info->rd_reegs[info->regs_rd++] = reg;
            info->wr_reegs[info->regs_wr++] = rm;
        }
        else if (inst->opcode[0] == 0x8B) {
            info->rd_reegs[info->regs_rd++] = rm;
            info->wr_reegs[info->regs_wr++] = reg;
        }
        else if (inst->opcode[0] == 0x01 || inst->opcode[0] == 0x03 ||
                 inst->opcode[0] == 0x29 || inst->opcode[0] == 0x2B ||
                 inst->opcode[0] == 0x21 || inst->opcode[0] == 0x23 ||
                 inst->opcode[0] == 0x09 || inst->opcode[0] == 0x0B ||
                 inst->opcode[0] == 0x31 || inst->opcode[0] == 0x33 ||
                 inst->opcode[0] == 0x39 || inst->opcode[0] == 0x3B ||
                 inst->opcode[0] == 0x85 || inst->opcode[0] == 0x87) {
            info->rd_reegs[info->regs_rd++] = reg;
            info->rd_reegs[info->regs_rd++] = rm;
            info->wr_reegs[info->regs_wr++] = reg;
            info->falg_wr = true;
        }
        else if (inst->opcode[0] == 0x8D) {
            info->rd_reegs[info->regs_rd++] = rm;
            info->wr_reegs[info->regs_wr++] = reg;
        }
        else if (inst->opcode[0] == 0x87) {
            info->rd_reegs[info->regs_rd++] = reg;
            info->rd_reegs[info->regs_rd++] = rm;
            info->wr_reegs[info->regs_wr++] = reg;
            info->wr_reegs[info->regs_wr++] = rm;
        }
        if (inst->disp_size > 0 || inst->has_sib) {
            info->mem_rd = true;
            if (inst->opcode[0] == 0x89 || inst->opcode[0] == 0xC7) info->mem_wr = true;
        }
    }
    if (inst->opcode[0] >= 0xB8 && inst->opcode[0] <= 0xBF) {
        info->wr_reegs[info->regs_wr++] = inst->opcode[0] - 0xB8;
    }
    if (inst->opcode[0] == 0x50 || inst->opcode[0] == 0x58) {
        uint8_t reg = inst->opcode[0] & 0x7;
        if ((inst->opcode[0] & 0xF8) == 0x50) info->rd_reegs[info->regs_rd++] = reg;
        else info->wr_reegs[info->regs_wr++] = reg;
    }
    if (inst->is_control_flow) info->flag_rd = true;
}
#endif

static const struct {
    uint8_t orgi_op; 
    uint8_t clos_op;
    const char *desc;
} x86_tb[] = {
    {0x31, 0x29, "xor->sub (zero reg)"}, 
    {0x29, 0x31, "sub->xor (zero reg)"},
    {0x31, 0x33, "xor->xor (swap)"},
    {0x89, 0x8B, "mov r/m,r <-> mov r,r/m"},
    {0x8B, 0x89, "mov r,r/m <-> mov r/m,r"},
    {0x90, 0x87, "nop <-> xchg eax,eax"},
    {0x87, 0x90, "xchg eax,eax <-> nop"},
    {0x50, 0xFF, "push reg <-> push via FF / pop via 8F"},

};
static const size_t x86_tb_size = sizeof(x86_tb)/sizeof(x86_tb[0]);

__attribute__((always_inline)) inline void ic_opaque_arm(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
    uint8_t reg1 = chacha20_random(rng) % 31; // avoid XZR
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
            // b.ne target
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

__attribute__((always_inline)) inline void ic_junk_x86(uint8_t *buf, size_t *len, chacha_state_t *rng) {
    uint8_t reg1 = chacha20_random(rng) % 8;
    uint8_t reg2 = chacha20_random(rng) % 8;
    uint8_t reg3 = chacha20_random(rng) % 8;
    
    while (reg2 == reg1) reg2 = chacha20_random(rng) % 8;
    while (reg3 == reg1 || reg3 == reg2) reg3 = chacha20_random(rng) % 8;
    
    uint8_t imm8 = chacha20_random(rng) & 0xFF;
    uint16_t imm16 = chacha20_random(rng) & 0xFFFF;
    uint32_t imm32 = chacha20_random(rng);
    
    switch(chacha20_random(rng) % 15) {
        case 0: { 
            buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            *len = 3;
            break;
        }
        case 1: { 
            buf[0] = 0x48; buf[1] = 0x31; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            *len = 3;
            break;
        }
        case 2: { 
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xC0 | reg1; buf[3] = 0x00;
            *len = 4;
            break;
        }
        case 3: { 
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xE8 | reg1; buf[3] = 0x00;
            *len = 4;
            break;
        }
        case 4: { 
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xE0 | reg1; buf[3] = 0xFF;
            *len = 4;
            break;
        }
        case 5: {
            buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xC8 | reg1; buf[3] = 0x00;
            *len = 4;
            break;
        }
        case 6: {
            buf[0] = 0x48; buf[1] = 0x8D; buf[2] = 0x00 | (reg1 << 3) | reg1;
            *len = 3;
            break;
        }
        case 7: { 
            buf[0] = 0x48; buf[1] = 0x39; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            *len = 3;
            break;
        }
        case 8: {
            buf[0] = 0x48; buf[1] = 0x85; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            *len = 3;
            break;
        }
        case 9: { 
            buf[0] = 0x48; buf[1] = 0x87; buf[2] = 0xC0 | (reg1 << 3) | reg1;
            *len = 3;
            break;
        }
        case 10: { 
            buf[0] = 0x50 | reg1; buf[1] = 0x58 | reg1;
            *len = 2;
            break;
        }
        case 11: { 
            uint8_t nop_count = 1 + (chacha20_random(rng) % 4);
            for (int i = 0; i < nop_count; i++) {
                buf[i] = 0x90;
            }
            *len = nop_count;
            break;
        }
        case 12: { 
            buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xC0 | (reg1 << 3) | reg2;
            *len = 3;
            break;
        }
        case 13: { 
            buf[0] = 0x48; buf[1] = 0x01; buf[2] = 0xC0 | (reg1 << 3) | reg2;
            *len = 3;
            break;
        }
        case 14: {
            buf[0] = 0x48; buf[1] = 0x29; buf[2] = 0xC0 | (reg1 << 3) | reg2;
            *len = 3;
            break;
        }
    }
}

__attribute__((always_inline)) inline void ic_junk_arm(uint8_t *buf, size_t *len, chacha_state_t *rng) {
    uint8_t reg1 = chacha20_random(rng) % 31;
    uint8_t reg2 = chacha20_random(rng) % 31;
    uint8_t reg3 = chacha20_random(rng) % 31;
    
    while (reg2 == reg1) reg2 = chacha20_random(rng) % 31;
    while (reg3 == reg1 || reg3 == reg2) reg3 = chacha20_random(rng) % 31;
    
    uint16_t imm12 = chacha20_random(rng) & 0xFFF;
    uint16_t imm16 = chacha20_random(rng) & 0xFFFF;
    
    switch(chacha20_random(rng) % 10) {
        case 0: { 
            *(uint32_t*)buf = 0xAA000000 | (reg1 << 5) | (reg1 << 16);
            *len = 4;
            break;
        }
        case 1: {
            *(uint32_t*)buf = 0x91000000 | (reg1 << 5) | (reg1 << 16);
            *len = 4;
            break;
        }
        case 2: {
            *(uint32_t*)buf = 0xD1000000 | (reg1 << 5) | (reg1 << 16);
            *len = 4;
            break;
        }
        case 3: {
            *(uint32_t*)buf = 0x8A000000 | (reg1 << 5) | (reg1 << 16) | (reg1 << 10);
            *len = 4;
            break;
        }
        case 4: { 
            *(uint32_t*)buf = 0xAA000000 | (reg1 << 5) | (reg1 << 16) | (reg1 << 10);
            *len = 4;
            break;
        }
        case 5: { 
            *(uint32_t*)buf = 0xCA000000 | (reg1 << 5) | (reg1 << 16) | (reg1 << 10);
            *len = 4;
            break;
        }
        case 6: { 
            *(uint32_t*)buf = 0xEB000000 | (reg1 << 16) | (reg1 << 5);
            *len = 4;
            break;
        }
        case 7: { 
            *(uint32_t*)buf = 0xEA000000 | (reg1 << 16) | (reg1 << 5);
            *len = 4;
            break;
        }
        case 8: { 
            *(uint32_t*)buf = 0xD503201F;
            *len = 4;
            break;
        }
        case 9: {
            *(uint32_t*)buf = 0xD2800000 | (reg1 << 5) | (imm12 << 10);
            *len = 4;
            break;
        }
    }
}

__attribute__((always_inline)) inline void Opaque(uint8_t *buf, size_t *len, uint32_t value, chacha_state_t *rng) {
#if defined(ARCH_X86)
    ic_opaque_x86(buf, len, value, rng);
#elif defined(ARCH_ARM)
    ic_opaque_arm(buf, len, value, rng);
#endif
}

__attribute__((always_inline)) inline void genmesomejunk(uint8_t *buf, size_t *len, chacha_state_t *rng) {
#if defined(ARCH_X86)
    if (notsafe) {
        if (chacha20_random(rng) % 2 == 0) {
            buf[0] = 0x90; *len = 1; // NOP
        } else {
            uint8_t reg = chacha20_random(rng) % 8;
            buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0xC0 | (reg << 3) | reg; *len = 3; // mov reg, reg
        }
        return;
    }
    ic_junk_x86(buf, len, rng);
#elif defined(ARCH_ARM)
    if (notsafe) {
        if (chacha20_random(rng) % 2 == 0) {
            *(uint32_t*)buf = 0xD503201F; *len = 4;
        } else {
            uint8_t reg = chacha20_random(rng) % 16;
            *(uint32_t*)buf = 0xAA0003E0 | (reg << 5) | (reg << 16); *len = 4; // mov reg, reg
        }
        return;
    }
    ic_junk_arm(buf, len, rng);
#endif
}


static void cfg_shit(uint8_t *code, size_t size, cfg_t *cfg) { 
    if (!code || !cfg || size < 16) {
        if (cfg) {
            cfg->blocks = NULL;
            cfg->num_blocks = 0;
        }
        return;
    }
    
    cfg->blocks = calloc(32, sizeof(basic_block_t));
    if (!cfg->blocks) panic();
    cfg->num_blocks = 0;
    
    size_t offset = 0;
    size_t end = 0;
    bool in_block = false;
    
    while (offset < size) {
        if (offset >= size) break;
        
        size_t len = snap_instr_len(code + offset, size - offset);
        if (!len) {
            offset++;
            continue;
        }
        
        if (offset + len > size) {
            offset++;
            continue;
        }
        
        uint8_t *instr = code + offset;
        bool is_control_flow = false;

#if defined(ARCH_X86)
        x86_inst_t x86_inst;
        if (decode_x86_withme(instr, size - offset, 0, &x86_inst, NULL)) {
            is_control_flow = (x86_inst.opcode[0] == 0xE8 || x86_inst.opcode[0] == 0xE9 || // CALL/JMP
                             (x86_inst.opcode[0] >= 0x70 && x86_inst.opcode[0] <= 0x7F) || // Jcc
                             (x86_inst.opcode[0] == 0x0F && x86_inst.opcode[1] >= 0x80 && x86_inst.opcode[1] <= 0x8F) || // Jcc
                             x86_inst.opcode[0] == 0xC3 || x86_inst.opcode[0] == 0xC2); // RET
        }
#elif defined(ARCH_ARM)
        arm64_inst_t arm_inst;
        if (decode_arm64(instr, &arm_inst)) {
            is_control_flow = (arm_inst.type != ARM_OP_NONE);
        }
#endif

        if (!in_block) {
            end = offset;
            in_block = true;
        }
        
        if (is_control_flow) {
            // End
            cfg->blocks[cfg->num_blocks].start = end;
            cfg->blocks[cfg->num_blocks].end = offset + len;
            cfg->blocks[cfg->num_blocks].id = cfg->num_blocks;
            cfg->num_blocks++;
            in_block = false;
        }
        
        offset += len;
    }
    
    if (in_block) {
        cfg->blocks[cfg->num_blocks].start = end;
        cfg->blocks[cfg->num_blocks].end = offset;
        cfg->blocks[cfg->num_blocks].id = cfg->num_blocks;
        cfg->num_blocks++;
    }
    
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        if (cfg->blocks[i].end == 0 || cfg->blocks[i].end > size) continue;
        size_t safe_offset = cfg->blocks[i].end - 1;
        if (safe_offset >= size) continue;
        size_t instr_len = snap_instr_len(code + safe_offset, size - safe_offset);
        if (instr_len == 0 || instr_len > cfg->blocks[i].end) continue;
        uint8_t *last_instr = code + cfg->blocks[i].end - instr_len;
        if (last_instr < code || last_instr >= code + size) continue;
        size_t remaining_size = size - (last_instr - code);
        if (remaining_size == 0) continue;
#if defined(ARCH_X86)
        x86_inst_t x86_inst;
        if (decode_x86_withme(last_instr, remaining_size, 0, &x86_inst, NULL)) {
            if (x86_inst.opcode[0] == 0xE9) {
                int32_t rel = (int32_t)x86_inst.imm;
                size_t target = (cfg->blocks[i].end) + rel;
                size_t found = (size_t)-1;
                for (size_t k = 0; k < cfg->num_blocks; k++) {
                    if (cfg->blocks[k].start == target) { found = k; break; }
                }
                if (found != (size_t)-1) {
                    cfg->blocks[i].successors[0] = found;
                    cfg->blocks[i].num_successors = 1;
                } else {
                    cfg->blocks[i].is_exit = true;
                }
            } else if (x86_inst.opcode[0] >= 0x70 && x86_inst.opcode[0] <= 0x7F) {
                size_t fall = i + 1 < cfg->num_blocks ? i + 1 : i;
                int8_t rel = (int8_t)x86_inst.opcode[1];
                size_t target = (cfg->blocks[i].end) + rel;
                size_t found = (size_t)-1;
                for (size_t k = 0; k < cfg->num_blocks; k++) {
                    if (cfg->blocks[k].start == target) { found = k; break; }
                }
                cfg->blocks[i].successors[0] = fall;
                if (found != (size_t)-1) {
                    cfg->blocks[i].successors[1] = found;
                    cfg->blocks[i].num_successors = 2;
                } else {
                    cfg->blocks[i].num_successors = 1;
                }
            } else if (x86_inst.opcode[0] == 0x0F && x86_inst.opcode[1] >= 0x80 && x86_inst.opcode[1] <= 0x8F) {
                int32_t rel = (int32_t)x86_inst.imm;
                size_t target = (cfg->blocks[i].end) + rel;
                size_t found = (size_t)-1;
                for (size_t k = 0; k < cfg->num_blocks; k++) {
                    if (cfg->blocks[k].start == target) { found = k; break; }
                }
                size_t fall = i + 1 < cfg->num_blocks ? i + 1 : i;
                cfg->blocks[i].successors[0] = fall;
                if (found != (size_t)-1) {
                    cfg->blocks[i].successors[1] = found;
                    cfg->blocks[i].num_successors = 2;
                } else {
                    cfg->blocks[i].num_successors = 1;
                }
            } else if (x86_inst.opcode[0] == 0xC3 || x86_inst.opcode[0] == 0xC2) {
                cfg->blocks[i].is_exit = true;
            } else if (x86_inst.opcode[0] == 0xFF) {
                cfg->blocks[i].is_exit = true;
                cfg->blocks[i].num_successors = 0;
            } else {
                if (i < cfg->num_blocks - 1) {
                    cfg->blocks[i].successors[0] = i + 1;
                    cfg->blocks[i].num_successors = 1;
                } else {
                    cfg->blocks[i].is_exit = true;
                }
            }
        }
#endif
    }
    cfg->entry_block = 0;
    cfg->exit_block = cfg->num_blocks - 1;
}

static void flattenme(uint8_t *code, size_t size, cfg_t *cfg, chacha_state_t *rng) {
    if (cfg->num_blocks < 3) return;
    size_t max_blocks = cfg->num_blocks;
    size_t buf_sz = size + 128 + max_blocks * 8;
    uint8_t *nbuf = malloc(buf_sz);
    if (!nbuf) panic();
    size_t *bmap = malloc(max_blocks * sizeof(size_t));
    if (!bmap) { free(nbuf); panic(); }
    size_t *order = malloc(max_blocks * sizeof(size_t));
    if (!order) { free(nbuf); free(bmap); panic(); }
    for (size_t i = 0; i < max_blocks; i++) order[i] = i;
    for (size_t i = max_blocks - 1; i > 0; i--) {
        size_t j = rand_n(rng, i + 1);
        size_t t = order[i]; order[i] = order[j]; order[j] = t;
    }
    typedef struct { size_t off; size_t blki; int typ; size_t orig; } patch_t;
    patch_t patch[64]; size_t np = 0;
    size_t out = 0;
    for (size_t i = 0; i < max_blocks; i++) {
        size_t bi = order[i];
        basic_block_t *b = &cfg->blocks[bi];
        bmap[bi] = out;
        size_t blen = b->end - b->start;
        memcpy(nbuf + out, code + b->start, blen);
        // scan for jmp/call/jcc at end
        if (blen > 0) {
            x86_inst_t inst;
            if (decode_x86_withme(nbuf + out + blen - 16, 16, 0, &inst, NULL) && inst.valid && inst.len && blen >= inst.len) {
                uint8_t *p = nbuf + out + blen - inst.len;
                if (inst.opcode[0] == 0xE9) patch[np++] = (patch_t){p - nbuf, bi, 1, inst.imm};
                else if (inst.opcode[0] == 0xE8) patch[np++] = (patch_t){p - nbuf, bi, 2, inst.imm};
                else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) patch[np++] = (patch_t){p - nbuf, bi, 3, inst.opcode[1]};
                else if (inst.opcode[0] == 0x0F && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) patch[np++] = (patch_t){p - nbuf, bi, 4, inst.imm};
            }
        }
        out += blen;
    }
    // patch all jumps/calls
    for (size_t i = 0; i < np; i++) {
        patch_t *p = &patch[i];
        size_t src = p->off;
        size_t bi = p->blki;
        size_t orig_tgt = 0;
        if (p->typ == 1 || p->typ == 2 || p->typ == 4) orig_tgt = cfg->blocks[bi].end + p->orig;
        else if (p->typ == 3) orig_tgt = cfg->blocks[bi].end + (int8_t)p->orig;
        size_t tgt_blk = (size_t)-1;
        for (size_t k = 0; k < max_blocks; k++) {
            if (orig_tgt >= cfg->blocks[k].start && orig_tgt < cfg->blocks[k].end) { tgt_blk = k; break; }
        }
        if (tgt_blk == (size_t)-1) continue;
        size_t new_tgt = bmap[tgt_blk];
        size_t rel = 0;
        if (p->typ == 1 || p->typ == 2 || p->typ == 4) rel = (int32_t)(new_tgt - (src + (p->typ == 3 ? 2 : (p->typ == 1 || p->typ == 2 ? 5 : 6))));
        else if (p->typ == 3) rel = (int8_t)(new_tgt - (src + 2));
        if (p->typ == 1) *(int32_t*)(nbuf + src + 1) = rel;
        else if (p->typ == 2) *(int32_t*)(nbuf + src + 1) = rel;
        else if (p->typ == 3) nbuf[src + 1] = (uint8_t)rel;
        else if (p->typ == 4) *(int32_t*)(nbuf + src + 2) = rel;
    }
    for (size_t i = 0; i < np; i++) {
        patch_t *p = &patch[i];
        size_t src = p->off;
        x86_inst_t inst;
        if (!decode_x86_withme(nbuf + src, 16, 0, &inst, NULL) || !inst.valid) continue;
        size_t tgt = 0;
        if (p->typ == 1 || p->typ == 2 || p->typ == 4) tgt = src + inst.len + *(int32_t*)(nbuf + src + (p->typ == 4 ? 2 : 1));
        else if (p->typ == 3) tgt = src + inst.len + (int8_t)nbuf[src + 1];
        if (tgt >= out) { free(nbuf); free(bmap); free(order); return; }
    }
    if (out <= size) {
        memcpy(code, nbuf, out);
        memset(code + out, 0, size - out);
    }
    free(nbuf); free(bmap); free(order);
}

#if defined(ARCH_X86)
static uint8_t random_gpr(chacha_state_t *rng) {
    return chacha20_random(rng) % 8;
}

/// Why ? No fuckin idea 

static const uint8_t *opaque_pa[] = {
    (const uint8_t[]){0x48,0x31,0xC0,0x48,0x85,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00}, 
    // xor/test/jz
    (const uint8_t[]){0x48,0x89,0xC1,0x48,0x31,0xC1,0x48,0x85,0xC9,0x0F,0x85,0x00,0x00,0x00,0x00}, // mov/xor/test/jnz
    (const uint8_t[]){0x48,0x31,0xC0,0x48,0x85,0xC0,0x0F,0x85,0x00,0x00,0x00,0x00}, 
    // xor/test/jnz
    (const uint8_t[]){0x48,0x8D,0x05,0x00,0x00,0x00,0x00,0x48,0x39,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00}, // lea/cmp/je
    (const uint8_t[]){0x9F,0x48,0x83,0xE0,0x01,0x48,0x85,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00}, 
    // lahf/and/test/jz
    (const uint8_t[]){0x50,0x58,0x48,0x85,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00}, 
    // push/pop/test/jz
    (const uint8_t[]){0x48,0xC7,0xC0,0xFF,0xFF,0xFF,0xFF,0x48,0x21,0xC0,0x48,0x85,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00}, // mov/and/test/jz
    (const uint8_t[]){0x48,0x8B,0xC0,0x48,0x85,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00}, // mov/test/jz
    (const uint8_t[]){0x48,0x89,0xC0,0x48,0x31,0xC0,0x48,0x39,0xC0,0x0F,0x84,0x00,0x00,0x00,0x00},
     // mov/xor/cmp/je
    (const uint8_t[]){0x48,0x83,0xEC,0x08,0x48,0x83,0xC4,0x08,0x48,0x85,0xE4,0x0F,0x84,0x00,0x00,0x00,0x00} 
    // sub/add/test/jz
};

static const size_t n_len[] = {12,15,12,16,14,11,18,12,15,17};
static const size_t num_opaque_pa = 10;

static void blocks_x86(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size < 64) return; 
    
    cfg_t cfg;
    cfg_shit(code, size, &cfg);
    
    if (cfg.num_blocks < 2) {
        free(cfg.blocks);
        return;
    }
    
    for (int i = cfg.num_blocks - 1; i > 0; i--) {
        int j = chacha20_random(rng) % (i + 1);
        if (i != j) {
            basic_block_t temp = cfg.blocks[i];
            cfg.blocks[i] = cfg.blocks[j];
            cfg.blocks[j] = temp;
        }
    }
    
    uint8_t *new_buffer = malloc(size);
    size_t new_offset = 0;
    
    for (int i = 0; i < cfg.num_blocks && new_offset < size; i++) {
        size_t block_len = cfg.blocks[i].end - cfg.blocks[i].start;
        if (new_offset + block_len <= size) {
            memcpy(new_buffer + new_offset, code + cfg.blocks[i].start, block_len);
            
            // Patch any jumps in this block
            size_t block_offset = 0;
            while (block_offset < block_len && (new_offset + block_offset) < size) {
                x86_inst_t inst;
                if (!decode_x86_withme(new_buffer + new_offset + block_offset, 
                                        (block_len - block_offset < size - (new_offset + block_offset)) ? 
                                        block_len - block_offset : size - (new_offset + block_offset), 
                                        0, &inst, NULL) || 
                    !inst.valid || inst.len == 0) {
                    block_offset++;
                    continue;
                }
                
                if (new_offset + block_offset + inst.len > size) {
                    block_offset++;
                    continue;
                }
                
                if ((inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9 || // CALL/JMP
                    (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) || // Jcc
                    (inst.opcode[0] == 0x0F && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F))) { // Jcc
                    
                    size_t original_target = (inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9) ? 
                        (cfg.blocks[i].start + block_offset + inst.len + (int32_t)inst.imm) :
                        (cfg.blocks[i].start + block_offset + inst.len + (int8_t)inst.opcode[1]);
                    
                    size_t new_target = 0;
                    for (int j = 0; j < cfg.num_blocks; j++) {
                        if (original_target >= cfg.blocks[j].start && original_target < cfg.blocks[j].end) {
                            size_t offset_in_block = original_target - cfg.blocks[j].start;
                            new_target = (j == 0 ? 0 : cfg.blocks[j-1].end) + offset_in_block;
                break;
                        }
                    }
                    
                    if (new_target > 0) {
                        size_t jump_src = new_offset + block_offset + inst.len;
                        int32_t new_rel = (int32_t)(new_target - jump_src);
                        
                        if (inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9) {
                            if (new_offset + block_offset + inst.len >= 4) {
                                size_t write_offset = new_offset + block_offset + inst.len - 4;
                                if (write_offset + 4 <= size) {
                                    *(int32_t*)(new_buffer + write_offset) = new_rel;
                                }
                            }
                        } else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) {
                            size_t write_offset = new_offset + block_offset + 1;
                            if (write_offset < size) {
                                new_buffer[write_offset] = (int8_t)new_rel;
                            }
                        } else if (inst.opcode[0] == 0x0F && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) {
                            size_t write_offset = new_offset + block_offset + 2;
                            if (write_offset + 4 <= size) {
                                *(int32_t*)(new_buffer + write_offset) = new_rel;
                            }
                        }
                    }
                }
                
                block_offset += inst.len;
            }
            
            new_offset += block_len;
        }
    }
    
    // Copy back if valid
    if (it_chunk(new_buffer, new_offset)) {
        memcpy(code, new_buffer, new_offset);
        // Zero out the rest
        if (new_offset < size) {
            memset(code + new_offset, 0, size - new_offset);
        }
    }
    
    free(new_buffer);
    free(cfg.blocks);
}

static void x86_semantic(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, 
                               muttt_t *log, liveness_state_t *liveness, unsigned mutation_intensity) {
    size_t offset = 0;
    
    if (liveness) {
        init_live(liveness);
    }
    
    while (offset < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0 || offset + inst.len > size) {
            offset++;
            continue;
        }
        
        if (liveness) {
            update_liveness(liveness, offset, &inst);
        }
        
        bool mutated = false;
        
        if (inst.has_modrm && inst.len <= 8) {
            uint8_t reg = modrm_reg(inst.modrm);
            uint8_t rm = modrm_rm(inst.modrm);
            uint8_t new_reg = reg;
            uint8_t new_rm = rm;
            
            if (liveness) {
                new_reg = pick_live_reg(liveness, reg, offset, rng); 
                new_rm = pick_live_reg(liveness, rm, offset, rng);
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
                    if (it_op(code + offset)) {
                        mutated = true;
                        if (log) {
                            char desc[64];
                            _snprintf(desc, sizeof(desc), "reg %d->%d, rm %d->%d", reg, new_reg, rm, new_rm);
                            logme(log, offset, inst.len, MUT_SUB, gen, desc);
                        }
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
                    if (offset + 5 <= size) {
                        memset(code + offset + 1, 0, 4);
                    }
                }
                if (!it_op(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0)
                        memcpy(code + offset, inst.raw, inst.len);
                } else {
                    mutated = true;
                    if (log) {
                        logme(log, offset, inst.len, MUT_EQUIV, gen, "xor->sub/mov");
                    }
                }
            }
            else if ((inst.opcode[0] & 0xF8) == 0xB8 && inst.imm == 0) {
                uint8_t reg = inst.opcode[0] & 0x7;
                switch(chacha20_random(rng) % 3) {
                    case 0: // xor reg, reg
                        code[offset] = 0x31;
                        code[offset+1] = 0xC0 | (reg << 3) | reg;
                        break;
                    case 1:
                        code[offset] = 0x83;
                        code[offset+1] = 0xE0 | reg;
                        code[offset+2] = 0x00;
                        break;
                    case 2: // sub reg, reg
                        code[offset] = 0x29;
                        code[offset+1] = 0xC0 | (reg << 3) | reg;
                        break;
                }
                if (!it_op(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0)
                        memcpy(code + offset, inst.raw, inst.len);
                } else {
                    mutated = true;
                }
            }
            // add reg, 1 <-> inc reg <-> lea reg, [reg+1]
            else if (inst.opcode[0] == 0x83 && inst.has_modrm && inst.raw[2] == 0x01) {
                uint8_t reg = modrm_rm(inst.modrm);
                if (chacha20_random(rng) % 2) {
                    code[offset] = 0x48 + reg;
                    if (offset + 1 < size && inst.len > 1) {
                        size_t fill_len = (inst.len - 1 < size - offset - 1) ? inst.len - 1 : size - offset - 1;
                        if (fill_len > 0) {
                            memset(code + offset + 1, 0x90, fill_len);
                        }
                    }
                } else {
                    if (offset + 4 <= size) {
                        code[offset] = 0x48;
                        code[offset+1] = 0x8D;
                        code[offset+2] = 0x40 | (reg << 3) | reg;
                        code[offset+3] = 0x01;
                        if (offset + 4 < size && inst.len > 4) {
                            size_t fill_len = (inst.len - 4 < size - offset - 4) ? inst.len - 4 : size - offset - 4;
                            if (fill_len > 0) {
                                memset(code + offset + 4, 0x90, fill_len);
                            }
                        }
                    }
                }
                if (!it_op(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0)
                        memcpy(code + offset, inst.raw, inst.len);
                } else {
                    mutated = true;
                }
            }
            // inc reg <-> add reg, 1 <-> lea reg, [reg+1]
            else if ((inst.opcode[0] & 0xF8) == 0x40) {
                uint8_t reg = inst.opcode[0] & 0x7;
                switch(chacha20_random(rng) % 3) {
                    case 0: // add reg, 1
                        if (offset + 3 <= size) {
                            code[offset] = 0x83;
                            code[offset+1] = 0xC0 | reg;
                            code[offset+2] = 0x01;
                            if (offset + 3 < size && inst.len > 3) {
                                size_t fill_len = (inst.len - 3 < size - offset - 3) ? inst.len - 3 : size - offset - 3;
                                if (fill_len > 0) {
                                    memset(code + offset + 3, 0x90, fill_len);
                                }
                            }
                        }
                        break;
                    case 1: // lea reg, [reg+1]
                        if (offset + 4 <= size) {
                            code[offset] = 0x48;
                            code[offset+1] = 0x8D;
                            code[offset+2] = 0x40 | (reg << 3) | reg;
                            code[offset+3] = 0x01;
                            if (offset + 4 < size && inst.len > 4) {
                                size_t fill_len = (inst.len - 4 < size - offset - 4) ? inst.len - 4 : size - offset - 4;
                                if (fill_len > 0) {
                                    memset(code + offset + 4, 0x90, fill_len);
                                }
                            }
                        }
                        break;
                    case 2: 
                        if (offset + 3 <= size) {
                            code[offset] = 0x48;
                            code[offset+1] = 0x01;
                            code[offset+2] = 0xC0 | (reg << 3) | reg;
                            if (offset + 3 < size && inst.len > 3) {
                                size_t fill_len = (inst.len - 3 < size - offset - 3) ? inst.len - 3 : size - offset - 3;
                                if (fill_len > 0) {
                                    memset(code + offset + 3, 0x90, fill_len);
                                }
                            }
                        }
                        break;
                }
                if (!it_op(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0)
                        memcpy(code + offset, inst.raw, inst.len);
                } else {
                    mutated = true;
                }
            }
            // lea reg, [reg] <-> mov reg, reg <-> xchg reg, reg
            else if (inst.opcode[0] == 0x8D && inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == rm) {
                    if (chacha20_random(rng) % 2) {
                        // mov reg, reg
                        code[offset] = 0x89;
                    } else {
                        // xchg reg, reg
                        code[offset] = 0x87;
                    }
                    if (!it_op(code + offset)) {
                        code[offset] = 0x8D;
                    } else {
                        mutated = true;
                    }
                }
            }
            else if (inst.opcode[0] == 0x85 && inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == rm) {
                    if (chacha20_random(rng) % 2) {
                        // cmp reg, reg
                        code[offset] = 0x39;
                    } else {
                        code[offset] = 0x21;
                    }
                    if (!it_op(code + offset)) {
                        code[offset] = 0x85;
                    } else {
                        mutated = true;
                    }
                }
            }
            else if ((inst.opcode[0] & 0xF8) == 0x50) {
                uint8_t reg = inst.opcode[0] & 0x07;
                if (chacha20_random(rng) % 2) {
                    code[offset] = 0x58 | reg;
                } else {
                    // sub rsp,8; mov [rsp],reg
                    if (offset + 8 <= size) {
                        code[offset] = 0x48;
                        code[offset+1] = 0x83;
                        code[offset+2] = 0xEC;
                        code[offset+3] = 0x08;
                        code[offset+4] = 0x48;
                        code[offset+5] = 0x89;
                        code[offset+6] = 0x04;
                        code[offset+7] = 0x24;
                        if (offset + 8 < size && inst.len > 8) {
                            size_t fill_len = (inst.len - 8 < size - offset - 8) ? inst.len - 8 : size - offset - 8;
                            if (fill_len > 0) {
                                memset(code + offset + 8, 0x90, fill_len);
                            }
                        }
                    }
                }
                if (!it_op(code + offset)) {
                    if (offset + inst.len <= size && inst.len > 0)
                        memcpy(code + offset, inst.raw, inst.len);
                } else {
                    mutated = true;
                }
            }
        }
        
        if (!mutated && (chacha20_random(rng) % 10) < mutation_intensity) {
            uint8_t opq_buf[32];
            size_t opq_len;
            uint32_t target_value = chacha20_random(rng);
            Opaque(opq_buf, &opq_len, target_value, rng);
            
            uint8_t junk_buf[16];
            size_t junk_len;
            genmesomejunk(junk_buf, &junk_len, rng);
            
            if (offset + inst.len + opq_len + junk_len <= size) {
                memmove(code + offset + opq_len + junk_len, code + offset, size - offset - opq_len - junk_len);
                memcpy(code + offset, opq_buf, opq_len);
                memcpy(code + offset + opq_len, junk_buf, junk_len);
                
                offset += opq_len + junk_len;
                mutated = true;
                if (log) {
                    logme(log, offset - opq_len - junk_len, opq_len + junk_len, MUT_PRED, gen, " opaque+junk");
                }
            }
        }
        
        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 2)) {
            uint8_t junk_buf[16];
            size_t junk_len;
            genmesomejunk(junk_buf, &junk_len, rng);
            
            if (offset + inst.len + junk_len <= size) {
                memmove(code + offset + junk_len, code + offset, size - offset - junk_len);
                memcpy(code + offset, junk_buf, junk_len);
                
                offset += junk_len;
                mutated = true;
                if (log) {
                    logme(log, offset - junk_len, junk_len, MUT_DEAD, gen, " dead code");
                }
            }
        }
        
        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 3)) {
            if (inst.opcode[0] == 0x89 && inst.has_modrm && inst.len >= 6) {
                uint8_t split[6] = {
                    0x50 | (inst.modrm & 7), // PUSH r
                    0x89, 0x04, 0x24,       // MOV [esp], r
                    0x58 | (inst.modrm >> 3) // POP r/m
                };
                memcpy(code + offset, split, 6);
                offset += 6;
                mutated = true;
                if (log) {
                    logme(log, offset - 6, 6, MUT_SPLIT, gen, "mov->push/mov/pop");
                }
            }
            else if (inst.opcode[0] == 0x81 && (inst.raw[1] & 0xC0) != 0xC0 && inst.len >= 6) {
                uint8_t lea[7] = {
                    0x48, 0x8D, 
                    (inst.raw[1] & 0xC0) | ((inst.raw[1] & 0x7) << 3) | 0x80, // ModRM with disp32
                    0x00, 0x00, 0x00, 0x00 // disp32 (imm)
                };
                *(uint32_t*)(lea + 3) = (uint32_t)inst.imm;
                memcpy(code + offset, lea, 7);
                offset += 7;
                mutated = true;
                if (log) {
                    logme(log, offset - 7, 7, MUT_SPLIT, gen, "add->lea");
                }
            }
        }
        
        if (!mutated && (inst.opcode[0] & 0xF8) == 0xB8 && inst.imm != 0 && inst.len >= 5) {
            switch(chacha20_random(rng) % 4) {
                case 0: 
                    if (offset + 8 <= size) {
                        code[offset] = 0x31;
                        code[offset+1] = 0xC0 | (inst.opcode[0] & 0x7);
                        code[offset+2] = 0x48;
                        code[offset+3] = 0x05;
                        *(uint32_t*)(code + offset + 4) = (uint32_t)inst.imm;
                    }
                    break;
                case 1: 
                    if (offset + 18 <= size) {
                        code[offset] = 0x48;
                        code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = 0xFFFFFFFF;
                        code[offset+7] = 0x48;
                        code[offset+8] = 0x25;
                        *(uint32_t*)(code + offset + 9) = ~((uint32_t)inst.imm - 1);
                        code[offset+13] = 0x48;
                        code[offset+14] = 0x05;
                        *(uint32_t*)(code + offset + 15) = (uint32_t)inst.imm;
                    }
                    break;
                case 2: 
                    if (offset + 7 <= size) {
                        code[offset] = 0x48;
                        code[offset+1] = 0x8D;
                        code[offset+2] = 0x05 | ((inst.opcode[0] & 0x7) << 3);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm;
                    }
                    break;
                case 3: // mov reg, imm/2; add reg, imm - imm/2
                    if (offset + 13 <= size) {
                        code[offset] = 0x48;
                        code[offset+1] = 0xC7;
                        code[offset+2] = 0xC0 | (inst.opcode[0] & 0x7);
                        *(uint32_t*)(code + offset + 3) = (uint32_t)inst.imm / 2;
                        code[offset+7] = 0x48;
                        code[offset+8] = 0x05;
                        *(uint32_t*)(code + offset + 9) = (uint32_t)inst.imm - ((uint32_t)inst.imm / 2);
                    }
                    break;
            }
            if (!it_op(code + offset)) {
                if (offset + inst.len <= size && inst.len > 0)
                    memcpy(code + offset, inst.raw, inst.len);
            } else {
                mutated = true;
                if (log) {
                    logme(log, offset, inst.len, MUT_OBFUSC, gen, "imm obfuscation");
                }
            }
        }
        
        if (!mutated && (chacha20_random(rng) % 10) < (mutation_intensity / 4)) {
            uint8_t orgi_op = inst.opcode[0];
            uint8_t new_opcode = orgi_op;
            
            switch(chacha20_random(rng) % 4) {
                case 0: // MOV <-> XCHG (when same register)
                    if (inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm)) {
                        new_opcode = (orgi_op == 0x89) ? 0x87 : 0x89;
                    }
                    break;
                case 1: // ADD <-> SUB (with negation)
                    if (orgi_op == 0x01) new_opcode = 0x29;
                    else if (orgi_op == 0x29) new_opcode = 0x01;
                    break;
                case 2: // AND <-> OR (with complement)
                    if (orgi_op == 0x21) new_opcode = 0x09;
                    else if (orgi_op == 0x09) new_opcode = 0x21;
                    break;
                case 3: // XOR <-> MOV (when zeroing)
                    if (orgi_op == 0x31 && inst.has_modrm && modrm_reg(inst.modrm) == modrm_rm(inst.modrm)) {
                        new_opcode = 0x89;
                    }
                    break;
            }
            
            if (new_opcode != orgi_op) {
                code[offset] = new_opcode;
                if (it_op(code + offset)) {
                    mutated = true;
                    if (log) {
                        char desc[64];
                        _snprintf(desc, sizeof(desc), "opcode 0x%02x->0x%02x", orgi_op, new_opcode);
                        logme(log, offset, inst.len, MUT_EQUIV, gen, desc);
                    }
                } else {
                    code[offset] = orgi_op;
                }
            }
        }
        
        offset += inst.len;
    }
    
    if (gen > 5 && (chacha20_random(rng) % 10) < (gen > 15 ? 8 : 3)) {
        cfg_t cfg;
        cfg_shit(code, size, &cfg);
        flattenme(code, size, &cfg, rng);
        if (log) {
            logme(log, 0, size, MUT_FLATTEN, gen, "Flattening");
        }
        free(cfg.blocks);
    }
    
    if (gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 5 : 2)) {
        blocks_x86(code, size, rng);
        if (log) {
            logme(log, 0, size, MUT_REORDER, gen, "Reordering");
        }
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
        init_live(liveness);
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
                if (it_op(code + offset)) {
                    changed = true;
                    if (log) {
                        char desc[64];
                        _snprintf(desc, sizeof(desc), "rd %d->%d, rn %d->%d, rm %d->%d", 
                                inst.rd, new_rd, inst.rn, new_rn, inst.rm, new_rm);
                        logme(log, offset, 4, MUT_SUB, gen, desc);
                    }
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
        }
        
        if (!changed) {
            if (inst.type == ARM_OP_MOV && inst.rd == inst.rm) {
                if (chacha20_random(rng) % 2) {
                    // ORR reg, xzr, reg
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rd << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (it_op(code + offset)) {
                    changed = true;
                    if (log) {
                        logme(log, offset, 4, MUT_EQUIV, gen, "mov->orr");
                    }
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
            else if (inst.type == ARM_OP_ADD && inst.imm == 0) {
                if (chacha20_random(rng) % 2) {
                    // MOV reg, reg
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rn << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (it_op(code + offset)) {
                    changed = true;
                    if (log) {
                        logme(log, offset, 4, MUT_EQUIV, gen, "add->mov");
                    }
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
            else if (inst.type == ARM_OP_SUB && inst.imm == 0) {
                if (chacha20_random(rng) % 2) {
                    // MOV reg, reg
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rn << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (it_op(code + offset)) {
                    changed = true;
                    if (log) {
                        logme(log, offset, 4, MUT_EQUIV, gen, "sub->mov");
                    }
                } else {
                    *(uint32_t*)(code + offset) = original;
                }
            }
            else if (inst.type == ARM_OP_AND && inst.imm == 0xFFF) {
                if (chacha20_random(rng) % 2) {
                    mutated = 0xAA0003E0 | (inst.rd) | (inst.rn << 16);
                }
                *(uint32_t*)(code + offset) = mutated;
                if (it_op(code + offset)) {
                    changed = true;
                    if (log) {
                        logme(log, offset, 4, MUT_EQUIV, gen, "and->mov");
                    }
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
                            if (log) {
                                logme(log, offset, 8, MUT_OBFUSC, gen, "imm->movz+movk");
                            }
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
                            if (log) {
                                logme(log, offset, 8, MUT_OBFUSC, gen, "imm->add+add");
                            }
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
                                logme(log, offset, 8, MUT_OBFUSC, gen, "imm->mov+xor");
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
            Opaque(opq_buf, &opq_len, target_value, rng);
            
            uint8_t junk_buf[16];
            size_t junk_len;
            genmesomejunk(junk_buf, &junk_len, rng);
            
            if (offset + 4 + opq_len + junk_len <= size) {
                memmove(code + offset + opq_len + junk_len, code + offset, size - offset - opq_len - junk_len);
                memcpy(code + offset, opq_buf, opq_len);
                memcpy(code + offset + opq_len, junk_buf, junk_len);
                
                if (log) {
                    logme(log, offset, opq_len + junk_len, MUT_PRED, gen, " arm opaque+junk");
                }
                offset += opq_len + junk_len;
                continue;
            }
        }
        
        if (!changed && gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 4 : 2)) {
            uint8_t junk_buf[16];
            size_t junk_len;
            genmesomejunk(junk_buf, &junk_len, rng);
            
            if (offset + 4 + junk_len <= size) {
                memmove(code + offset + junk_len, code + offset, size - offset - junk_len);
                memcpy(code + offset, junk_buf, junk_len);
                
                if (log) {
                    logme(log, offset, junk_len, MUT_DEAD, gen, " arm junk");
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
    uint8_t original[size];
    memcpy(original, code, size);
    muttt_t mut_log;
    liveness_state_t liveness;
    init_mut(&mut_log);
    init_live(&liveness);
    unsigned mutation_intensity = gen + 1;
    if (mutation_intensity > 20) mutation_intensity = 20;
    
#if defined(ARCH_X86)
    size_t offset = 0;
    int mutations_applied = 0;
    int semantic_mutations = 0;
    int junk_insertions = 0;
    
    while (offset < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0 || offset + inst.len > size) {
            offset++;
            continue;
        }
        
        size_t original_offset = offset;
        x86_semantic(code + offset, inst.len, rng, gen, &mut_log, &liveness, mutation_intensity);
        if (memcmp(original + original_offset, code + original_offset, inst.len) != 0) {
            mutations_applied++;
            semantic_mutations++;
        }
        
        offset += inst.len;
    }
    
    if ((chacha20_random(rng) % 10) < (mutation_intensity / 2)) {
        cfg_t cfg;
        cfg_shit(code, size, &cfg);
        flattenme(code, size, &cfg, rng);
        logme(&mut_log, 0, size, MUT_FLATTEN, gen, "CF BS");
        mutations_applied++;
        DBG("[!] Flattening applied\n");
        free(cfg.blocks);
    }
    
    if ((chacha20_random(rng) % 10) < (mutation_intensity / 3)) {
        blocks_x86(code, size, rng);
        logme(&mut_log, 0, size, MUT_REORDER, gen, "Block reorder");
        mutations_applied++;
        DBG("[!] Block reordering applied\n");
    }
    
    xpass_rswp(code, size, rng);
    xpass_jnk(code, size, rng);
    xpass_opq(code, size, rng);

    
#elif defined(ARCH_ARM)
    size_t offset = 0;
    int mutations_applied = 0;
    int semantic_mutations = 0;
    int junk_insertions = 0;
    
    while (offset + 4 <= size) {
        arm64_inst_t inst;
        if (!decode_arm64(code + offset, &inst) || !inst.valid) {
            offset += 4;
            continue;
        }
        
        size_t original_offset = offset;
        arm_semantic(code + offset, 4, rng, gen, &mut_log, &liveness, mutation_intensity);
        if (memcmp(original + original_offset, code + original_offset, 4) != 0) {
            mutations_applied++;
            semantic_mutations++;
        }
        
        offset += 4;
    }
    
    if (gen > 5 && (chacha20_random(rng) % 10) < (gen > 15 ? 8 : 3)) {
        cfg_t cfg;
        cfg_shit(code, size, &cfg);
        fg_arm(code, size, &cfg, rng);
        logme(&mut_log, 0, size, MUT_FLATTEN, gen, "arm control flow flattening");
        mutations_applied++;
        DBG("[!] ARM control flow flattening applied\n");
        free(cfg.blocks);
    }
    
/*     if (gen > 3 && (chacha20_random(rng) % 10) < (gen > 10 ? 5 : 2)) {
        blocks_arm(code, size, rng);
        logme(&mut_log, 0, size, MUT_REORDER, gen, "arm block reordering");
        mutations_applied++;
        DBG("[!] ARM block reordering applied\n");
    } */
    
    xpass_rswp(code, size, rng);
    xpass_jnk(code, size, rng);
    xpass_opq(code, size, rng);
    
    DBG("[!] ARM mutations applied: %d total (%d semantic, %d junk insertions)\n", 
           mutations_applied, semantic_mutations, junk_insertions);
#endif

    if (mut_log.count > 0) {
        dump(&mut_log);
    }

    // Post-mutation
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
                // Try all possible safe registers for substitution
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
            if (inst.opcode[0] == 0x9A || inst.opcode[0] == 0xEA) { // far call/jmp
                DBG("[!] Blacklisted opcode 0x%02x at 0x%zx, reverting mutation", inst.opcode[0], off);
                memcpy(code, original, size);
                freeme(&mut_log);
                return;
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

    if (memcmp(original, code, size) == 0) {
        DBG("No ops on target!\n");
    } else {
        DBG("[+] Mutation set: success.\n");
    }
    
    if (!it_chunk(code, size)) {
        DBG("[!] Reverting2 orgi\n");
        if (notsafe) {
            DBG("[*] Hit a wall!! Dumping code before revert:");
            hexdump(code, size, "[*] Mutated code");
        }
        memcpy(code, original, size);
    }
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
        // vERY SIMPLE 
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

bool is_shellcode_mode(const uint8_t *code, size_t size, const cfg_t *cfg) {
    if (size == 0 || size > PAGE_SIZE) return false;
    if (cfg->num_blocks > 4) return false;

    if (s_syscall(code, size)) return true;
    if (has_anom(code, size)) return true;
    if (iz_exec(code, size) && cfg->num_blocks <= 2) return true;

    return false;
}


void mutate(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen) {
    did_we_cry = code;
    did_we_cry_size = size;
    if (size < 16) return;

    cfg_t cfg;
    cfg_shit(code, size, &cfg);
    bool shellcode_mode = is_shellcode_mode(code, size, &cfg);

#if defined(ARCH_X86)
    if (shellcode_mode) {
        uint8_t original[size];
        memcpy(original, code, size);
        muttt_t mut_log;
        liveness_state_t liveness;
        init_mut(&mut_log);
        init_live(&liveness);
        unsigned mutation_intensity = gen + 1;
        size_t offset = 0;
        while (offset < size) {
            x86_inst_t inst;
            if (!decode_x86_withme(code + offset, size - offset, 0, &inst, NULL) || !inst.valid || inst.len == 0)
                break;
            bool skip = false;
            if (inst.is_control_flow || inst.modifies_ip)
                skip = true;
            if (inst.has_modrm) {
                uint8_t reg = modrm_reg(inst.modrm);
                uint8_t rm = modrm_rm(inst.modrm);
                if (reg == 4 || reg == 5 || rm == 4 || rm == 5)
                    skip = true;
            }
            if (inst.opcode[0] == 0x50 || inst.opcode[0] == 0x58 || // push/pop
                (inst.opcode[0] & 0xF0) == 0xE0 || // jmp/call short/near
                inst.opcode[0] == 0xC3 || inst.opcode[0] == 0xCB || // ret
                inst.opcode[0] == 0x9A || inst.opcode[0] == 0xFF) // call/jmp indirect
                skip = true;
            if ((inst.opcode[0] & 0xF8) == 0xB8)
                skip = true;
            if (!skip) {
                if (inst.opcode[0] == 0x90) {
                } else if ((inst.opcode[0] == 0x89 || inst.opcode[0] == 0x8B) && inst.has_modrm) {
                    uint8_t reg = modrm_reg(inst.modrm);
                    uint8_t rm = modrm_rm(inst.modrm);
                    if (reg == rm) {
                      // mess with this all you want, just don't break shellcode layout.
                        // size/layout sensitive, no real bblocks in shellcode.
                        code[offset] = 0x31;
                        code[offset + 1] = 0xC0 | (reg << 3) | reg;
                    }
                } else if (inst.opcode[0] == 0x31 && inst.has_modrm) {
                    uint8_t reg = modrm_reg(inst.modrm);
                    uint8_t rm = modrm_rm(inst.modrm);
                    if (reg == rm) {
                        code[offset] = 0x89;
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

int chk_map(const instr_info_t *map, size_t n, size_t size) {
    if (n == 0) return 0;
    
    size_t off = 0;
    for (size_t i = 0; i < n; i++) {
        if (!map[i].valid) {
            DBG("[!] Invalid at index %zu\n", i);
            return 0;
        }
        if (map[i].off != off) {
            DBG("[!] Offset mismatch at index %zu: want %zu, got %zu\n", i, off, map[i].off);
            return 0;
        }
        off += map[i].len;
    }
    
    if (off > size) {
        DBG("[!] Length %zu exceeds buffer size %zu\n", off, size);
        return 0;
    }
    
    if (size - off > 16) {
        DBG("[!] Too much %zu bytes\n", size - off);
        return 0;
    }
    
    return 1;
}


#if defined(ARCH_X86)
static void block_liveness(const uint8_t *code, size_t size, basic_block_t *block, bool *live_regs) {
    memset(live_regs, 0, 16);
    // Scan backwards from block end to start
    for (ssize_t off = (ssize_t)block->end - 1; off >= (ssize_t)block->start; ) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + off, size - off, 0, &inst, NULL) || !inst.valid || inst.len == 0) break;
        if (inst.has_modrm) {
            uint8_t reg = modrm_reg(inst.modrm);
            live_regs[reg] = false;
        }
        if (inst.has_modrm) {
            uint8_t rm = modrm_rm(inst.modrm);
            live_regs[rm] = true;
        }
        off -= inst.len;
    }
}

static uint8_t pick_rig(const bool *live_regs, chacha_state_t *rng) {
    uint8_t candidates[8]; int n = 0;
    for (uint8_t r = 0; r < 8; ++r) if (!live_regs[r]) candidates[n++] = r;
    if (n == 0) return chacha20_random(rng) % 8;
    return candidates[chacha20_random(rng) % n];
}

int sub_inst(uint8_t *a, size_t al, uint8_t *b, size_t bl, chacha_state_t *r) {
    if (al > 16 || bl > 16) return 0;
    
    uint8_t orig_a[16], orig_b[16];
    memcpy(orig_a, a, al);
    memcpy(orig_b, b, bl);
    
    if (al == 3 && bl == 2) {
        if (a[0] == 0x48 && a[1] == 0x83 && a[2] == 0xC0) {
            b[0] = 0x48;
            b[1] = 0xFF;
            b[2] = 0xC0;
            return 1;
        }
        if (a[0] == 0x48 && a[1] == 0x31 && a[2] == 0xC0) {
            b[0] = 0x48;
            b[1] = 0x89;
            b[2] = 0xC0;
            return 1;
        }
    }
    
    if (al == 2 && bl == 3) {
        if (a[0] == 0x48 && a[1] == 0xFF) {
            b[0] = 0x48;
            b[1] = 0x83;
            b[2] = 0xC0;
            return 1;
        }
        if (a[0] == 0x48 && a[1] == 0x89) {
            b[0] = 0x48;
            b[1] = 0x31;
            b[2] = 0xC0;
            return 1;
        }
    }
    
    return 0;
}

void xpass_jnk(uint8_t *c, size_t sz, chacha_state_t *r) {
#if defined(ARCH_X86)
    cfg_t cfg;
    cfg_shit(c, sz, &cfg);
    if (cfg.num_blocks < 1) return;

    liveness_state_t liveness;
    init_live(&liveness);

    for (size_t b = 0; b < cfg.num_blocks; ++b) {
        basic_block_t *blk = &cfg.blocks[b];
        size_t insert_off = blk->end;
        if (insert_off >= sz) continue;
        // before dropping junk, make sure no jmp/call targets get shifted
        // grab all targets upfront by decoding everything first
    instr_info_t m[256];
    size_t n = decode_map(c, sz, m, 256);
        bool target_conflict = false;
        for (size_t i = 0; i < n; ++i) {
            if (m[i].cf) {
                int64_t target = -1;
                x86_inst_t inst;
                if (decode_x86_withme(c + m[i].off, m[i].len, 0, &inst, NULL) && inst.valid) {
                    if (inst.is_control_flow && inst.modifies_ip && inst.target > 0) {
                        if ((size_t)inst.target > insert_off) {
                            target_conflict = true;
                            break;
                        }
                    }
                }
            }
        }
        if (target_conflict) continue; 

        bool live_regs[16] = {0};
        block_liveness(c, sz, blk, live_regs);

        uint8_t junk_buf[16];
        size_t junk_len = 0;
        if (chacha20_random(r) % 2 == 0) {
            junk_buf[0] = 0x90; // NOP
            junk_len = 1;
        } else {
            uint8_t reg = pick_rig(live_regs, r);
            junk_buf[0] = 0x48; junk_buf[1] = 0x89; junk_buf[2] = 0xC0 | (reg << 3) | reg;
            junk_len = 3;
        }
        if (insert_off + junk_len > sz) continue;
        
        // Save Me Back
        uint8_t orig[16];
        size_t tail_len = sz - insert_off - junk_len;
        if (tail_len > sizeof(orig)) tail_len = sizeof(orig);
        if (insert_off + tail_len > sz) tail_len = sz - insert_off;
        memcpy(orig, c + insert_off, tail_len);
        
        // Insert junk
        memmove(c + insert_off + junk_len, c + insert_off, sz - insert_off - junk_len);
        memcpy(c + insert_off, junk_buf, junk_len);

        for (size_t i = 0; i < n; ++i) {
            if (m[i].cf) {
                x86_inst_t inst;
                if (decode_x86_withme(c + m[i].off, m[i].len, 0, &inst, NULL) && inst.valid) {
                    if (inst.is_control_flow && inst.modifies_ip && inst.target > 0) {
                        size_t old_target = (size_t)inst.target;
                        if (old_target >= insert_off) {
                            size_t jump_src = m[i].off + inst.len;
                            int32_t new_rel = (int32_t)((old_target + junk_len) - jump_src);
                            if (inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9) {
                                if (m[i].off + inst.len >= 4) {
                                    size_t write_offset = m[i].off + inst.len - 4;
                                    if (write_offset + 4 <= sz) {
                                        *(int32_t*)(c + write_offset) = new_rel;
                                    }
                                }
                            } else if (inst.opcode[0] >= 0x70 && inst.opcode[0] <= 0x7F) {
                                size_t write_offset = m[i].off + 1;
                                if (write_offset < sz) {
                                    c[write_offset] = (int8_t)new_rel;
                                }
                            } else if (inst.opcode[0] == 0x0F && inst.opcode[1] >= 0x80 && inst.opcode[1] <= 0x8F) {
                                size_t write_offset = m[i].off + 2;
                                if (write_offset + 4 <= sz) {
                                    *(int32_t*)(c + write_offset) = new_rel;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (it_chunk(c, sz)) {
            free(cfg.blocks);
            return;
        }
        memmove(c + insert_off, c + insert_off + junk_len, sz - insert_off - junk_len);
        if (insert_off + tail_len <= sz) {
            memcpy(c + insert_off, orig, tail_len);
        }
    }
    free(cfg.blocks);
#endif
}

int heav_reg(uint8_t *a, size_t al, uint8_t *b, size_t bl) {
    if (al < 2 || bl < 2) return 1;
    
    uint8_t reg_a = 0, reg_b = 0;
    
    if (a[0] == 0x48 && a[1] >= 0x88 && a[1] <= 0x8B) {
        if (al >= 3) reg_a = a[2] & 7;
    }
    if (b[0] == 0x48 && b[1] >= 0x88 && b[1] <= 0x8B) {
        if (bl >= 3) reg_b = b[2] & 7;
    }
    
    if (reg_a == reg_b) return 0;
    return 1;
}

void xpass_swp(uint8_t *c, size_t sz, chacha_state_t *r) {
    instr_info_t m[256];
    size_t n = decode_map(c, sz, m, 256);
    if (n < 2) return;
    
    for (int t = 0; t < 16; t++) {
        size_t i = chacha20_random(r) % n;
        size_t j = chacha20_random(r) % n;
        if (i == j) continue;
        
        sem_meta_t sem_i, sem_j;
        if (sem_scan(c + m[i].off, m[i].len, &sem_i) != 0) continue;
        if (sem_scan(c + m[j].off, m[j].len, &sem_j) != 0) continue;
        
        if (!sem_meta_match(&sem_i, &sem_j)) continue;
        if (m[i].off + m[i].len > sz || m[j].off + m[j].len > sz) continue;
        
        uint8_t tmp[16];
        memcpy(tmp, c + m[i].off, m[i].len);
        memmove(c + m[i].off, c + m[j].off, m[j].len);
        memmove(c + m[j].off, tmp, m[i].len);
        
        if (it_chunk(c, sz)) return;
        
        memcpy(c + m[j].off, c + m[i].off, m[i].len);
        memcpy(c + m[i].off, tmp, m[i].len);
    }
}

void xpass_opq(uint8_t *c, size_t sz, chacha_state_t *r) {
    instr_info_t m[256];
    size_t n = decode_map(c, sz, m, 256);
    if (n < 1) return;
    
    for (int t = 0; t < 6; t++) { 
        size_t pos = chacha20_random(r) % n;
        if (m[pos].cf) continue;
        
        size_t insert_off = m[pos].off + m[pos].len;
        if (insert_off > sz) continue;
        
        uint8_t opq_buf[32];
        size_t opq_len;
        uint32_t target_value = chacha20_random(r); 

        Opaque(opq_buf, &opq_len, target_value, r);        
        if (insert_off + opq_len > sz) continue;
        uint8_t orig[32];
        size_t tail_len = sz - insert_off - opq_len;
        if (tail_len > sizeof(orig)) tail_len = sizeof(orig);
        if (insert_off + tail_len > sz) tail_len = sz - insert_off;
        memcpy(orig, c + insert_off, tail_len);
        
        memmove(c + insert_off + opq_len, 
               c + insert_off, 
               sz - insert_off - opq_len);
        memcpy(c + insert_off, opq_buf, opq_len);
        
        if (it_chunk(c, sz)) {
            return;
        }
        
        memmove(c + insert_off, 
               c + insert_off + opq_len, 
               sz - insert_off - opq_len);
        if (insert_off + tail_len <= sz) {
            memcpy(c + insert_off, orig, tail_len);
        }
    }
}

int sem_scan(const uint8_t *code, size_t len, sem_meta_t *sem) {
    memset(sem, 0, sizeof(*sem));
    if (len < 1) return -1;
    
#if defined(ARCH_X86)
    x86_inst_t inst;
    if (!decode_x86_withme(code, len, 0, &inst, NULL) || !inst.valid) return -1;
    
    uint8_t opc = inst.opcode[0];
    uint8_t opc2 = inst.opcode[1];
    
    sem->num_ops = 0;
    sem->stk_adj = 0;
    
    if (opc >= 0x00 && opc <= 0x05) {
        sem->sem_type = ST_ALU;
        sem->f_out = 1;
        sem->f_in = 0;
        if (opc == 0x00 || opc == 0x02) sem->ops[0].type = OP_MEM;
        else sem->ops[0].type = OP_REG;
        sem->ops[1].type = OP_REG;
        sem->num_ops = 2;
    }
    else if (opc >= 0x08 && opc <= 0x0D) {
        sem->sem_type = ST_BIT;
        sem->f_out = 1;
        sem->f_in = 0;
        if (opc == 0x08 || opc == 0x0A) sem->ops[0].type = OP_MEM;
        else sem->ops[0].type = OP_REG;
        sem->ops[1].type = OP_REG;
        sem->num_ops = 2;
    }
    else if (opc >= 0x88 && opc <= 0x8B) {
        sem->sem_type = ST_MOV;
        sem->f_out = 0;
        sem->f_in = 0;
        if (opc == 0x88 || opc == 0x8A) {
            sem->ops[0].type = OP_MEM;
            sem->ops[1].type = OP_REG;
        } else {
            sem->ops[0].type = OP_REG;
            sem->ops[1].type = OP_MEM;
        }
        sem->num_ops = 2;
    }
    else if (opc >= 0xB8 && opc <= 0xBF) {
        sem->sem_type = ST_MOV;
        sem->f_out = 0;
        sem->ops[0].type = OP_REG;
        sem->ops[0].reg = opc & 7;
        sem->ops[1].type = OP_IMM;
        sem->ops[1].imm = inst.imm;
        sem->num_ops = 2;
    }
    else if (opc >= 0x70 && opc <= 0x7F) {
        sem->sem_type = ST_JCC;
        sem->f_out = 0;
        sem->f_in = 1;
        sem->ops[0].type = OP_REL;
        sem->ops[0].imm = (int8_t)opc2;
        sem->num_ops = 1;
    }
    else if (opc == 0xE8) {
        sem->sem_type = ST_FLOW;
        sem->f_out = 0;
        sem->ops[0].type = OP_REL;
        sem->ops[0].imm = (int32_t)inst.imm;
        sem->num_ops = 1;
        sem->stk_adj = -8;
    }
    else if (opc == 0xE9) {
        sem->sem_type = ST_FLOW;
        sem->f_out = 0;
        sem->ops[0].type = OP_REL;
        sem->ops[0].imm = (int32_t)inst.imm;
        sem->num_ops = 1;
    }
    else if (opc == 0xC3) {
        sem->sem_type = ST_FLOW;
        sem->f_out = 0;
        sem->num_ops = 0;
        sem->stk_adj = 8;
    }
    else if (opc >= 0x50 && opc <= 0x57) {
        sem->sem_type = ST_STK;
        sem->f_out = 0;
        sem->ops[0].type = OP_REG;
        sem->ops[0].reg = opc & 7;
        sem->num_ops = 1;
        sem->stk_adj = -8;
    }
    else if (opc >= 0x58 && opc <= 0x5F) {
        sem->sem_type = ST_STK;
        sem->f_out = 0;
        sem->ops[0].type = OP_REG;
        sem->ops[0].reg = opc & 7;
        sem->num_ops = 1;
        sem->stk_adj = 8;
    }
    else if (opc == 0x85 || opc == 0x87) {
        sem->sem_type = ST_CMP;
        sem->f_out = 1;
        sem->f_in = 0;
        if (opc == 0x85) {
            sem->ops[0].type = OP_MEM;
            sem->ops[1].type = OP_REG;
        } else {
            sem->ops[0].type = OP_REG;
            sem->ops[1].type = OP_MEM;
        }
        sem->num_ops = 2;
    }
    else if (opc == 0x39 || opc == 0x3B) {
        sem->sem_type = ST_CMP;
        sem->f_out = 1;
        sem->f_in = 0;
        if (opc == 0x39) {
            sem->ops[0].type = OP_MEM;
            sem->ops[1].type = OP_REG;
        } else {
            sem->ops[0].type = OP_REG;
            sem->ops[1].type = OP_MEM;
        }
        sem->num_ops = 2;
    }
    else if (opc == 0x81 || opc == 0x83) {
        sem->sem_type = ST_ALU;
        sem->f_out = 1;
        sem->ops[0].type = OP_MEM;
        sem->ops[1].type = OP_IMM;
        sem->ops[1].imm = inst.imm;
        sem->num_ops = 2;
    }
    else if (opc == 0x8D) {
        sem->sem_type = ST_MOV;
        sem->f_out = 0;
        sem->ops[0].type = OP_REG;
        sem->ops[1].type = OP_MEM;
        sem->num_ops = 2;
    }
    else if (opc == 0x87) {
        sem->sem_type = ST_MOV;
        sem->f_out = 0;
        sem->ops[0].type = OP_REG;
        sem->ops[1].type = OP_REG;
        sem->num_ops = 2;
    }
    else if (opc == 0x90) {
        sem->sem_type = ST_NOP;
        sem->num_ops = 0;
    }
    else {
        sem->sem_type = ST_NOP;
        sem->num_ops = 0;
    }
    
    if (inst.has_modrm) {
        uint8_t reg = modrm_reg(inst.modrm);
        uint8_t rm = modrm_rm(inst.modrm);
        
        for (int i = 0; i < sem->num_ops; i++) {
            if (sem->ops[i].type == OP_REG) {
                if (i == 0) sem->ops[i].reg = reg;
                else sem->ops[i].reg = rm;
            }
        }
    }
    
    return 0;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (!decode_arm64(code, &inst) || !inst.valid) return -1;
    
    sem->num_ops = 0;
    
    switch (inst.type) {
        case ARM_OP_MOV:
            sem->sem_type = ST_MOV;
            sem->f_out = 0;
            sem->ops[0].type = OP_REG;
            sem->ops[0].reg = inst.rd;
            if (inst.imm_size > 0) {
                sem->ops[1].type = OP_IMM;
                sem->ops[1].imm = inst.imm;
            } else {
                sem->ops[1].type = OP_REG;
                sem->ops[1].reg = inst.rm;
            }
            sem->num_ops = 2;
            break;
        case ARM_OP_ADD:
        case ARM_OP_SUB:
            sem->sem_type = ST_ALU;
            sem->f_out = 1;
            sem->ops[0].type = OP_REG;
            sem->ops[0].reg = inst.rd;
            sem->ops[1].type = OP_REG;
            sem->ops[1].reg = inst.rn;
            if (inst.imm_size > 0) {
                sem->ops[2].type = OP_IMM;
                sem->ops[2].imm = inst.imm;
            } else {
                sem->ops[2].type = OP_REG;
                sem->ops[2].reg = inst.rm;
            }
            sem->num_ops = 3;
            break;
        case ARM_OP_BRANCH:
        case ARM_OP_BRANCH_LINK:
            sem->sem_type = ST_FLOW;
            sem->f_out = 0;
            sem->ops[0].type = OP_REL;
            sem->ops[0].imm = inst.imm;
            sem->num_ops = 1;
            break;
        case ARM_OP_BRANCH_COND:
            sem->sem_type = ST_JCC;
            sem->f_out = 0;
            sem->f_in = 1;
            sem->ops[0].type = OP_REL;
            sem->ops[0].imm = inst.imm;
            sem->num_ops = 1;
            break;
        default:
            sem->sem_type = ST_NOP;
            sem->num_ops = 0;
            break;
    }
    
    return 0;
#endif
    return -1;
}

int sem_meta_match(const sem_meta_t *a, const sem_meta_t *b) {
    if (!a || !b) return 0;
    
    if (a->sem_type != b->sem_type) return 0;
    
    if (a->f_out != b->f_out) return 0;
    if (a->f_in != b->f_in) return 0;
    if (a->stk_out != b->stk_out) return 0;
    if (a->stk_in != b->stk_in) return 0;
    if (a->stk_adj != b->stk_adj) return 0;
    
    if (a->num_ops != b->num_ops) return 0;
    
    for (int i = 0; i < a->num_ops; i++) {
        if (a->ops[i].type != b->ops[i].type) return 0;
        if (a->ops[i].type == 1 && a->ops[i].reg == b->ops[i].reg) return 0;  // OP_REG = 1
    }
    
    return 1;
}

dom_info_t *compute_dih(cfg_t *cfg) {
    dom_info_t *dom = calloc(1, sizeof(dom_info_t));
    dom->num_doms = cfg->num_blocks;
    dom->dominators = calloc(cfg->num_blocks, sizeof(size_t));
    dom->dominated = calloc(cfg->num_blocks, sizeof(size_t));
    
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        dom->dominators[i] = i;
    }
    
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        for (size_t j = 0; j < cfg->num_blocks; j++) {
            if (i != j && cfg->blocks[j].is_exit) {
                dom->dominated[i] = j;
                break;
            }
        }
    }
    
    return dom;
}

loop_info_t *any_loops(cfg_t *cfg, dom_info_t *dom) {
    loop_info_t *loops = calloc(1, sizeof(loop_info_t));
    loops->body = calloc(cfg->num_blocks, sizeof(size_t));
    loops->body_size = 0;
    loops->exits = calloc(cfg->num_blocks, sizeof(size_t));
    loops->exits_size = 0;
    
    // Detect loops
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        if (dom->dominated[i] != i) {
            loops->body[loops->body_size++] = i;
            loops->exits[loops->exits_size++] = dom->dominated[i];
        }
    }
    
    return loops;
}

call_graph_t *d_call_graph(uint8_t *code, size_t size, cfg_t *cfg) {
    call_graph_t *cg = calloc(1, sizeof(call_graph_t));
    cg->num_edges = 0;
    cg->num_functions = 0;
    cg->edges = calloc(cfg->num_blocks, sizeof(call_edge_t));
    cg->functions = calloc(cfg->num_blocks, sizeof(size_t));
    
    // Build call graph
    for (size_t i = 0; i < cfg->num_blocks; i++) {
        if (cfg->blocks[i].is_exit) {
            cg->functions[cg->num_functions++] = i;
        }
        for (size_t j = 0; j < cfg->num_blocks; j++) {
            if (cfg->blocks[j].is_exit && cfg->blocks[i].successors[0] == j) {
                cg->edges[cg->num_edges].caller = i;
                cg->edges[cg->num_edges].callee = j;
                cg->edges[cg->num_edges].call_site = cfg->blocks[i].start;
                cg->num_edges++;
            }
        }
    }
    
    return cg;
}

int parse_modrm(const uint8_t *code, size_t len, addr_mode_t *addr) {
    if (len < 1) return -1;
    uint8_t modrm = code[0];
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm = modrm & 7;
    
    addr->base_reg = rm;
    addr->index_reg = 0;
    addr->scale = 1;
    addr->disp = 0;
    addr->has_sib = 0;
    addr->rip_relative = 0;
    
    if (mod == 0) {
        if (rm == 5) {
            addr->disp = *(int32_t*)(code + 1);
            addr->rip_relative = 1;
        }
    } else if (mod == 1) {
        addr->disp = (int8_t)code[1];
    } else if (mod == 2) {
        addr->disp = *(int32_t*)(code + 1);
    }
    
    if (rm == 4) {
        addr->has_sib = 1;
        return parse_sib(code + 1, len - 1, addr);
    }
    
    return 1 + (mod == 1 ? 1 : (mod == 2 ? 4 : 0));
}

int parse_sib(const uint8_t *code, size_t len, addr_mode_t *addr) {
    if (len < 1) return -1;
    uint8_t sib = code[0];
    uint8_t scale = (sib >> 6) & 3;
    uint8_t index = (sib >> 3) & 7;
    uint8_t base = sib & 7;
    
    addr->scale = 1 << scale;
    addr->index_reg = index;
    addr->base_reg = base;
    
    return 1;
}

int reg_usage(uint8_t opc, uint8_t modrm, uint8_t sib, real_sem_t *sem) {
    uint8_t mod = (modrm >> 6) & 3;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm = modrm & 7;
    
    sem->regs_rd = 0;
    sem->regs_wr = 0;
    
    if (opc >= 0x88 && opc <= 0x8B) {
        if (opc == 0x88 || opc == 0x8A) {
            sem->wr_reegs[sem->regs_wr++] = rm;
            sem->rd_reegs[sem->regs_rd++] = reg;
        } else {
            sem->wr_reegs[sem->regs_wr++] = reg;
            sem->rd_reegs[sem->regs_rd++] = rm;
        }
    } else if (opc >= 0x00 && opc <= 0x05) {
        sem->wr_reegs[sem->regs_wr++] = reg;
        sem->rd_reegs[sem->regs_rd++] = reg;
        sem->rd_reegs[sem->regs_rd++] = rm;
    } else if (opc >= 0x08 && opc <= 0x0D) {
        sem->wr_reegs[sem->regs_wr++] = reg;
        sem->rd_reegs[sem->regs_rd++] = reg;
        sem->rd_reegs[sem->regs_rd++] = rm;
    }
    
    if (sib != 0) {
        uint8_t index = (sib >> 3) & 7;
        uint8_t base = sib & 7;
        if (index != 4) sem->rd_reegs[sem->regs_rd++] = index;
        if (base != 5) sem->rd_reegs[sem->regs_rd++] = base;
    }
    
    return 0;
}

int mem_access(uint8_t opc, addr_mode_t *addr, real_sem_t *sem) {
    sem->mem_rd = 0;
    sem->mem_wr = 0;
    sem->mem_addr = 0;
    
    if (opc >= 0x88 && opc <= 0x8B) {
        if (opc == 0x88 || opc == 0x8A) {
            sem->mem_wr = 1;
        } else {
            sem->mem_rd = 1;
        }
    } else if (opc >= 0x00 && opc <= 0x05) {
        sem->mem_rd = 1;
    } else if (opc >= 0x08 && opc <= 0x0D) {
        sem->mem_rd = 1;
    }
    
    if (sem->mem_rd || sem->mem_wr) {
        sem->mem_addr = addr->disp;
        if (addr->base_reg != 5) sem->mem_addr += addr->base_reg;
        if (addr->index_reg != 4) sem->mem_addr += addr->index_reg * addr->scale;
    }
    
    return 0;
}

int flag_effects(uint8_t opc, real_sem_t *sem) {
    sem->flag_rd = 0;
    sem->falg_wr = 0;
    
    if (opc >= 0x00 && opc <= 0x05) {
        sem->falg_wr = 0x3F;
    } else if (opc >= 0x08 && opc <= 0x0D) {
        sem->falg_wr = 0x3F;
    } else if (opc >= 0x70 && opc <= 0x7F) {
        sem->flag_rd = 0x3F;
    } else if (opc == 0x85 || opc == 0x87) {
        sem->falg_wr = 0x3F;
    } else if (opc == 0x39 || opc == 0x3B) {
        sem->falg_wr = 0x3F;
    }
    
    return 0;
}

int analyze_sem(const uint8_t *code, size_t len, real_sem_t *sem) {
    memset(sem, 0, sizeof(*sem));
    if (len < 1) return -1;
    
#if defined(ARCH_X86)
    x86_inst_t inst;
    if (!decode_x86_withme(code, len, 0, &inst, NULL) || !inst.valid) return -1;
    
    uint8_t opc = inst.opcode[0];
    addr_mode_t addr = {0};
    
    if (inst.has_modrm) {
        parse_modrm(code + inst.opcode_len, len - inst.opcode_len, &addr);
        if (addr.has_sib) {
            parse_sib(code + inst.opcode_len + 1, len - inst.opcode_len - 1, &addr);
        }
        reg_usage(opc, inst.modrm, inst.sib, sem);
        mem_access(opc, &addr, sem);
    }
    
    flag_effects(opc, sem);
    
    if (opc >= 0x50 && opc <= 0x57) {
        sem->stk_adj = -8;
    } else if (opc >= 0x58 && opc <= 0x5F) {
        sem->stk_adj = 8;
    } else if (opc == 0xE8) {
        sem->stk_adj = -8;
    } else if (opc == 0xC3) {
        sem->stk_adj = 8;
    }
    
    if (opc >= 0x70 && opc <= 0x7F) {
        sem->voll = 1;
    }
    
    return 0;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (!decode_arm64(code, &inst) || !inst.valid) return -1;
    
    sem->regs_rd = 0;
    sem->regs_wr = 0;
    
    switch (inst.type) {
        case ARM_OP_MOV:
            sem->wr_reegs[sem->regs_wr++] = inst.rd;
            if (inst.imm_size == 0) {
                sem->rd_reegs[sem->regs_rd++] = inst.rm;
            }
            break;
        case ARM_OP_ADD:
        case ARM_OP_SUB:
            sem->wr_reegs[sem->regs_wr++] = inst.rd;
            sem->rd_reegs[sem->regs_rd++] = inst.rn;
            if (inst.imm_size == 0) {
                sem->rd_reegs[sem->regs_rd++] = inst.rm;
            }
            sem->falg_wr = 0x3F;
            break;
        case ARM_OP_BRANCH_COND:
            sem->flag_rd = 0x3F;
            sem->voll = 1;
            break;
    }
    
    return 0;
#endif
    return -1;
}

int real_sem_match(const real_sem_t *a, const real_sem_t *b) {
    if (!a || !b) return 0;
    
    if (a->stk_adj != b->stk_adj) return 0;
    if (a->mem_rd != b->mem_rd) return 0;
    if (a->mem_wr != b->mem_wr) return 0;
    if (a->flag_rd != b->flag_rd) return 0;
    if (a->falg_wr != b->falg_wr) return 0;
    if (a->ring0 != b->ring0) return 0;
    if (a->voll != b->voll) return 0;
    
    for (int i = 0; i < a->regs_rd; i++) {
        for (int j = 0; j < b->regs_wr; j++) {
            if (a->rd_reegs[i] == b->wr_reegs[j]) return 0;
        }
    }
    
    for (int i = 0; i < a->regs_wr; i++) {
        for (int j = 0; j < b->regs_rd; j++) {
            if (a->wr_reegs[i] == b->rd_reegs[j]) return 0;
        }
    }
    
    return 1;
}

int apply_me_again(uint8_t *code, size_t size, size_t off1, size_t off2, chacha_state_t *r) {
    instr_info_t m[256];
    size_t n = decode_map(code, size, m, 256);
    
    size_t i = 0, j = 0;
    for (size_t k = 0; k < n; k++) {
        if (m[k].off == off1) i = k;
        if (m[k].off == off2) j = k;
    }
    
    real_sem_t sem_i, sem_j;
    if (analyze_sem(code + m[i].off, m[i].len, &sem_i) != 0) return 0;
    if (analyze_sem(code + m[j].off, m[j].len, &sem_j) != 0) return 0;
    
    if (!real_sem_match(&sem_i, &sem_j)) return 0;
    
    uint8_t tmp[16];
    memmove(tmp, code + m[i].off, m[i].len);
    memmove(code + m[i].off, code + m[j].off, m[j].len);
    memmove(code + m[j].off, tmp, m[i].len);
    
    if (it_chunk(code, size)) return 1;
    
    memmove(code + m[j].off, code + m[i].off, m[i].len);
    memmove(code + m[i].off, tmp, m[i].len);
    if (m[i].off + m[j].len > size || m[j].off + m[i].len > size) {
    // Don't do the swap, it's not safe
    return 0;
    }
}

void xpass_rswp(uint8_t *c, size_t sz, chacha_state_t *r) {
    instr_info_t m[256];
    size_t n = decode_map(c, sz, m, 256);
    if (n < 2) return;
    
    for (int t = 0; t < 16; t++) {
        size_t i = chacha20_random(r) % n;
        size_t j = chacha20_random(r) % n;
        if (i == j) continue;
        if (m[i].cf || m[j].cf) continue;
        
        // Add register dependency check
        real_sem_t sem_i, sem_j;
        if (analyze_sem(c + m[i].off, m[i].len, &sem_i) != 0) continue;
        if (analyze_sem(c + m[j].off, m[j].len, &sem_j) != 0) continue;
        
        if (!real_sem_match(&sem_i, &sem_j)) continue;
        
        uint8_t tmp[16];
        memmove(tmp, c + m[i].off, m[i].len);
        memmove(c + m[i].off, c + m[j].off, m[j].len);
        memmove(c + m[j].off, tmp, m[i].len);
        
        if (it_chunk(c, sz)) return;
        
        // Revert if invalid
        memcpy(c + m[j].off, c + m[i].off, m[i].len);
        memcpy(c + m[i].off, tmp, m[i].len);
    }
}

uint8_t* prepare_mut(const uint8_t *shellcode, size_t shellcode_len, size_t *buffer_size, chacha_state_t *rng) {
    size_t min_size = 256;
    size_t optimal_size = shellcode_len + 128; 
    
    if (optimal_size < min_size) optimal_size = min_size;
    if (optimal_size > PAGE_SIZE) optimal_size = PAGE_SIZE;
    
    *buffer_size = optimal_size;
    
    uint8_t *buffer = malloc(optimal_size);
    if (!buffer) return NULL;
    
    memcpy(buffer, shellcode, shellcode_len);
    size_t remaining = optimal_size - shellcode_len;
    
#if defined(ARCH_X86)
    size_t offset = shellcode_len;
    while (offset + 3 <= optimal_size) {
        uint8_t junk_buf[16];
        size_t junk_len;
        genmesomejunk(junk_buf, &junk_len, rng);
        
        if (offset + junk_len <= optimal_size) {
            memcpy(buffer + offset, junk_buf, junk_len);
            offset += junk_len;
        } else {
            break;
        }
    }
    memset(buffer + offset, 0x90, optimal_size - offset);
#elif defined(ARCH_ARM)
    size_t offset = shellcode_len;
    while (offset + 4 <= optimal_size) {
        uint8_t junk_buf[16];
        size_t junk_len;
        genmesomejunk(junk_buf, &junk_len, rng);
        
        if (offset + junk_len <= optimal_size) {
            memcpy(buffer + offset, junk_buf, junk_len);
            offset += junk_len;
        } else {
            break;
        }
    }
    while (offset < optimal_size) {
        buffer[offset++] = 0xD5; 
        if (offset < optimal_size) buffer[offset++] = 0x03;
        if (offset < optimal_size) buffer[offset++] = 0x20;
        if (offset < optimal_size) buffer[offset++] = 0x1F;
    }
#endif
    
    return buffer;
}

void mut_sh3ll(uint8_t *shellcode, size_t shellcode_len, chacha_state_t *rng, unsigned gen) {
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
        // for now OnlyNOP, mov reg,reg (reg==reg), xor reg,reg (reg==reg)
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

void crashh(const uint8_t *data, size_t len, const char *label) {
    DBG("[CRASH] crashh: %s", label);
    for (size_t i = 0; i < len; i += 16) {
        char line[80] = {0};
        size_t n = (len - i > 16) ? 16 : (len - i);
        for (size_t j = 0; j < n; ++j)
            sprintf(line + j*3, "%02x ", data[i+j]);
        DBG("%04zx: %s", i, line);
    }
}

static void nahh(int sig, siginfo_t *info, void *ucontext) { 
    void *ip = NULL;
#if defined(__x86_64__)
    ucontext_t *ctx = (ucontext_t *)ucontext;
    ip = (void *)ctx->uc_mcontext->__ss.__rip;
#elif defined(__aarch64__)
    ucontext_t *ctx = (ucontext_t *)ucontext;
    ip = (void *)ctx->uc_mcontext->__ss.__pc;
#else
    ip = NULL;
#endif
    DBG("[CRASH] %d at IP %p", sig, ip);
    if (did_we_cry && did_we_cry_size > 0 && ip) {
        uintptr_t code_start = (uintptr_t)did_we_cry;
        uintptr_t code_end = code_start + did_we_cry_size;
        uintptr_t ip_addr = (uintptr_t)ip;
        uintptr_t dump_start = ip_addr > code_start + 32 ? ip_addr - 32 : code_start;
        uintptr_t dump_end = ip_addr + 32 < code_end ? ip_addr + 32 : code_end;
        size_t dump_len = dump_end > dump_start ? dump_end - dump_start : 0;
        if (dump_len > 0)
            crashh((const uint8_t *)dump_start, dump_len, "code around crash");
    }
    _exit(128 + sig);
}

void set_crash(void) { 
    struct sigaction sa;
    sa.sa_sigaction = nahh;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
}

static void rec_cfg_add_block(rec_cfg_t *cfg, size_t start, size_t end, bool is_exit) {
    if (cfg->num_blocks >= cfg->cap_blocks) {
        cfg->cap_blocks = cfg->cap_blocks ? cfg->cap_blocks * 2 : 32;
        cfg->blocks = realloc(cfg->blocks, cfg->cap_blocks * sizeof(rec_block_t));
    }
    rec_block_t *b = &cfg->blocks[cfg->num_blocks++];
    b->start = start;
    b->end = end;
    b->num_successors = 0;
    b->is_exit = is_exit;
}

static void shit_recursive_x86_inner(const uint8_t *code, size_t size, rec_cfg_t *cfg, size_t addr) {
    if (addr >= size || cfg->visited[addr]) return;
    cfg->visited[addr] = true;
    size_t off = addr;
    while (off < size) {
        x86_inst_t inst;
        if (!decode_x86_withme(code + off, size - off, 0, &inst, NULL) || !inst.valid || inst.len == 0) {
            rec_cfg_add_block(cfg, addr, off + 1, true);
            return;
        }
        if (inst.opcode[0] == 0xC3 || inst.opcode[0] == 0xCB) { // ret
            rec_cfg_add_block(cfg, addr, off + inst.len, true);
            return;
        } else if ((inst.opcode[0] & 0xF0) == 0x70 || inst.opcode[0] == 0xE3) { // jcc short
            int8_t rel = (int8_t)inst.imm;
            size_t target = off + inst.len + rel;
            rec_cfg_add_block(cfg, addr, off + inst.len, false);
            shit_recursive_x86_inner(code, size, cfg, target);
            shit_recursive_x86_inner(code, size, cfg, off + inst.len);
            return;
        } else if (inst.opcode[0] == 0xE9) { // jmp rel32
            int32_t rel = (int32_t)inst.imm;
            size_t target = off + inst.len + rel;
            rec_cfg_add_block(cfg, addr, off + inst.len, false);
            shit_recursive_x86_inner(code, size, cfg, target);
            return;
        } else if (inst.opcode[0] == 0xEB) { // jmp rel8
            int8_t rel = (int8_t)inst.imm;
            size_t target = off + inst.len + rel;
            rec_cfg_add_block(cfg, addr, off + inst.len, false);
            shit_recursive_x86_inner(code, size, cfg, target);
            return;
        } else if (inst.opcode[0] == 0xE8) { // call rel32
            int32_t rel = (int32_t)inst.imm;
            size_t target = off + inst.len + rel;
            shit_recursive_x86_inner(code, size, cfg, target);
            // fallthrough to next
        } else if (inst.opcode[0] == 0xFF && (inst.modrm & 0x38) == 0x10) { // call [mem/reg]
            rec_cfg_add_block(cfg, addr, off + inst.len, true);
            return;
        } else if (inst.opcode[0] == 0xFF && (inst.modrm & 0x38) == 0x20) { // jmp [mem/reg]
            rec_cfg_add_block(cfg, addr, off + inst.len, true);
            return;
        }
        off += inst.len;
    }
    rec_cfg_add_block(cfg, addr, off, true);
}

static rec_cfg_t *shit_recursive_x86(const uint8_t *code, size_t size) {
    rec_cfg_t *cfg = calloc(1, sizeof(rec_cfg_t));
    cfg->code_size = size;
    cfg->visited = calloc(size, sizeof(bool));
    shit_recursive_x86_inner(code, size, cfg, 0);
    return cfg;
}

void mut_with_x86(uint8_t *code, size_t size, chacha_state_t *rng, unsigned gen, muttt_t *log) {
    rec_cfg_t *cfg = shit_recursive_x86(code, size);
    size_t *order = malloc(cfg->num_blocks * sizeof(size_t));
    for (size_t i = 0; i < cfg->num_blocks; ++i) order[i] = i;
    for (size_t i = cfg->num_blocks - 1; i > 0; --i) {
        size_t j = chacha20_random(rng) % (i + 1);
        size_t tmp = order[i]; order[i] = order[j]; order[j] = tmp;
    }
    uint8_t *tmp = malloc(size * 2); 
    size_t out = 0;
    for (size_t i = 0; i < cfg->num_blocks; ++i) {
        rec_block_t *b = &cfg->blocks[order[i]];
        size_t blen = b->end - b->start;
        if ((chacha20_random(rng) % 4) == 0) {
            uint8_t opq_buf[32]; size_t opq_len; uint32_t val = chacha20_random(rng);
            Opaque(opq_buf, &opq_len, val, rng);
            memcpy(tmp + out, opq_buf, opq_len); out += opq_len;
            if (log) logme(log, out - opq_len, opq_len, MUT_PRED, gen, "opaque@entry");
        }
        if ((chacha20_random(rng) % 3) == 0) {
            uint8_t junk_buf[16]; size_t junk_len;
            genmesomejunk(junk_buf, &junk_len, rng);
            memcpy(tmp + out, junk_buf, junk_len); out += junk_len;
            if (log) logme(log, out - junk_len, junk_len, MUT_JUNK, gen, "junk@entry");
        }
        memcpy(tmp + out, code + b->start, blen); out += blen;
        if ((chacha20_random(rng) % 4) == 0) {
            uint8_t opq_buf[32]; size_t opq_len; uint32_t val = chacha20_random(rng);
            Opaque(opq_buf, &opq_len, val, rng);
            memcpy(tmp + out, opq_buf, opq_len); out += opq_len;
            if (log) logme(log, out - opq_len, opq_len, MUT_PRED, gen, "opaque@exit");
        }
        if ((chacha20_random(rng) % 3) == 0) {
            uint8_t junk_buf[16]; size_t junk_len;
            genmesomejunk(junk_buf, &junk_len, rng);
            memcpy(tmp + out, junk_buf, junk_len); out += junk_len;
            if (log) logme(log, out - junk_len, junk_len, MUT_JUNK, gen, "junk@exit");
        }
        if ((chacha20_random(rng) % 6) == 0) {
            size_t fake_len = 4 + (chacha20_random(rng) % 8);
            uint8_t *fake = malloc(fake_len);
            for (size_t k = 0; k < fake_len;) {
                uint8_t junk_buf[16]; size_t junk_len;
                genmesomejunk(junk_buf, &junk_len, rng);
                size_t to_copy = (k + junk_len > fake_len) ? (fake_len - k) : junk_len;
                memcpy(fake + k, junk_buf, to_copy); k += to_copy;
            }
            memcpy(tmp + out, fake, fake_len); out += fake_len;
            free(fake);
            if (log) logme(log, out - fake_len, fake_len, MUT_DEAD, gen, "fake block");
        }
    }
    if ((chacha20_random(rng) % 3) == 0) {
        uint8_t opq_buf[32]; size_t opq_len; uint32_t val = chacha20_random(rng);
        Opaque(opq_buf, &opq_len, val, rng);
        memmove(tmp + opq_len, tmp, out); memcpy(tmp, opq_buf, opq_len); out += opq_len;
        if (log) logme(log, 0, opq_len, MUT_FLATTEN, gen, "dispatcher/flatten");
    }
    memcpy(code, tmp, out > size ? size : out);
    free(tmp);
    free(order);
    free(cfg->blocks);
    free(cfg->visited);
    free(cfg);
    if (log) logme(log, 0, out, MUT_REORDER, gen, "Bl0ck reorder");
}

#endif
