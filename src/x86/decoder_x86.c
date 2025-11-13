#include <aether.h>

/* http://ref.x86asm.net/coder64.html */

#if defined(ARCH_X86)
 
 /* modrm_reg - Extracts the reg field from a ModR/M byte. */
uint8_t modrm_reg(uint8_t m);

/* modrm_rm - Extracts the r/m field from a ModR/M byte. */
uint8_t modrm_rm(uint8_t m);

/* Legacy prefix? (lock, rep, segment, size) */
static inline bool is_legacy_prefix(uint8_t b) {
    return b == 0xF0 || b == 0xF2 || b == 0xF3 ||
           b == 0x2E || b == 0x36 || b == 0x3E ||
           b == 0x26 || b == 0x64 || b == 0x65 ||
           b == 0x66 || b == 0x67;
}

/* REX prefix? (0x40-0x4F) */
static inline bool is_rex(uint8_t b) { return (b & 0xF0) == 0x40; }

/* Extract REX.W/R/X/B fields */
static void parse_rex(x86_inst_t *inst, uint8_t rex) {
    inst->rex = rex;
    inst->rex_w = (rex >> 3) & 1;
    inst->rex_r = (rex >> 2) & 1;
    inst->rex_x = (rex >> 1) & 1;
    inst->rex_b = (rex >> 0) & 1;
}

/* modrm_mod is defined in decoder_x86.h */
static inline uint8_t sib_scale(uint8_t s) { return (s >> 6) & 3; }
static inline uint8_t sib_index(uint8_t s) { return (s >> 3) & 7; }
static inline uint8_t sib_base(uint8_t s) { return s & 7; }

static inline bool have(const uint8_t *p, const uint8_t *end, size_t n) {
    return (size_t)(end - p) >= n;
}

static uint64_t read_imm_le(const uint8_t *p, uint8_t size) {
    uint64_t v = 0;
    for (uint8_t i = 0; i < size; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

static int64_t read_disp_se(const uint8_t *p, uint8_t size) {
    uint64_t u = read_imm_le(p, size);
    if (size == 1) return (int8_t)u;
    if (size == 2) return (int16_t)u;
    return (int32_t)u;  
}

/* Parse VEX (2/3-byte) or EVEX prefix for AVX instructions */
static bool parse_vex_evex(x86_inst_t *inst, const uint8_t **p, const uint8_t *end) {
    if (!have(*p, end, 1)) return false;
    uint8_t first = **p;

    if (first == 0x62) {  /* EVEX */
        if (!have(*p, end, 4)) return false;
        inst->evex = true;
        inst->evex_mmmm = (*p)[1] >> 3;
        inst->evex_pp   = (*p)[2] & 0x3;
        inst->evex_L    = ((*p)[2] >> 2) & 1;
        inst->evex_vvvv = (~(*p)[2] >> 3) & 0xF;
        *p += 4;
        return true;
    } else if (first == 0xC4) {  /* VEX 3-byte */
        if (!have(*p, end, 3)) return false;
        inst->vex = true;
        inst->vex_mmmm = (*p)[1] & 0x1F;
        inst->vex_pp   = (*p)[2] & 0x3;
        inst->vex_L    = ((*p)[2] >> 2) & 1;
        inst->vex_vvvv = (~(*p)[2] >> 3) & 0xF;
        *p += 3;
        return true;
    } else if (first == 0xC5) {  /* VEX 2-byte */
        if (!have(*p, end, 2)) return false;
        inst->vex = true;
        inst->vex_L    = ((*p)[1] >> 2) & 1;
        inst->vex_vvvv = (~(*p)[1] >> 3) & 0xF;
        inst->vex_pp   = (*p)[1] & 0x3;
        *p += 2;
        return true;
    }
    return false;
}

/* Is this a SIMD/MMX instruction? */
static bool is_simd(uint8_t op0, uint8_t op1, bool has_legacy_prefix) {
    if (op0 != 0x0F) return false;
    
    /* MMX/SSE moves */
    if (op1 == 0x6E || op1 == 0x7E) return true;  
    if (op1 == 0x6F || op1 == 0x7F) return true; 
    
    /* SSE/SSE2 moves and operations */
    if ((op1 & 0xF0) == 0x10) return true; 
    if ((op1 & 0xF0) == 0x20) return true; 
    if ((op1 & 0xF0) == 0x50) return true;  
    if ((op1 & 0xF0) == 0x60) return true; 
    if ((op1 & 0xF0) == 0x70) return true;  
    if ((op1 & 0xF0) == 0xD0) return true; 
    if ((op1 & 0xF0) == 0xE0) return true; 
    if ((op1 & 0xF0) == 0xF0) return true; 
    
    /* SSE comparison and shuffle */
    if (op1 == 0xC2) return true;  /* CMPPS, CMPPD, CMPSS, CMPSD */
    if (op1 == 0xC6) return true;  /* SHUFPS, SHUFPD */
    
    (void)has_legacy_prefix;  /* May use this later for prefix-specific detection */
    return false;
}

/* Does this instruction modify RIP? */
static bool is_cflow(uint8_t op0, uint8_t op1, bool has_modrm, uint8_t modrm) {
    if (op0 == 0xC3 || op0 == 0xCB || op0 == 0xC2 || op0 == 0xCA) return true;
    if (op0 == 0xE8 || op0 == 0xE9 || op0 == 0xEB || op0 == 0xEA || op0 == 0x9A) return true;
    if (op0 >= 0x70 && op0 <= 0x7F) return true;
    if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F) return true;
    if (op0 >= 0xE0 && op0 <= 0xE3) return true;
    if (op0 == 0xFF && has_modrm) {
        uint8_t r = modrm_reg(modrm);
        if (r == 2 || r == 3 || r == 4 || r == 5) return true;
    }
    return false;
}

 
static bool needs_modrm(uint8_t op0, uint8_t op1) {
    if (op0 == 0x0F) {
        if ((op1 & 0xF0) == 0x10 || (op1 & 0xF0) == 0x20 || (op1 & 0xF0) == 0x28 ||
            (op1 & 0xF0) == 0x38 || (op1 & 0xF0) == 0x3A) return true;
        if ((op1 & 0xF0) == 0x60 || (op1 & 0xF0) == 0x70) return true;
        if (op1 == 0x6F || op1 == 0x7F) return true;  
        if (op1 == 0x6E || op1 == 0x7E) return true;  /* MOVD */
        if ((op1 & 0xF0) == 0xD0 || (op1 & 0xF0) == 0xE0 || (op1 & 0xF0) == 0xF0) return true; 
        if (op1 == 0xAE || op1 == 0xAF) return true;  /* FXSAVE, IMUL */
        if (op1 == 0xB6 || op1 == 0xB7 || op1 == 0xBE || op1 == 0xBF) return true;  /* MOVZX, MOVSX */
        if (op1 == 0xC2 || op1 == 0xC4 || op1 == 0xC5 || op1 == 0xC6) return true;  /* CMP*, PINSRW, SHUFPS */
        /* Bit instructions */
        if (op1 == 0xA3 || op1 == 0xAB || op1 == 0xB3 || op1 == 0xBB) return true;  /* BT, BTS, BTR, BTC */
        if (op1 == 0xBA) return true;  
        if (op1 == 0xBC || op1 == 0xBD) return true;  /* BSF, BSR */
        /* arithmetic */
        if (op1 == 0xA4 || op1 == 0xA5 || op1 == 0xAC || op1 == 0xAD) return true;  /* SHLD, SHRD */
    }
    if ((op0 >= 0x88 && op0 <= 0x8E) || op0 == 0x8F) return true;
    if (op0 == 0x01 || op0 == 0x03 || op0 == 0x29 || op0 == 0x2B ||
        op0 == 0x31 || op0 == 0x33 || op0 == 0x21 || op0 == 0x23 ||
        op0 == 0x09 || op0 == 0x0B || op0 == 0x39 || op0 == 0x3B ||
        op0 == 0x85 || op0 == 0x87 || op0 == 0x8D || op0 == 0xFF ||
        op0 == 0x81 || op0 == 0x83 || op0 == 0xC7) return true;
    return false;
}

 
static bool needs_imm(uint8_t op0, uint8_t op1, bool has_modrm, uint8_t modrm) {
    (void)op1; (void)has_modrm; (void)modrm;
    if (op0 >= 0xB8 && op0 <= 0xBF) return true;
    if (op0 == 0xC7) return true;
    if (op0 == 0x81 || op0 == 0x83) return true;
    if (op0 == 0xE8 || op0 == 0xE9 || op0 == 0xEB) return true;
    if (op0 >= 0x70 && op0 <= 0x7F) return true;         
    if (op0 == 0x0F && (op1 >= 0x80 && op1 <= 0x8F)) return true;  
    if (op0 >= 0xE0 && op0 <= 0xE3) return true;         
    if (op0 == 0xC2 || op0 == 0xCA) return true;         
    return false;
}

static uint8_t imm_size_for(uint8_t op0, uint8_t op1, bool rex_w, bool opsz16) {
    (void)op1;
    
     
    if (op0 >= 0xB8 && op0 <= 0xBF) {
        if (rex_w) return 8;
        return opsz16 ? 2 : 4;
    }
    
     
    switch (op0) {
        case 0xC7:  
        case 0x81:  
            return opsz16 ? 2 : 4;
            
        case 0x83:  
            return 1;
            
        case 0xE8:  
        case 0xE9:  
            return 4;
            
        case 0xEB:  
            return 1;
            
        case 0xC2:  
        case 0xCA:  
            return 2;
            
        default:
            if (op0 == 0x0F) {
                if (op1 >= 0x80 && op1 <= 0x8F) return 4;  
            }             
            if ((op0 >= 0x70 && op0 <= 0x7F) ||  
                (op0 >= 0xE0 && op0 <= 0xE3)) {  
                return 1;
            }
    }
    
    return 0;
}

/* Calculate absolute target for branches/calls */
static void resolve_target(x86_inst_t *inst, uintptr_t ip) {
    if (!inst->valid) return;
    uint8_t o0 = inst->opcode[0], o1 = inst->opcode[1];

    if (o0 == 0xE8) {  
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int32_t)inst->imm;
    } else if (o0 == 0xE9) {  
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int32_t)inst->imm;
    } else if (o0 == 0xEB) {  
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int8_t)inst->imm;
    } else if (o0 >= 0x70 && o0 <= 0x7F) {  
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int8_t)inst->imm;
    } else if (o0 == 0x0F && (o1 >= 0x80 && o1 <= 0x8F)) {  
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int32_t)inst->imm;
    } else if (o0 >= 0xE0 && o0 <= 0xE3) {  
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int8_t)inst->imm;
    } else if (o0 == 0xFF && inst->has_modrm) {
        uint8_t r = modrm_reg(inst->modrm);
        if (r == 2 || r == 3 || r == 4 || r == 5) {  
            inst->modifies_ip = true;
            inst->target = 0;  
        }
    } else if (o0 == 0xEA || o0 == 0x9A) {  
        inst->modifies_ip = true;
        inst->target = 0;
    } else if (o0 == 0xC2 || o0 == 0xCA || o0 == 0xC3 || o0 == 0xCB) {
        inst->modifies_ip = true;
        inst->target = 0;
    }
}

 
static void parse_ea_and_disp(x86_inst_t *inst, const uint8_t **p, const uint8_t *end,
                              bool addr32_mode, bool rex_b, bool *has_sib_out,
                              memread_fn mem_read, uintptr_t ip) {
    uint8_t m = inst->modrm;
    uint8_t mod = modrm_mod(m), rm = modrm_rm(m);
    uint8_t extended_rm = rm | (rex_b ? 0x8 : 0);

    inst->has_sib = false;

    if (mod != 3 && rm == 4) {
        if (!have(*p, end, 1)) { inst->valid = false; return; }
        inst->has_sib = true;
        inst->sib = *(*p)++;
        if (has_sib_out) *has_sib_out = true;

        uint8_t base = sib_base(inst->sib);
        if (base == 5 && mod == 0) {
            if (!have(*p, end, 4)) { inst->valid = false; return; }
            inst->disp_size = 4;
            inst->disp = read_disp_se(*p, 4);
            *p += 4;
            inst->rip_relative = !addr32_mode;
        }
    }

    if (mod == 1) {
        if (!have(*p, end, 1)) { inst->valid = false; return; }
        inst->disp_size = 1;
        inst->disp = read_disp_se(*p, 1);
        *p += 1;
    } else if (mod == 2) {
        if (!have(*p, end, 4)) { inst->valid = false; return; }
        inst->disp_size = 4;
        inst->disp = read_disp_se(*p, 4);
        *p += 4;
    } else if (mod == 0 && extended_rm == 5) {
        if (!have(*p, end, 4)) { inst->valid = false; return; }
        inst->disp_size = 4;
        inst->disp = read_disp_se(*p, 4);
        *p += 4;
        inst->rip_relative = true;
    }

    if (inst->rip_relative && mem_read) {
        uintptr_t addr = ip + inst->len + inst->disp;
        uint64_t val = 0;
        if (mem_read(&val, addr, inst->imm_size ? inst->imm_size : 4)) {
            inst->resolved_mem = val;
        }
    }
}

/**
 * Legacy prefixes, REX, VEX/EVEX,
 * ModR/M, SIB, displacements, immediates, RIP-relative addressing.
 * Max 4 legacy prefixes, max 15 bytes total per Intel spec.
 */
bool decode_x86_withme(const uint8_t *code, size_t size, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read) {
    (void)mem_read;
    memset(inst, 0, sizeof(*inst));
    inst->valid = true;

    const uint8_t *p = code;
    const uint8_t *end = size ? (code + size) : (code + 15);

    bool have_lock = false, have_rep = false, have_repne = false;
    bool opsz16 = false, addrsz32 = false;
    uint8_t seg_override = 0;
    uint8_t prefix_count = 0;
    const uint8_t MAX_PREFIXES = 4; /* Intel spec: max 4 legacy prefixes */

    /* Parse prefixes (legacy + REX) */
    while (p < end && prefix_count < MAX_PREFIXES) {
        if (!have(p, end, 1)) break;
        uint8_t b = *p;
        
        if (is_rex(b)) {
            parse_rex(inst, b);
            p++;
            continue;
        }
        
        if (!is_legacy_prefix(b)) break;
        
        switch (b) {
            case 0xF0: have_lock = true; break;
            case 0xF3: have_rep = true; break;
            case 0xF2: have_repne = true; break;
            case 0x66: opsz16 = true; break;
            case 0x67: addrsz32 = true; break;
            default: 
                if (b == 0x2E || b == 0x36 || b == 0x3E || 
                    b == 0x26 || b == 0x64 || b == 0x65) {
                    seg_override = b;
                }
                break;
        }
        p++;
        prefix_count++;
        
        /* don't exceed max instruction length */
        if ((size_t)(p - code) >= 15) {
            inst->valid = false;
            return false;
        }
    }
    
    if (!have(p, end, 1)) { inst->valid = false; return false; }

     
    if (!parse_vex_evex(inst, &p, end)) {
         
        if (!have(p, end, 1)) { inst->valid = false; return false; }
    }

     
    inst->opcode[0] = *p++;
    inst->opcode_len = 1;
    
     
    if (inst->opcode[0] == 0x0F) {
        if (!have(p, end, 1)) { inst->valid = false; return false; }
        inst->opcode[1] = *p++;
        inst->opcode_len++;
        
        if (inst->opcode[1] == 0x38 || inst->opcode[1] == 0x3A) {
            if (!have(p, end, 1)) { inst->valid = false; return false; }
            inst->opcode[2] = *p++;
            inst->opcode_len++;
        }
    }

     
    bool has_sib = false;
    if (needs_modrm(inst->opcode[0], inst->opcode[1])) {
        if (!have(p, end, 1)) { inst->valid = false; return false; }
        inst->has_modrm = true;
        inst->modrm = *p++;
        
    parse_ea_and_disp(inst, &p, end, addrsz32, inst->rex_b, &has_sib, mem_read, ip);
    if (!inst->valid) return false;
    }
     
    if (needs_imm(inst->opcode[0], inst->opcode[1], inst->has_modrm, inst->modrm)) {
        inst->imm_size = imm_size_for(inst->opcode[0], inst->opcode[1], inst->rex_w, opsz16);
        if (inst->imm_size > 0) {
            if (!have(p, end, inst->imm_size)) { inst->valid = false; return false; }
            inst->imm = read_imm_le(p, inst->imm_size);
            p += inst->imm_size;
        }
    }

    /* Calculate instruction length */
    inst->len = (uint8_t)(p - code);
    if (inst->len > 15) {
        inst->valid = false;
        return false;
    }
    
    /* Copy raw bytes */
    memcpy(inst->raw, code, inst->len);

     
    inst->is_control_flow = is_cflow(inst->opcode[0], inst->opcode[1], inst->has_modrm, inst->modrm);
    inst->lock = have_lock;
    inst->rep = have_rep;
    inst->repne = have_repne;
    inst->seg = seg_override;
    inst->opsize_16 = opsz16;
    inst->addrsize_32 = addrsz32;
    
    /* Mark SIMD instructions */
    inst->is_simd = inst->vex || inst->evex || is_simd(inst->opcode[0], inst->opcode[1], opsz16 || have_rep || have_repne);

     
    resolve_target(inst, ip);

    return inst->valid;
}

/* Decode x86-64 instruction  */
bool decode_x86(const uint8_t *code, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read) {
    return decode_x86_withme(code, 15, ip, inst, mem_read);
}

#endif  
