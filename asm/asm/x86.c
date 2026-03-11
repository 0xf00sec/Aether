#include "x86.h"

static inline bool have(const uint8_t *p, const uint8_t *end, size_t n) {
    return (size_t)(end - p) >= n;
}

static int64_t read_se(const uint8_t *p, uint8_t sz) {
    uint64_t v = 0;
    for (uint8_t i = 0; i < sz; i++) v |= ((uint64_t)p[i]) << (i * 8);
    if (sz == 1) return (int8_t)v;
    if (sz == 2) return (int16_t)v;
    if (sz == 4) return (int32_t)v;
    return (int64_t)v;
}

static uint64_t read_le(const uint8_t *p, uint8_t sz) {
    uint64_t v = 0;
    for (uint8_t i = 0; i < sz; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

static inline bool is_prefix(uint8_t b) {
    return b == 0xF0 || b == 0xF2 || b == 0xF3 ||
           b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
           b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67;
}

/* opcode classification */

static bool needs_modrm(uint8_t op0, uint8_t op1) {
    if (op0 == 0x0F) {
        if (op1 == 0xAF || op1 == 0xB6 || op1 == 0xB7 ||
            op1 == 0xBE || op1 == 0xBF) return true; /* IMUL, MOVZX, MOVSX */
        if ((op1 >= 0x40 && op1 <= 0x4F) || (op1 >= 0x90 && op1 <= 0x9F))
            return true; /* CMOVcc, SETcc */
        if ((op1 & 0xF0) == 0x10 || (op1 & 0xF0) == 0x20 ||
            (op1 & 0xF0) == 0x50 || (op1 & 0xF0) == 0x60 ||
            (op1 & 0xF0) == 0x70 || (op1 & 0xF0) == 0xD0 ||
            (op1 & 0xF0) == 0xE0 || (op1 & 0xF0) == 0xF0) return true;
        if (op1 == 0x6E || op1 == 0x6F || op1 == 0x7E || op1 == 0x7F) return true;
        if (op1 == 0xA3 || op1 == 0xAB || op1 == 0xB3 || op1 == 0xBA ||
            op1 == 0xBB || op1 == 0xBC || op1 == 0xBD) return true;
        if (op1 == 0xA4 || op1 == 0xA5 || op1 == 0xAC || op1 == 0xAD) return true;
        if (op1 == 0xAE || op1 == 0xC2 || op1 == 0xC4 || op1 == 0xC5 || op1 == 0xC6) return true;
        if (op1 == 0x38 || op1 == 0x3A) return true;
        return false;
    }
    if ((op0 >= 0x00 && op0 <= 0x03) || (op0 >= 0x08 && op0 <= 0x0B) ||
        (op0 >= 0x10 && op0 <= 0x13) || (op0 >= 0x18 && op0 <= 0x1B) ||
        (op0 >= 0x20 && op0 <= 0x23) || (op0 >= 0x28 && op0 <= 0x2B) ||
        (op0 >= 0x30 && op0 <= 0x33) || (op0 >= 0x38 && op0 <= 0x3B))
        return true;
    if ((op0 >= 0x80 && op0 <= 0x83) || (op0 >= 0x84 && op0 <= 0x8F))
        return true;
    if (op0 == 0xC0 || op0 == 0xC1 || op0 == 0xC6 || op0 == 0xC7)
        return true;
    if (op0 == 0xD0 || op0 == 0xD1 || op0 == 0xD2 || op0 == 0xD3)
        return true;
    if (op0 == 0xF6 || op0 == 0xF7 || op0 == 0xFE || op0 == 0xFF)
        return true;
    if (op0 == 0x69 || op0 == 0x6B) return true;
    return false;
}

static uint8_t get_imm_size(uint8_t op0, uint8_t op1, bool rex_w, bool opsz16) {
    if (op0 >= 0xB0 && op0 <= 0xB7) return 1;
    if (op0 >= 0xB8 && op0 <= 0xBF) return rex_w ? 8 : (opsz16 ? 2 : 4);
    if (op0 == 0xC7 || op0 == 0x81) return opsz16 ? 2 : 4;
    if (op0 == 0x83 || op0 == 0xC0 || op0 == 0xC1) return 1;
    if (op0 == 0xC6) return 1;
    if (op0 == 0xE8 || op0 == 0xE9) return 4;
    if (op0 == 0xEB) return 1;
    if (op0 == 0xC2 || op0 == 0xCA) return 2;
    if (op0 >= 0x70 && op0 <= 0x7F) return 1;
    if (op0 >= 0xE0 && op0 <= 0xE3) return 1;
    if (op0 == 0x6A) return 1;
    if (op0 == 0x68) return opsz16 ? 2 : 4;
    if (op0 == 0x69) return opsz16 ? 2 : 4;
    if (op0 == 0x6B) return 1;
    if (op0 == 0xA8) return 1;
    if (op0 == 0xA9) return opsz16 ? 2 : 4;
    if (op0 == 0x04 || op0 == 0x0C || op0 == 0x14 || op0 == 0x1C ||
        op0 == 0x24 || op0 == 0x2C || op0 == 0x34 || op0 == 0x3C) return 1;
    if (op0 == 0x05 || op0 == 0x0D || op0 == 0x15 || op0 == 0x1D ||
        op0 == 0x25 || op0 == 0x2D || op0 == 0x35 || op0 == 0x3D) return opsz16 ? 2 : 4;
    if (op0 == 0x0F) {
        if (op1 >= 0x80 && op1 <= 0x8F) return 4;
        if (op1 == 0xBA) return 1;
        if (op1 == 0xC2 || op1 == 0xC4 || op1 == 0xC5 || op1 == 0xC6) return 1;
        if (op1 == 0x3A) return 1; /* 3-byte opcode imm8 */
        if (op1 == 0xA4 || op1 == 0xAC) return 1; /* SHLD/SHRD imm8 */
    }
    return 0;
}

extern void x86_classify(x86_inst_t *inst, uint8_t op0, uint8_t op1, bool rex_w);

/* main decoder */

bool x86_decode(const uint8_t *code, size_t max_len, x86_inst_t *out) {
    memset(out, 0, sizeof(*out));
    out->reg = X86_REG_NONE;
    out->rm = X86_REG_NONE;
    out->index = X86_REG_NONE;
    out->addr_mode = X86_ADDR_NONE;

    if (!code || max_len == 0) return false;

    const uint8_t *p = code;
    const uint8_t *end = code + (max_len > 15 ? 15 : max_len);
    bool opsz16 = false, rex_w = false, rex_r = false, rex_x = false, rex_b = false;

    /* Prefixes */
    while (p < end && out->prefix_count < 4) {
        uint8_t b = *p;
        if ((b & 0xF0) == 0x40) { /* REX */
            out->rex = b;
            rex_w = (b >> 3) & 1; rex_r = (b >> 2) & 1;
            rex_x = (b >> 1) & 1; rex_b = b & 1;
            p++; continue;
        }
        if (!is_prefix(b)) break;
        if (b == 0x66) opsz16 = true;
        if (b == 0xF0) out->has_lock = true;
        if (b == 0xF2 || b == 0xF3) out->has_rep = true;
        p++; out->prefix_count++;
    }
    if (!have(p, end, 1)) return false;

    /* Skip VEX/EVEX - mark as SIMD */
    if (*p == 0xC4 || *p == 0xC5 || *p == 0x62) {
        out->is_simd = true;
        /* Consume rest as opaque */
        out->len = (uint8_t)(end - code);
        if (out->len > 15) out->len = 15;
        memcpy(out->raw, code, out->len);
        out->op = X86_OP_SIMD;
        out->valid = true;
        return true;
    }

    /* Opcode */
    out->opcode[0] = *p++;
    out->opcode_len = 1;
    if (out->opcode[0] == 0x0F) {
        if (!have(p, end, 1)) return false;
        out->opcode[1] = *p++;
        out->opcode_len = 2;
        if (out->opcode[1] == 0x38 || out->opcode[1] == 0x3A) {
            if (!have(p, end, 1)) return false;
            out->opcode[2] = *p++;
            out->opcode_len = 3;
        }
    }

    uint8_t op0 = out->opcode[0], op1 = out->opcode[1];
    out->is_64bit = rex_w;

    /* ModR/M */
    if (needs_modrm(op0, op1)) {
        if (!have(p, end, 1)) return false;
        out->has_modrm = true;
        out->modrm = *p++;
        uint8_t mod = x86_modrm_mod(out->modrm);
        uint8_t reg3 = x86_modrm_reg(out->modrm);
        uint8_t rm3 = x86_modrm_rm(out->modrm);

        out->reg = reg3 | (rex_r ? 8 : 0);
        uint8_t base_reg = rm3 | (rex_b ? 8 : 0);

        if (mod == 3) {
            out->addr_mode = X86_ADDR_REG;
            out->rm = base_reg;
        } else {
            out->addr_mode = X86_ADDR_MEM;
            /* SIB */
            if (rm3 == 4) {
                if (!have(p, end, 1)) return false;
                out->has_sib = true;
                out->sib = *p++;
                uint8_t sb = x86_sib_base(out->sib) | (rex_b ? 8 : 0);
                uint8_t si = x86_sib_index(out->sib) | (rex_x ? 8 : 0);
                out->scale = x86_sib_scale(out->sib);
                out->rm = sb;
                out->index = (si == 4) ? X86_REG_NONE : si; /* index=RSP means no index */
                if (x86_sib_base(out->sib) == 5 && mod == 0) {
                    out->rm = X86_REG_NONE; /* disp32 only */
                    out->disp_size = 4;
                }
            } else if (mod == 0 && rm3 == 5) {
                out->addr_mode = X86_ADDR_RIP;
                out->rip_relative = true;
                out->rm = X86_REG_NONE;
                out->disp_size = 4;
            } else {
                out->rm = base_reg;
            }
            /* Displacement */
            if (mod == 1) out->disp_size = 1;
            else if (mod == 2) out->disp_size = 4;
            if (out->disp_size) {
                if (!have(p, end, out->disp_size)) return false;
                out->disp = read_se(p, out->disp_size);
                p += out->disp_size;
            }
        }
    }

    /* Immediate */
    uint8_t isz = get_imm_size(op0, op1, rex_w, opsz16);
    if (isz) {
        if (!have(p, end, isz)) return false;
        out->has_imm = true;
        out->imm_size = isz;
        out->imm = (isz <= 4) ? read_se(p, isz) : (int64_t)read_le(p, isz);
        p += isz;
    }

    out->len = (uint8_t)(p - code);
    if (out->len > 15 || out->len == 0) return false;
    memcpy(out->raw, code, out->len);
    out->valid = true;

    /* Classify operation + register tracking */
    x86_classify(out, op0, op1, rex_w);
    return true;
}
