/*
+ * File:        decoder_x86.c
+ *   x86_64 instruction decoder implementation. Parses instruction
+ *   prefixes, REX/VEX/EVEX, opcode bytes, ModR/M, SIB, displacements,
+ *   immediates, and control-flow targets.
+ *
+ * Capabilities:
+ *   – Prefix detection (is_prefix)
+ *   – REX/VEX/EVEX parsing (parse_rex, parse_vex, parse_evex)
+ *   – ModR/M & SIB handling with displacement (modrm_*, sib_*)
+ *   – Immediate and displacement reads (read_imm, read_disp)
+ *   – Opcode and length extraction (decode_x86)
+ *   – Control-flow target resolution (res_tar)
+ *
+ * Dependencies:
+ *   <decoder.h> – x86_instruction_t, mem_read_fn
+ *
+ * Usage:
+ *   Call `decode_x86(code, ip, &inst, mem_read)` to fill out
+ *   `inst` (len, raw bytes, flags, target, etc.). Returns false
+ *   if decoding fails or instruction is invalid.
+ *
+ * Notes:
+ *   – Maximum instruction length enforced (15 bytes).
+ *   – Control-flow target only computed for CALL/JMP and FF /2,3.
+ */
    #include <decoder.h>

#if defined(ARCH_X86)
static bool is_prefix(uint8_t b) {
    return (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            (b >= 0x2E && b <= 0x3E && (b & 0xF7) == 0x26) ||
            b == 0x66 || b == 0x67);
}

static void parse_rex(x86_instruction_t *inst, uint8_t rex) {
    inst->rex = rex;
    inst->rex_w = rex & 8;
}

// Mhmm, Not SURE ABOUT THIS ONE !

static uint8_t modrm_mod(uint8_t m) { return (m >> 6) & 3; }
static uint8_t modrm_reg(uint8_t m) { return (m >> 3) & 7; }
static uint8_t modrm_rm (uint8_t m) { return m & 7; }
static uint8_t sib_scale(uint8_t s) { return (s >> 6) & 3; }
static uint8_t sib_index(uint8_t s) { return (s >> 3) & 7; }
static uint8_t sib_base (uint8_t s) { return s & 7; }

static uint64_t read_imm(const uint8_t *p, uint8_t size) {
    uint64_t v = 0;
    for (uint8_t i = 0; i < size; i++) v |= ((uint64_t)p[i]) << (i * 8);
    return v;
}

static int64_t read_disp(const uint8_t *p, uint8_t size) {
    int64_t v = (int8_t)p[0];
    if (size == 4) v = *(int32_t *)p;
    return v;
}

static bool parse_vex(x86_instruction_t *inst, const uint8_t **p) {
    if ((*p)[0] == 0xC5) {
        *p += 2;
        inst->vex = true;
        return true;
    }
    if ((*p)[0] == 0xC4) {
        *p += 3;
        inst->vex = true;
        return true;
    }
    return false;
}

static bool parse_evex(x86_instruction_t *inst, const uint8_t **p) {
    *p += 4;
    inst->evex = true;
    return true;
}

static void res_tar(x86_instruction_t *inst, uintptr_t ip, mem_read_fn mem_read) {
    if (!inst->valid) return;
    if (inst->opcode[0] == 0xE8 || inst->opcode[0] == 0xE9) {
        inst->modifies_ip = true;
        inst->target = ip + inst->len + (int32_t)inst->imm;
    }
    if (inst->opcode[0] == 0xFF && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        uint8_t mod = modrm_mod(inst->modrm);
        if (reg == 2 || reg == 3) {
            inst->modifies_ip = true;
            if (mod != 3) {
                uintptr_t addr = 0;
                if (inst->has_sib) {
                    uint8_t base = sib_base(inst->sib);
                    addr = inst->disp;
                } else {
                    addr = inst->disp;
                }
                inst->target = 0;
                for (int i = 7; i >= 0; i--)
                    inst->target = (inst->target << 8) | mem_read(addr + i);
            }
        }
    }
}

bool decode_x86(const uint8_t *code, uintptr_t ip, x86_instruction_t *inst, mem_read_fn mem_read) {
    memset(inst, 0, sizeof(*inst));
    inst->valid = true;
    const uint8_t *p = code;
    uint8_t rex = 0;

    while (is_prefix(*p)) {
        if ((*p & 0xF0) == 0x40) rex = *p;
        p++;
        if (p - code >= 15) return false;
    }

    if (rex) parse_rex(inst, rex);

    if (p[0] == 0x62) { if (!parse_evex(inst, &p)) return false; }
    else if (p[0] == 0xC4 || p[0] == 0xC5) { if (!parse_vex(inst, &p)) return false; }

    inst->opcode[0] = *p++;
    inst->opcode_len = 1;

    if (inst->opcode[0] == 0x0F) {
        inst->opcode[1] = *p++;
        inst->opcode_len++;
        if (inst->opcode[1] == 0x38 || inst->opcode[1] == 0x3A) {
            inst->opcode[2] = *p++;
            inst->opcode_len++;
        }
    }

    if ((inst->opcode[0] >= 0x88 && inst->opcode[0] <= 0x8B) ||
        inst->opcode[0] == 0xFF || inst->opcode[0] == 0x01 ||
        inst->opcode[0] == 0x03 || inst->opcode[0] == 0x29 ||
        inst->opcode[0] == 0x2B) {
        inst->has_modrm = true;
        inst->modrm = *p++;
        if (modrm_mod(inst->modrm) != 3 && modrm_rm(inst->modrm) == 4) {
            inst->has_sib = true;
            inst->sib = *p++;
        }
        if (modrm_mod(inst->modrm) == 1) {
            inst->disp_size = 1;
            inst->disp = read_disp(p, 1);
            p += 1;
        } else if (modrm_mod(inst->modrm) == 2) {
            inst->disp_size = 4;
            inst->disp = read_disp(p, 4);
            p += 4;
        }
    }

    if ((inst->opcode[0] >= 0xB8 && inst->opcode[0] <= 0xBF) ||
        inst->opcode[0] == 0xC7 || inst->opcode[0] == 0xE8 ||
        inst->opcode[0] == 0xE9) {
        if (inst->opcode[0] >= 0xB8 && inst->opcode[0] <= 0xBF) {
            inst->imm_size = inst->rex_w ? 8 : 4;
        } else {
            inst->imm_size = 4;
        }
        inst->imm = read_imm(p, inst->imm_size);
        p += inst->imm_size;
    }

    inst->len = p - code;
    memcpy(inst->raw, code, inst->len > 15 ? 15 : inst->len);

    res_tar(inst, ip, mem_read);
    return inst->valid;
}

#endif // ARCH_X86
