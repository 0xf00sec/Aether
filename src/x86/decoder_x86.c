#include <wisp.h>

/*-------------------------------------------
/// Main decoder 
-------------------------------------------*/

#if defined(ARCH_X86)

static bool is_prefix(uint8_t b) {
    return (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            (b >= 0x2E && b <= 0x3E && (b & 0xF7) == 0x26) ||
            b == 0x66 || b == 0x67);
}

static void parse_rex(x86_inst_t *inst, uint8_t rex) {
    inst->rex = rex;
    inst->rex_w = rex & 8;
    inst->rex_r = rex & 4;
    inst->rex_x = rex & 2;
    inst->rex_b = rex & 1;
}

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

static bool parse_vex(x86_inst_t *inst, const uint8_t **p) {
    if ((*p)[0] == 0xC5) { *p += 2; inst->vex = true; return true; }
    if ((*p)[0] == 0xC4) { *p += 3; inst->vex = true; return true; }
    return false;
}

static bool parse_evex(x86_inst_t *inst, const uint8_t **p) {
    *p += 4; inst->evex = true; return true;
}

static bool is_control_flow_instruction(uint8_t opcode, uint8_t opcode2) {
    if (opcode == 0xE8 || opcode == 0xE9 || opcode == 0xC3 || opcode == 0xC2) return true;
    if (opcode >= 0x70 && opcode <= 0x7F) return true;
    if (opcode == 0x0F && opcode2 >= 0x80 && opcode2 <= 0x8F) return true;
    if (opcode == 0xFF) return true;
    return false;
}

static bool needs_modrm(uint8_t opcode, uint8_t opcode2) {
    if (opcode >= 0x88 && opcode <= 0x8B) return true;
    if (opcode == 0x01 || opcode == 0x03 || opcode == 0x29 || opcode == 0x2B) return true;
    if (opcode == 0x31 || opcode == 0x33 || opcode == 0x21 || opcode == 0x23 ||
        opcode == 0x09 || opcode == 0x0B) return true;
    if (opcode == 0x85 || opcode == 0x87 || opcode == 0x39 || opcode == 0x3B) return true;
    if (opcode == 0x81 || opcode == 0x83) return true;
    if (opcode == 0x8D) return true;
    if (opcode == 0x87) return true;
    if (opcode == 0xFF) return true;
    return false;
}

static bool needs_immediate(uint8_t opcode, uint8_t opcode2) {
    if (opcode >= 0xB8 && opcode <= 0xBF) return true;
    if (opcode == 0xC7) return true;
    if (opcode == 0xE8 || opcode == 0xE9) return true;
    if (opcode == 0x81 || opcode == 0x83) return true;
    if (opcode == 0xC2) return true;
    return false;
}

static uint8_t get_immediate_size(uint8_t opcode, bool rex_w) {
    if (opcode >= 0xB8 && opcode <= 0xBF) return rex_w ? 8 : 4;
    if (opcode == 0xC7 || opcode == 0xE8 || opcode == 0xE9 || opcode == 0x81) return 4;
    if (opcode == 0x83) return 1;
    if (opcode == 0xC2) return 2;
    return 0;
}

static void res_tar(x86_inst_t *inst, uintptr_t ip, memread_fn mem_read) {
    if (!inst->valid) return;
    if (inst->opcode[0] == 0xE8 || inst->opcode[0] == 0xE9)
        { inst->modifies_ip = true; inst->target = ip + inst->len + (int32_t)inst->imm; }
    if (inst->opcode[0] >= 0x70 && inst->opcode[0] <= 0x7F)
        { inst->modifies_ip = true; inst->target = ip + inst->len + (int8_t)inst->opcode[1]; }
    if (inst->opcode[0] == 0x0F && inst->opcode[1] >= 0x80 && inst->opcode[1] <= 0x8F)
        { inst->modifies_ip = true; inst->target = ip + inst->len + (int32_t)inst->imm; }
    if (inst->opcode[0] == 0xFF && inst->has_modrm) {
        uint8_t reg = modrm_reg(inst->modrm);
        if (reg == 2 || reg == 3) { inst->modifies_ip = true; inst->target = 0; }
    }
}

bool decode_x86_withme(const uint8_t *code, size_t size, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read) {
    memset(inst, 0, sizeof(*inst));
    inst->valid = true;
    const uint8_t *p = code;
    const uint8_t *end = code + size;
    uint8_t rex = 0;

    while (p < end && is_prefix(*p)) {
        if ((*p & 0xF0) == 0x40) rex = *p;
        p++;
        if (p - code >= 15) return false;
    }
    if (p >= end) return false;
    if (rex) parse_rex(inst, rex);
    if (p < end && p[0] == 0x62) {
        if (p + 4 > end) return false;
        p += 4; inst->evex = true;
    } else if (p < end && (p[0] == 0xC4 || p[0] == 0xC5)) {
        if (p[0] == 0xC5) { if (p + 2 > end) return false; p += 2; inst->vex = true; }
        else { if (p + 3 > end) return false; p += 3; inst->vex = true; }
    }
    if (p >= end) return false;
    inst->opcode[0] = *p++;
    inst->opcode_len = 1;
    if (inst->opcode[0] == 0x0F) {
        if (p >= end) return false;
        inst->opcode[1] = *p++;
        inst->opcode_len++;
        if (inst->opcode[1] == 0x38 || inst->opcode[1] == 0x3A) {
            if (p >= end) return false;
            inst->opcode[2] = *p++;
            inst->opcode_len++;
        }
    }
    if (needs_modrm(inst->opcode[0], inst->opcode[1])) {
        if (p >= end) return false;
        inst->has_modrm = true;
        inst->modrm = *p++;
        if (modrm_mod(inst->modrm) != 3 && modrm_rm(inst->modrm) == 4) {
            if (p >= end) return false;
            inst->has_sib = true;
            inst->sib = *p++;
        }
        if (modrm_mod(inst->modrm) == 1) {
            if (p >= end) return false;
            inst->disp_size = 1;
            inst->disp = read_disp(p, 1);
            p += 1;
        } else if (modrm_mod(inst->modrm) == 2) {
            if (p + 4 > end) return false;
            inst->disp_size = 4;
            inst->disp = read_disp(p, 4);
            p += 4;
        }
    }
    if (needs_immediate(inst->opcode[0], inst->opcode[1])) {
        inst->imm_size = get_immediate_size(inst->opcode[0], inst->rex_w);
        if (inst->imm_size > 0) {
            if (p + inst->imm_size > end) return false;
            inst->imm = read_imm(p, inst->imm_size);
            p += inst->imm_size;
        }
    }
    inst->len = p - code;
    if (inst->len > 15) inst->len = 15;
    memcpy(inst->raw, code, inst->len);
    inst->is_control_flow = is_control_flow_instruction(inst->opcode[0], inst->opcode[1]);
    res_tar(inst, ip, mem_read);
    return inst->valid;
}

bool decode_x86(const uint8_t *code, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read) {
    return decode_x86_withme(code, 0, ip, inst, mem_read);
}

#endif // ARCH_X86
