#include <wisp.h>

/*-------------------------------------------
/// Not main decoder
-------------------------------------------*/

#if defined(ARCH_ARM)
static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static bool is_control_flow_instruction(uint32_t insn) {
    uint32_t op = (insn >> 26) & 0x3F;
    if (op == 0b000101 || op == 0b100101) return true; // B, BL
    if ((insn & 0xFF000010) == 0x54000000) return true; // B.cond
    return false;
}

static bool is_privileged_instruction(uint32_t insn) {
    return ((insn & 0xFFC00000) == 0xD5000000); // MSR/MRS/SYS
}

static arm_reg_t parse_rd(uint32_t insn) { return (arm_reg_t)(insn & 0x1F); }
static arm_reg_t parse_rn(uint32_t insn) { return (arm_reg_t)((insn >> 5) & 0x1F); }
static arm_reg_t parse_rm(uint32_t insn) { return (arm_reg_t)((insn >> 16) & 0x1F); }
static arm_reg_t parse_ra(uint32_t insn) { return (arm_reg_t)((insn >> 10) & 0x1F); }
static uint64_t parse_imm12(uint32_t insn) { return (insn >> 10) & 0xFFF; }
static uint64_t parse_imm16(uint32_t insn) { return (insn >> 5) & 0xFFFF; }
static uint64_t parse_imm19(uint32_t insn) { return (insn >> 5) & 0x7FFFF; }
static uint64_t parse_imm26(uint32_t insn) { return insn & 0x3FFFFFF; }
static uint8_t parse_shift_type(uint32_t insn) { return (insn >> 22) & 0x3; }
static uint8_t parse_shift_amount(uint32_t insn) { return (insn >> 10) & 0x3F; }

//  Main decode
bool decode_arm64(const uint8_t *code, arm64_inst_t *out) {
    memset(out, 0, sizeof(*out));
    uint32_t insn = read_u32(code);
    out->raw = insn;
    out->opcode = (insn >> 21) & 0x7FF;
    out->opcode_len = 4;
    out->len = 4;
    out->valid = true;
    out->is_64bit = (insn >> 31) & 1;
    out->is_signed = false;
    out->is_privileged = is_privileged_instruction(insn);
    out->is_control_flow = is_control_flow_instruction(insn);
    out->modifies_ip = out->is_control_flow;
    out->privileged = out->is_privileged;
    out->type = ARM_OP_NONE;
    // Decode op type     if ((insn & 0x7C000000) == 0x14000000) {
        out->type = ((insn >> 31) & 1) ? ARM_OP_BRANCH_LINK : ARM_OP_BRANCH;
        out->imm = (int64_t)((int32_t)((parse_imm26(insn) << 6) >> 6)) << 2;
        out->rd = ARM_REG_PC;
        out->is_control_flow = true;
        out->modifies_ip = true;
        out->target = out->imm;
        return true;
    }
    if ((insn & 0xFF000010) == 0x54000000) {
        out->type = ARM_OP_BRANCH_COND;
        out->imm = (int64_t)((int32_t)((parse_imm19(insn) << 13) >> 13)) << 2;
        out->is_control_flow = true;
        out->modifies_ip = true;
        out->target = out->imm;
        return true;
    }
    if ((insn & 0x7F000000) == 0x11000000) {
        out->type = ARM_OP_ADD;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->imm = parse_imm12(insn);
        out->imm_size = 12;
        return true;
    }
    if ((insn & 0x7F000000) == 0x51000000) {
        out->type = ARM_OP_SUB;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->imm = parse_imm12(insn);
        out->imm_size = 12;
        return true;
    }
    if ((insn & 0x7F200000) == 0x0B000000) {
        out->type = ARM_OP_ADD;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->rm = parse_rm(insn);
        return true;
    }
    if ((insn & 0x7F200000) == 0x4B000000) {
        out->type = ARM_OP_SUB;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->rm = parse_rm(insn);
        return true;
    }
    if ((insn & 0x7F200000) == 0x2A000000) {
        out->type = ARM_OP_ORR;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->rm = parse_rm(insn);
        return true;
    }
    if ((insn & 0x7F200000) == 0x0A000000) {
        out->type = ARM_OP_AND;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->rm = parse_rm(insn);
        return true;
    }
    if ((insn & 0x7F200000) == 0x6A000000) {
        out->type = ARM_OP_EOR;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->rm = parse_rm(insn);
        return true;
    }
    if ((insn & 0x7F000000) == 0x91000000) {
        out->type = ARM_OP_ADD;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->imm = parse_imm12(insn);
        out->imm_size = 12;
        return true;
    }
    if ((insn & 0x7F000000) == 0xD1000000) {
        out->type = ARM_OP_SUB;
        out->rd = parse_rd(insn);
        out->rn = parse_rn(insn);
        out->imm = parse_imm12(insn);
        out->imm_size = 12;
        return true;
    }
    if ((insn & 0x7F000000) == 0xB9000000) {
        out->type = ARM_OP_STR;
        out->rn = parse_rn(insn);
        out->rd = parse_rd(insn);
        out->imm = parse_imm12(insn);
        out->imm_size = 12;
        return true;
    }
    if ((insn & 0x7F000000) == 0xB9400000) {
        out->type = ARM_OP_LDR;
        out->rn = parse_rn(insn);
        out->rd = parse_rd(insn);
        out->imm = parse_imm12(insn);
        out->imm_size = 12;
        return true;
    }
    if ((insn & 0x7F000000) == 0xAA000000) {
        out->type = ARM_OP_MOV;
        out->rd = parse_rd(insn);
        out->rm = parse_rm(insn);
        return true;
    }
    if ((insn & 0x7F000000) == 0x52800000) {
        out->type = ARM_OP_MOV;
        out->rd = parse_rd(insn);
        out->imm = parse_imm16(insn);
        out->imm_size = 16;
        return true;
    }
    if ((insn & 0x7F000000) == 0xD2800000) {
        out->type = ARM_OP_MOV;
        out->rd = parse_rd(insn);
        out->imm = parse_imm16(insn);
        out->imm_size = 16;
        return true;
    }
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
        out->type = ARM_OP_RET;
        out->rn = parse_rn(insn);
        out->is_control_flow = true;
        out->modifies_ip = true;
        return true;
    }
    if ((insn & 0xFFFFFC00) == 0xD4000000) {
        out->type = ARM_OP_SVC;
        out->imm = (insn >> 5) & 0xFFFF;
        return true;
    }
    if ((insn & 0xFFFFFC00) == 0xD4000001) {
        out->type = ARM_OP_SYS;
        out->imm = (insn >> 5) & 0xFFFF;
        return true;
    }
    if ((insn & 0xFFFFFC00) == 0xD5184000) {
        out->type = ARM_OP_MRS;
        out->rd = parse_rd(insn);
        return true;
    }
    if ((insn & 0xFFFFFC00) == 0xD5104000) {
        out->type = ARM_OP_MSR;
        out->rd = parse_rd(insn);
        return true;
    }
    out->valid = false;
    return false;
}

#endif // ARCH_ARM
