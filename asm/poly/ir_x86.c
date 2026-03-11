#include "ir.h"
#include "x86.h"
#include <string.h>

/* lift x86 -> IR */

bool ir_lift_x86(const x86_inst_t *inst, ir_inst_t *out) {
    memset(out, 0, sizeof(*out));
    memcpy(out->raw_bytes, inst->raw, inst->len);
    out->raw_len = inst->len;
    out->is_64bit = inst->is_64bit;
    out->sets_flags = inst->sets_flags;
    out->dst = inst->reg < 16 ? inst->reg : 0xFF;
    out->src1 = 0xFF;
    out->src2 = 0xFF;
    out->imm = inst->imm;

    uint8_t mod = inst->has_modrm ? x86_modrm_mod(inst->modrm) : 0;

    /* Only lift reg-reg and reg-imm ALU ops */
    if (inst->is_control_flow || inst->is_simd || inst->is_privileged) {
        out->op = IR_RAW; return false;
    }
    if (inst->addr_mode == X86_ADDR_MEM || inst->addr_mode == X86_ADDR_RIP) {
        out->op = IR_RAW; return false;
    }

    switch (inst->op) {
    case X86_OP_ADD:
        out->op = IR_ADD;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        if (inst->has_imm) out->src2 = 0xFF;
        else if (mod == 3) out->src2 = inst->reg;
        return true;
    case X86_OP_SUB:
        out->op = IR_SUB;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        if (inst->has_imm) out->src2 = 0xFF;
        else if (mod == 3) out->src2 = inst->reg;
        return true;
    case X86_OP_AND:
        out->op = IR_AND;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; out->src2 = inst->reg; }
        return true;
    case X86_OP_OR:
        out->op = IR_ORR;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; out->src2 = inst->reg; }
        return true;
    case X86_OP_XOR:
        out->op = IR_EOR;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; out->src2 = inst->reg; }
        return true;
    case X86_OP_MOV:
        out->op = IR_MOV;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->reg; }
        else if (inst->has_imm) { out->src1 = 0xFF; } /* mov reg, imm */
        return true;
    case X86_OP_CMP:
        out->op = IR_CMP; out->dst = 0xFF;
        if (mod == 3) { out->src1 = inst->rm; out->src2 = inst->reg; }
        return true;
    case X86_OP_TEST:
        out->op = IR_AND; out->dst = 0xFF; /* TEST = AND without write */
        if (mod == 3) { out->src1 = inst->rm; out->src2 = inst->reg; }
        return true;
    case X86_OP_SHL:
        out->op = IR_LSL;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        return true;
    case X86_OP_SHR:
        out->op = IR_LSR;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        return true;
    case X86_OP_SAR:
        out->op = IR_ASR;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        return true;
    case X86_OP_NEG:
        out->op = IR_NEG;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        return true;
    case X86_OP_NOT:
        out->op = IR_NOT;
        if (mod == 3) { out->dst = inst->rm; out->src1 = inst->rm; }
        return true;
    case X86_OP_NOP:
        out->op = IR_NOP; return true;
    default:
        out->op = IR_RAW; return false;
    }
}

int ir_lower_x86(const ir_inst_t *ir, uint8_t *out) {
    /* For RAW/BR/LOAD/STORE/NOP */
    if (ir->op == IR_RAW || ir->op == IR_BR || ir->op == IR_LOAD || ir->op == IR_STORE) {
        memcpy(out, ir->raw_bytes, ir->raw_len);
        return ir->raw_len;
    }
    if (ir->op == IR_NOP) {
        out[0] = 0x90;
        return 1;
    }

    /* The transforms, change the IR op but the lowerin' just emits the original bytes
     * unless we can encode the new form. */
    memcpy(out, ir->raw_bytes, ir->raw_len);
    return ir->raw_len;
}
