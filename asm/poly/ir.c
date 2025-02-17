#include "ir.h"
#include "arm64.h"
#include <string.h>

/* lift ARM64 -> IR */

bool ir_lift(const uint8_t *code, ir_inst_t *out) {
    arm64_inst_t a;
    memset(out, 0, sizeof(*out));
    if (!arm64_decode(code, &a) || !a.valid) {
        memcpy(&out->raw, code, 4);
        out->op = IR_RAW;
        return false;
    }
    out->raw = a.raw;
    out->is_64bit = a.is_64bit;
    out->sets_flags = a.sets_flags;
    out->dst = a.rd;
    out->src1 = a.rn;
    out->src2 = 0xFF;
    out->imm = a.imm;

    switch (a.op) {
    case ARM_OP_ADD: case ARM_OP_ADDS:
        out->op = IR_ADD;
        if (a.num_regs_read >= 2) {
            if (a.shift_amount != 0) { out->op = IR_RAW; return false; }
            out->src2 = a.rm;
        }
        return true;
    case ARM_OP_SUB: case ARM_OP_SUBS:
        out->op = IR_SUB;
        if (a.num_regs_read >= 2) {
            if (a.shift_amount != 0) { out->op = IR_RAW; return false; }
            out->src2 = a.rm;
        }
        return true;
    case ARM_OP_AND: case ARM_OP_ANDS:
        if (a.shift_amount != 0) { out->op = IR_RAW; return false; }
        out->op = IR_AND; out->src2 = a.rm; return true;
    case ARM_OP_ORR:
        if (a.shift_amount != 0) { out->op = IR_RAW; return false; }
        out->op = IR_ORR; out->src2 = a.rm; return true;
    case ARM_OP_EOR:
        if (a.shift_amount != 0) { out->op = IR_RAW; return false; }
        out->op = IR_EOR; out->src2 = a.rm; return true;
    case ARM_OP_MOV_REG:
        out->op = IR_MOV; out->src1 = a.rm; return true;
    case ARM_OP_MOV_IMM:
        out->op = IR_MOV; out->src1 = 0xFF; return true;
    case ARM_OP_LSL:
        out->op = IR_LSL; return true;
    case ARM_OP_LSR:
        out->op = IR_LSR; return true;
    case ARM_OP_ASR:
        out->op = IR_ASR; return true;
    case ARM_OP_MUL:
        out->op = IR_MUL; out->src2 = a.rm; return true;
    case ARM_OP_NEG:
        out->op = IR_NEG; return true;
    case ARM_OP_MVN:
        out->op = IR_NOT; return true;
    case ARM_OP_CMP:
        out->op = IR_CMP; out->dst = 0xFF;
        if (a.num_regs_read >= 2) out->src2 = a.rm;
        return true;
    case ARM_OP_CMN:
        /* CMN sets flags from addition, not subtraction */
        out->op = IR_RAW; return false;
    case ARM_OP_NOP:
        out->op = IR_NOP; return true;
    default:
        /* Control flow, loads, stores, system */
        if (a.is_control_flow) { out->op = IR_BR; return false; }
        if (a.addr_mode) {
            out->op = (a.op >= ARM_OP_STR && a.op <= ARM_OP_STRH) ? IR_STORE : IR_LOAD;
            return false; /* keep as RAW for now */
        }
        out->op = IR_RAW;
        return false;
    }
}

/* Transforms */

/* Simple PRNG for transform decisions */
static uint32_t xor_next(uint32_t *s) {
    *s ^= *s << 13; *s ^= *s >> 17; *s ^= *s << 5; return *s;
}

int ir_transform(ir_inst_t *ir, int n, uint32_t seed) {
    int count = 0;
    uint32_t rng = seed ? seed : 0xDEADBEEF;

    for (int i = 0; i < n; i++) {
        ir_inst_t *p = &ir[i];
        if (p->op == IR_RAW || p->op == IR_BR || p->op == IR_NOP) continue;

        /* Identity elimination */
        /* ADD Xd, Xn, #0 -> MOV Xd, Xn */
        if (p->op == IR_ADD && p->src2 == 0xFF && p->imm == 0 && !p->sets_flags) {
            p->op = IR_MOV; p->src1 = p->src1; count++;
            continue;
        }
        /* SUB Xd, Xn, #0 -> MOV Xd, Xn */
        if (p->op == IR_SUB && p->src2 == 0xFF && p->imm == 0 && !p->sets_flags) {
            p->op = IR_MOV; count++;
            continue;
        }
        /* EOR Xd, Xn, XZR -> MOV Xd, Xn */
        if (p->op == IR_EOR && p->src2 == 31) {
            p->op = IR_MOV; p->src2 = 0xFF; count++;
            continue;
        }
        /* ORR Xd, XZR, Xn -> MOV Xd, Xn */
        if (p->op == IR_ORR && p->src1 == 31) {
            p->op = IR_MOV; p->src1 = p->src2; p->src2 = 0xFF; count++;
            continue;
        }
        /* AND Xd, Xn, Xn -> MOV Xd, Xn */
        if (p->op == IR_AND && p->src1 == p->src2) {
            p->op = IR_MOV; p->src2 = 0xFF; count++;
            continue;
        }
        /* ORR Xd, Xn, Xn -> MOV Xd, Xn */
        if (p->op == IR_ORR && p->src1 == p->src2) {
            p->op = IR_MOV; p->src2 = 0xFF; count++;
            continue;
        }
        /* LSL/LSR/ASR by 0 -> MOV */
        if ((p->op == IR_LSL || p->op == IR_LSR || p->op == IR_ASR) && p->imm == 0) {
            p->op = IR_MOV; count++;
            continue;
        }

        /* LSL Xd, Xn, #1 ↔ ADD Xd, Xn, Xn (randomly swap) */
        if (p->op == IR_LSL && p->imm == 1 && !p->sets_flags && (xor_next(&rng) & 1)) {
            p->op = IR_ADD; p->src2 = p->src1; p->imm = 0; count++;
            continue;
        }
        if (p->op == IR_ADD && p->src2 != 0xFF && p->src1 == p->src2 &&
            !p->sets_flags && (xor_next(&rng) & 1)) {
            p->op = IR_LSL; p->src2 = 0xFF; p->imm = 1; count++;
            continue;
        }

        /* Commutativity */
        /* ADD Xd, Xn, Xm -> ADD Xd, Xm, Xn */
        if ((p->op == IR_ADD || p->op == IR_AND || p->op == IR_ORR ||
             p->op == IR_EOR || p->op == IR_MUL) &&
            p->src2 != 0xFF && p->src1 != p->src2 && (xor_next(&rng) & 1)) {
            uint8_t tmp = p->src1; p->src1 = p->src2; p->src2 = tmp;
            count++;
        }

        if (i + 1 < n && p->op == IR_MOV && ir[i+1].op == IR_MOV &&
            p->dst == ir[i+1].src1 && p->src1 == ir[i+1].dst &&
            p->src1 != 0xFF && ir[i+1].src1 != 0xFF) {
            ir[i+1].op = IR_NOP; count++;
        }
    }
    return count;
}

/* Lower */

static uint32_t enc_add_imm_ir(uint8_t d, uint8_t n, uint16_t imm, bool sf) {
    return ((uint32_t)sf << 31) | 0x11000000u | ((uint32_t)(imm & 0xFFF) << 10) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_sub_imm_ir(uint8_t d, uint8_t n, uint16_t imm, bool sf) {
    return ((uint32_t)sf << 31) | 0x51000000u | ((uint32_t)(imm & 0xFFF) << 10) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_orr_reg_ir(uint8_t d, uint8_t n, uint8_t m, bool sf) {
    return ((uint32_t)sf << 31) | 0x2A000000u | ((uint32_t)m << 16) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_add_reg_ir(uint8_t d, uint8_t n, uint8_t m, bool sf) {
    return ((uint32_t)sf << 31) | 0x0B000000u | ((uint32_t)m << 16) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_sub_reg_ir(uint8_t d, uint8_t n, uint8_t m, bool sf) {
    return ((uint32_t)sf << 31) | 0x4B000000u | ((uint32_t)m << 16) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_and_reg_ir(uint8_t d, uint8_t n, uint8_t m, bool sf) {
    return ((uint32_t)sf << 31) | 0x0A000000u | ((uint32_t)m << 16) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_eor_reg_ir(uint8_t d, uint8_t n, uint8_t m, bool sf) {
    return ((uint32_t)sf << 31) | 0x4A000000u | ((uint32_t)m << 16) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_lsl_imm_ir(uint8_t d, uint8_t n, uint8_t amt, bool sf) {
    uint8_t bits = sf ? 63 : 31;
    uint8_t immr = (bits - amt + 1) & bits;
    uint8_t imms = bits - amt;
    return ((uint32_t)sf << 31) | 0x53000000u | ((uint32_t)sf << 22) |
           ((uint32_t)immr << 16) | ((uint32_t)imms << 10) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_lsr_imm_ir(uint8_t d, uint8_t n, uint8_t amt, bool sf) {
    uint8_t imms = sf ? 63 : 31;
    return ((uint32_t)sf << 31) | 0x53000000u | ((uint32_t)sf << 22) |
           ((uint32_t)amt << 16) | ((uint32_t)imms << 10) |
           ((uint32_t)n << 5) | d;
}
static uint32_t enc_mul_ir(uint8_t d, uint8_t n, uint8_t m, bool sf) {
    return ((uint32_t)sf << 31) | 0x1B000000u | ((uint32_t)m << 16) |
           (31u << 10) | ((uint32_t)n << 5) | d;
}

int ir_lower(const ir_inst_t *ir, uint32_t *out) {
    switch (ir->op) {
    case IR_NOP:
        out[0] = 0xD503201F; return 1;
    case IR_RAW: case IR_BR: case IR_LOAD: case IR_STORE:
        out[0] = ir->raw; return 1;
    case IR_MOV:
        if (ir->src1 == 0xFF) {
            out[0] = ir->raw; return 1;
        }
        out[0] = enc_orr_reg_ir(ir->dst, 31, ir->src1, ir->is_64bit);
        return 1;
    case IR_ADD:
        if (ir->src2 != 0xFF)
            out[0] = enc_add_reg_ir(ir->dst, ir->src1, ir->src2, ir->is_64bit);
        else
            out[0] = enc_add_imm_ir(ir->dst, ir->src1, (uint16_t)(ir->imm & 0xFFF), ir->is_64bit);
        if (ir->sets_flags) out[0] |= 0x20000000u; /* S bit */
        return 1;
    case IR_SUB:
        if (ir->src2 != 0xFF)
            out[0] = enc_sub_reg_ir(ir->dst, ir->src1, ir->src2, ir->is_64bit);
        else
            out[0] = enc_sub_imm_ir(ir->dst, ir->src1, (uint16_t)(ir->imm & 0xFFF), ir->is_64bit);
        if (ir->sets_flags) out[0] |= 0x20000000u;
        return 1;
    case IR_AND:
        out[0] = enc_and_reg_ir(ir->dst, ir->src1, ir->src2, ir->is_64bit);
        if (ir->sets_flags) out[0] |= 0x20000000u;
        return 1;
    case IR_ORR:
        out[0] = enc_orr_reg_ir(ir->dst, ir->src1, ir->src2, ir->is_64bit);
        return 1;
    case IR_EOR:
        out[0] = enc_eor_reg_ir(ir->dst, ir->src1, ir->src2, ir->is_64bit);
        return 1;
    case IR_LSL:
        out[0] = enc_lsl_imm_ir(ir->dst, ir->src1, (uint8_t)ir->imm, ir->is_64bit);
        return 1;
    case IR_LSR:
        out[0] = enc_lsr_imm_ir(ir->dst, ir->src1, (uint8_t)ir->imm, ir->is_64bit);
        return 1;
    case IR_ASR:
        out[0] = ir->raw; return 1; /* complex encoding, pass through */
    case IR_MUL:
        out[0] = enc_mul_ir(ir->dst, ir->src1, ir->src2, ir->is_64bit);
        return 1;
    case IR_NEG: case IR_NOT:
        out[0] = ir->raw; return 1;
    case IR_CMP:
        if (ir->src2 != 0xFF) {
            /* CMP Xn, Xm = SUBS XZR, Xn, Xm */
            out[0] = enc_sub_reg_ir(31, ir->src1, ir->src2, ir->is_64bit) | 0x20000000u;
        } else {
            out[0] = enc_sub_imm_ir(31, ir->src1, (uint16_t)(ir->imm & 0xFFF), ir->is_64bit) | 0x20000000u;
        }
        return 1;
    }
    out[0] = ir->raw;
    return 1;
}
