#include "xfrm.h"
#include <stdlib.h>
#include <string.h>

static uint32_t rng(mutate_ctx_t *ctx) {
    return aether_rand(ctx->rng);
}

static uint8_t pick_dead(mutate_ctx_t *ctx, regset_t dead) {
    if (!dead) return 0xFF;
    int n = __builtin_popcount(dead);
    int pick = rng(ctx) % n;
    for (int r = 0; r < 29; r++) {
        if (!(dead & REG_BIT(r))) continue;
        if (pick-- == 0) return (uint8_t)r;
    }
    return 0xFF;
}

static uint32_t enc_add_imm(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x11000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_sub_imm(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x51000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_orr_reg(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x2A000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_and_reg(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x0A000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_eor_reg(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x4A000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_mov_reg(uint8_t rd, uint8_t rm, bool sf) {
    return enc_orr_reg(rd, 31, rm, sf); /* MOV = ORR Rd, XZR, Rm */
}

static uint32_t enc_movz(uint8_t rd, uint16_t imm16, bool sf) {
    return ((uint32_t)sf << 31) | 0x52800000u | ((uint32_t)imm16 << 5) | rd;
}

static uint32_t enc_adds_imm(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x31000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_subs_imm(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x71000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_ands_reg(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x6A000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_lsl_imm(uint8_t rd, uint8_t rn, uint8_t amt, bool sf) {
    /* LSL = UBFM Rd, Rn, #(-amt mod width), #(width-1-amt) */
    uint8_t w = sf ? 64 : 32;
    uint8_t immr = (w - amt) & (w - 1);
    uint8_t imms = w - 1 - amt;
    return ((uint32_t)sf << 31) | ((uint32_t)sf << 22) | 0x53000000u |
           ((uint32_t)immr << 16) | ((uint32_t)imms << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_lsr_imm(uint8_t rd, uint8_t rn, uint8_t amt, bool sf) {
    uint8_t w = sf ? 63 : 31;
    return ((uint32_t)sf << 31) | ((uint32_t)sf << 22) | 0x53000000u |
           ((uint32_t)amt << 16) | ((uint32_t)w << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_mul(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x1B007C00u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

uint32_t gen_junk(mutate_ctx_t *ctx) {
    int i = ctx->idx;
    regset_t dead = dead_regs(ctx->live, i);

    /* Inside a loop: exclude loop-live regs */
    if (ctx->loop_body && ctx->loop_body[i]) {
        regset_t ll = loop_live_regs(ctx->insns, ctx->live, ctx->n, ctx->loop_body, i);
        dead &= ~ll;
    }

    bool fl_dead = flags_are_dead(ctx->live, i);
    uint8_t d1 = pick_dead(ctx, dead);
    if (d1 == 0xFF) return 0xD503201F; 

    /* Remove d1 from pool, pick a second */
    uint8_t d2 = pick_dead(ctx, dead & ~REG_BIT(d1));
    bool sf = rng(ctx) & 1;

    uint32_t r = rng(ctx);
    uint16_t small_imm;
    if ((r & 0xF) < 9)       small_imm = rng(ctx) & 0xFF;   
    else if ((r & 0xF) < 13) small_imm = rng(ctx) & 0x3F;   
    else                      small_imm = (rng(ctx) & 0x7) * 8; 

    /* No random MOVZ with 16-bit immediates - use small_imm for those too.
     * Real MOVZ almost always loads addresses (handled by linker) or small constants. */
    uint16_t imm16 = small_imm;
    uint8_t shift = (rng(ctx) % 3) + 1; 

    if (fl_dead && d2 != 0xFF) {
        switch (r % 12) {
        case 0:  return enc_adds_imm(d1, d2, small_imm & 0xFFF, sf);
        case 1:  return enc_subs_imm(d1, d2, small_imm & 0xFFF, sf);
        case 2:  return enc_ands_reg(d1, d1, d2, sf);
        case 3:  return enc_add_imm(d1, d2, small_imm & 0xFFF, sf);
        case 4:  return enc_sub_imm(d1, d2, small_imm & 0xFFF, sf);
        case 5:  return enc_orr_reg(d1, d1, d2, sf);
        case 6:  return enc_and_reg(d1, d1, d2, sf);
        case 7:  return enc_eor_reg(d1, d1, d2, sf);
        case 8:  return enc_movz(d1, imm16, sf);
        case 9:  return enc_mov_reg(d1, d2, sf);
        case 10: return enc_lsl_imm(d1, d2, shift, sf);
        case 11: return enc_mul(d1, d1, d2, sf);
        }
    } else if (fl_dead) {
        /* One dead reg, can clobber flags */
        switch (r % 6) {
        case 0: return enc_adds_imm(d1, d1, small_imm & 0xFFF, sf);
        case 1: return enc_subs_imm(d1, d1, small_imm & 0xFFF, sf);
        case 2: return enc_movz(d1, imm16, sf);
        case 3: return enc_lsl_imm(d1, d1, shift, sf);
        case 4: return enc_lsr_imm(d1, d1, shift, sf);
        case 5: return enc_ands_reg(d1, d1, d1, sf);
        }
    } else if (d2 != 0xFF) {
        /* Two dead regs, must preserve flags */
        switch (r % 7) {
        case 0: return enc_add_imm(d1, d2, small_imm & 0xFFF, sf);
        case 1: return enc_sub_imm(d1, d2, small_imm & 0xFFF, sf);
        case 2: return enc_orr_reg(d1, d1, d2, sf);
        case 3: return enc_and_reg(d1, d1, d2, sf);
        case 4: return enc_eor_reg(d1, d1, d2, sf);
        case 5: return enc_mov_reg(d1, d2, sf);
        case 6: return enc_movz(d1, imm16, sf);
        }
    } else {
        /* One dead reg, must preserve flags */
        switch (r % 4) {
        case 0: return enc_add_imm(d1, d1, small_imm & 0xFFF, sf);
        case 1: return enc_sub_imm(d1, d1, small_imm & 0xFFF, sf);
        case 2: return enc_movz(d1, imm16, sf);
        case 3: return enc_mov_reg(d1, d1, sf);
        }
    }
    return 0xD503201F; /* NOP fallback */
}

int gen_junk_sequence(mutate_ctx_t *ctx, uint32_t *out, int n_junk) {
    int generated = 0;
    for (int i = 0; i < n_junk; i++) {
        uint32_t w = gen_junk(ctx);
        out[generated++] = w;
        /* Vary the seed between instructions for diversity */
        rng(ctx);
    }
    return generated;
}

static void patch_reg(uint8_t *code, int idx, uint8_t old_reg, uint8_t new_reg) {
    uint32_t w;
    memcpy(&w, code + idx * 4, 4);

    /* Check all standard register positions */
    if ((w & 0x1F) == old_reg)
        w = (w & ~0x1Fu) | new_reg;                          /* Rd [4:0] */
    if (((w >> 5) & 0x1F) == old_reg)
        w = (w & ~(0x1Fu << 5)) | ((uint32_t)new_reg << 5);  /* Rn [9:5] */
    if (((w >> 16) & 0x1F) == old_reg)
        w = (w & ~(0x1Fu << 16)) | ((uint32_t)new_reg << 16);/* Rm [20:16] */

    memcpy(code + idx * 4, &w, 4);
}

int rename_reg(uint8_t *code, int n, const inst_live_t *live,
               const def_use_t *chain, uint8_t new_reg) {
    uint8_t old_reg = chain->reg;
    if (old_reg == new_reg) return 0;
    if (new_reg >= 29) return 0; /* don't rename to FP/LR/SP */

    regset_t bit = REG_BIT(new_reg);
    if (live[chain->def_idx].live_out & bit) return 0;
    for (int i = 0; i < chain->num_uses; i++) {
        int ui = chain->use_idx[i];
        if (ui >= n) return 0;
        if (live[ui].live_in & bit) return 0;
    }

    int patched = 0;
    patch_reg(code, chain->def_idx, old_reg, new_reg);
    patched++;
    for (int i = 0; i < chain->num_uses; i++) {
        patch_reg(code, chain->use_idx[i], old_reg, new_reg);
        patched++;
    }
    return patched;
}

static bool mem_is_store(const arm64_inst_t *inst) {
    switch (inst->op) {
    case ARM_OP_STR: case ARM_OP_STRB: case ARM_OP_STRH:
    case ARM_OP_STP: case ARM_OP_STXR: case ARM_OP_STLR:
        return true;
    default: return false;
    }
}

bool can_reorder(const arm64_inst_t *insns, const inst_live_t *live, int a, int b) {
    (void)live;
    if (a < 0 || b < 0) return false;
    const arm64_inst_t *ia = &insns[a], *ib = &insns[b];

    /* Never reorder branches, calls, system, privileged, or invalid */
    if (ia->is_control_flow || ib->is_control_flow) return false;
    if (ia->is_privileged || ib->is_privileged) return false;
    if (!ia->valid || !ib->valid) return false;
    if (ia->op == ARM_OP_SIMD || ib->op == ARM_OP_SIMD) return false;

    if (ia->addr_mode || ib->addr_mode) {
        if (!ia->addr_mode || !ib->addr_mode) {
            const arm64_inst_t *mem_i = ia->addr_mode ? ia : ib;
            const arm64_inst_t *other = ia->addr_mode ? ib : ia;
            if (mem_i->rn == 31 && mem_i->rn_is_sp) {
                /* Other writes SP? (rd=31 with rn_is_sp, e.g. ADD SP, SP, #x) */
                if (other->rd == 31 && other->rn_is_sp) return false;
                if (other->rn == 31 && other->rn_is_sp) return false;
            }
            goto check_regs;
        }
        /* Both are memory ops */
        /* Pre/post-index modify base ain't reorder */
        if (ia->addr_mode == ADDR_PRE_INDEX || ia->addr_mode == ADDR_POST_INDEX) return false;
        if (ib->addr_mode == ADDR_PRE_INDEX || ib->addr_mode == ADDR_POST_INDEX) return false;
        if (ia->addr_mode == ADDR_LITERAL && ib->addr_mode == ADDR_LITERAL) goto check_regs;
        if (ia->addr_mode == ADDR_LITERAL && !mem_is_store(ib)) goto check_regs;
        if (ib->addr_mode == ADDR_LITERAL && !mem_is_store(ia)) goto check_regs;
        if (!mem_is_store(ia) && !mem_is_store(ib)) goto check_regs;
        /* Same base + non-overlapping offsets: safe */
        if (ia->addr_mode == ADDR_OFFSET && ib->addr_mode == ADDR_OFFSET &&
            ia->rn == ib->rn) {
            int64_t a_lo = ia->imm, a_hi = a_lo + ia->access_size;
            int64_t b_lo = ib->imm, b_hi = b_lo + ib->access_size;
            if (a_hi <= b_lo || b_hi <= a_lo) goto check_regs;
        }
        /* SP-based vs non-SP-based: different address spaces, safe */
        if (ia->addr_mode == ADDR_OFFSET && ib->addr_mode == ADDR_OFFSET) {
            bool a_sp = ia->rn_is_sp && ia->rn == 31;
            bool b_sp = ib->rn_is_sp && ib->rn == 31;
            if (a_sp != b_sp) goto check_regs;
        }
        return false; /* conservative fallback for two memory ops */
    }
check_regs:

    /* Check data dependencies: WAR, RAW, WAW */
    for (int i = 0; i < ia->num_regs_written; i++) {
        uint8_t wr = ia->regs_written[i];
        for (int j = 0; j < ib->num_regs_read; j++)
            if (wr == ib->regs_read[j]) return false;  /* RAW */
        for (int j = 0; j < ib->num_regs_written; j++)
            if (wr == ib->regs_written[j]) return false; /* WAW */
    }
    for (int i = 0; i < ia->num_regs_read; i++) {
        uint8_t rd = ia->regs_read[i];
        for (int j = 0; j < ib->num_regs_written; j++)
            if (rd == ib->regs_written[j]) return false; /* WAR */
    }

    /* Flag dependencies */
    if (ia->sets_flags && ib->reads_flags) return false;
    if (ia->reads_flags && ib->sets_flags) return false;
    if (ia->sets_flags && ib->sets_flags) return false;

    return true;
}

/* Encode SUB immediate */
static uint32_t enc_sub_imm_e(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x51000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_add_imm_e(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x11000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_subs_imm_e(uint8_t rd, uint8_t rn, uint16_t imm12, bool sf) {
    return ((uint32_t)sf << 31) | 0x71000000u | ((uint32_t)imm12 << 10) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_eor_reg_e(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x4A000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_orr_reg_e(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x2A000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_movn(uint8_t rd, uint16_t imm16, bool sf) {
    return ((uint32_t)sf << 31) | 0x12800000u | ((uint32_t)imm16 << 5) | rd;
}

static uint32_t enc_movz_e(uint8_t rd, uint16_t imm16, bool sf) {
    return ((uint32_t)sf << 31) | 0x52800000u | ((uint32_t)imm16 << 5) | rd;
}

/* Encode SUB register */
static uint32_t enc_sub_reg(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x4B000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

static uint32_t enc_add_reg(uint8_t rd, uint8_t rn, uint8_t rm, bool sf) {
    return ((uint32_t)sf << 31) | 0x0B000000u | ((uint32_t)rm << 16) |
           ((uint32_t)rn << 5) | rd;
}

int equiv_subst(mutate_ctx_t *ctx, uint32_t *out) {
    int i = ctx->idx;
    const arm64_inst_t *inst = &ctx->insns[i];
    if (!inst->valid) return 0;

    bool fl = flags_are_dead(ctx->live, i);
    regset_t dead = dead_regs(ctx->live, i);
    if (ctx->loop_body && ctx->loop_body[i]) {
        regset_t ll = loop_live_regs(ctx->insns, ctx->live, ctx->n, ctx->loop_body, i);
        dead &= ~ll;
    }
    uint8_t scratch = pick_dead(ctx, dead);
    uint32_t r = rng(ctx);

    switch (inst->op) {

    /* MOV Xd, Xm -> multiple equivalent forms */
    case ARM_OP_MOV_REG: {
        uint8_t d = inst->rd, m = inst->rm;
        bool sf = inst->is_64bit;
        switch (r % 3) {
        case 0: out[0] = enc_add_imm_e(d, m, 0, sf); return 1;       /* ADD Xd, Xm, #0 */
        case 1: out[0] = enc_eor_reg_e(d, m, 31, sf); return 1;      /* EOR Xd, Xm, XZR */
        case 2: 
            if (scratch != 0xFF) {
                out[0] = enc_orr_reg_e(scratch, 31, m, sf);
                out[1] = enc_orr_reg_e(d, 31, scratch, sf);
                return 2;
            }
            out[0] = enc_add_imm_e(d, m, 0, sf);
            return 1;
        }
        break;
    }

    /* ADD Xd, Xn, #imm */
    case ARM_OP_ADD:
        /* ADD Xd, Xn, #0 -> ORR Xd, XZR, Xn (1-for-1, when not SP) */
        if (!inst->sets_flags && inst->imm == 0 && inst->num_regs_read == 1 &&
            inst->rn != 31 && inst->rd != 31) {
            out[0] = enc_orr_reg_e(inst->rd, 31, inst->rn, inst->is_64bit);
            return 1;
        }
        if (!inst->sets_flags && inst->num_regs_read == 1 && inst->imm > 0 && inst->imm <= 0xFFF) {
            uint8_t d = inst->rd, n = inst->rn;
            bool sf = inst->is_64bit;
            uint16_t imm = (uint16_t)inst->imm;
            switch (r % 3) {
            case 0:
                if (scratch != 0xFF) {
                    out[0] = enc_movz_e(scratch, imm, sf);
                    out[1] = enc_add_reg(d, n, scratch, sf);
                    return 2;
                }
                return 0;
            case 1: 
                if (scratch != 0xFF) {
                    out[0] = enc_movz_e(scratch, imm, sf);
                    out[1] = enc_add_reg(d, n, scratch, sf);
                    return 2;
                }
                return 0;
            case 2: /* ADD Xd,Xn,#a; ADD Xd,Xd,#b where a+b=imm */
                if (imm >= 2) {
                    uint16_t a = (rng(ctx) % (imm - 1)) + 1;
                    uint16_t b = imm - a;
                    out[0] = enc_add_imm_e(d, n, a, sf);
                    out[1] = enc_add_imm_e(d, d, b, sf);
                    return 2;
                }
                return 0;
            }
        }
        break;

    /* SUB Xd, Xn, #imm -> ADD Xd, Xn, #(-imm) via split or reg form */
    case ARM_OP_SUB:
        if (!inst->sets_flags && inst->num_regs_read == 1 && inst->imm > 0 && inst->imm <= 0xFFF) {
            uint8_t d = inst->rd, n = inst->rn;
            bool sf = inst->is_64bit;
            uint16_t imm = (uint16_t)inst->imm;
            if (scratch != 0xFF) {
                out[0] = enc_movz_e(scratch, imm, sf);
                out[1] = enc_sub_reg(d, n, scratch, sf);
                return 2;
            }
            if (imm >= 2) {
                uint16_t a = (rng(ctx) % (imm - 1)) + 1;
                out[0] = enc_sub_imm_e(d, n, a, sf);
                out[1] = enc_sub_imm_e(d, d, imm - a, sf);
                return 2;
            }
        }
        break;

    /* CMP Xn, #imm -> SUBS XZR, Xn, #imm (already the encoding) but can also:
       CMN Xn, #(-imm) when imm fits, or SUBS scratch, Xn, #imm if scratch available */
    case ARM_OP_CMP:
        if (inst->num_regs_read == 1 && inst->imm > 0 && inst->imm <= 0xFFF) {
            uint8_t n = inst->rn;
            bool sf = inst->is_64bit;
            uint16_t imm = (uint16_t)inst->imm;
            if (scratch != 0xFF) {
                /* MOVZ scratch, #imm; SUBS XZR, Xn, scratch */
                out[0] = enc_movz_e(scratch, imm, sf);
                out[1] = enc_subs_imm_e(31, n, 0, sf) | ((uint32_t)scratch << 16);
                /* Actually encode SUBS as register form */
                out[1] = ((uint32_t)sf << 31) | 0x6B000000u | ((uint32_t)scratch << 16) |
                         ((uint32_t)n << 5) | 31;
                return 2;
            }
        }
        break;

    /* MOV Xd, #imm -> MOVN Xd, #(~imm) when imm fits as inverted */
    case ARM_OP_MOV_IMM: {
        uint8_t d = inst->rd;
        bool sf = inst->is_64bit;
        int64_t val = inst->imm;
        uint64_t uval = (uint64_t)val;
        uint64_t mask = sf ? ~0ULL : 0xFFFFFFFFULL;
        uint64_t inv = (~uval) & mask;

        if (inv <= 0xFFFF) {
            /* MOVN Xd, #inv -> produces ~inv = original value */
            out[0] = enc_movn(d, (uint16_t)inv, sf);
            return 1;
        }
        if (uval <= 0xFFFF && scratch != 0xFF) {
            /* MOVZ scratch, #val; ORR Xd, XZR, scratch */
            out[0] = enc_movz_e(scratch, (uint16_t)uval, sf);
            out[1] = enc_orr_reg_e(d, 31, scratch, sf);
            return 2;
        }
        if (uval <= 0xFFFF) {
            /* EOR Xd, Xd, Xd; ADD Xd, Xd, #val - zero then add */
            if (fl) {
                out[0] = enc_eor_reg_e(d, d, d, sf);
                out[1] = enc_add_imm_e(d, d, (uint16_t)(uval & 0xFFF), sf);
                return (uval <= 0xFFF) ? 2 : 0;
            }
            /* Can't clobber flags - use ORR XZR form */
            out[0] = enc_orr_reg_e(d, 31, 31, sf); /* MOV Xd, XZR = 0 */
            out[1] = enc_add_imm_e(d, d, (uint16_t)(uval & 0xFFF), sf);
            return (uval <= 0xFFF) ? 2 : 0;
        }
        break;
    }

    /* SUBS Wd, Wn, Wm -> can swap to CMP-like forms or re-encode */
    case ARM_OP_SUBS: {
        /* SUBS Xd, Xn, Xm with Xd==XZR is CMP - re-encode with different bit pattern */
        if (inst->rd == 31 && inst->num_regs_read == 2) {
            /* CMP Xn, Xm -> SUBS XZR, Xn, Xm - already canonical, but we can
               re-encode with shifted register form (LSL #0 explicit) */
            uint8_t n = inst->rn, m = inst->rm;
            bool sf = inst->is_64bit;
            /* SUBS XZR, Xn, Xm, LSL #0 - same semantics, different encoding */
            out[0] = ((uint32_t)sf << 31) | 0x6B000000u | ((uint32_t)m << 16) |
                     ((uint32_t)n << 5) | 31;
            return 1;
        }
        break;
    }

    /* ADD Xd, Xn, #0 (MOV alias from SP) -> ORR Xd, XZR, Xn when not SP */
    /* (other ADD/SUB/MOV_IMM cases handled above) */

    default:
        break;
    }
    return 0;
}

/* Live read junk */

uint32_t gen_live_junk(mutate_ctx_t *ctx) {
    int i = ctx->idx;
    if (!flags_are_dead(ctx->live, i)) return 0xD503201F; /* need dead flags */

    regset_t dead = dead_regs(ctx->live, i);
    if (ctx->loop_body && ctx->loop_body[i]) {
        regset_t ll = loop_live_regs(ctx->insns, ctx->live, ctx->n, ctx->loop_body, i);
        dead &= ~ll;
    }
    uint8_t d = pick_dead(ctx, dead);
    if (d == 0xFF) return 0xD503201F;

    regset_t live_regs = ctx->live[i].live_out & 0x1FFFFFFFu;
    if (!live_regs) return gen_junk(ctx); /* no live regs, fall back */

    int nlive = __builtin_popcount(live_regs);
    int pick = rng(ctx) % nlive;
    uint8_t lr = 0;
    for (int r = 0; r < 29; r++) {
        if (!(live_regs & REG_BIT(r))) continue;
        if (pick-- == 0) { lr = r; break; }
    }

    bool sf = rng(ctx) & 1;
    uint32_t rb = rng(ctx);
    uint16_t imm;
    if ((rb & 0xF) < 9)       imm = rng(ctx) & 0xFF;
    else if ((rb & 0xF) < 13) imm = rng(ctx) & 0x3F;
    else                       imm = (rng(ctx) & 0x7) * 8;

    switch (rng(ctx) % 10) {
    case 0: return enc_add_imm(d, lr, imm, sf);          /* ADD dead, live, #imm */
    case 1: return enc_sub_imm(d, lr, imm, sf);          /* SUB dead, live, #imm */
    case 2: return enc_orr_reg(d, lr, lr, sf);            /* ORR dead, live, live (=MOV) */
    case 3: return enc_and_reg(d, lr, lr, sf);            /* AND dead, live, live (=MOV) */
    case 4: return enc_adds_imm(d, lr, imm, sf);         /* ADDS dead, live, #imm */
    case 5: return enc_subs_imm(d, lr, imm, sf);         /* SUBS dead, live, #imm */
    case 6: return enc_lsl_imm(d, lr, (rng(ctx) % 3) + 1, sf);
    case 7: return enc_lsr_imm(d, lr, (rng(ctx) % 3) + 1, sf);
    case 8: 
        return enc_subs_imm(31, lr, imm, sf);
    case 9: /* TST-like: ANDS XZR, live, live */
        return enc_ands_reg(31, lr, lr, sf);
    }
    return 0xD503201F;
}

/* Block permutation */

typedef struct { int start, end; int ft_tgt; } block_t;

size_t permute_blocks(const arm64_inst_t *insns, int n, uint32_t *out, size_t out_max, aether_rng_t *rng) {
    if (n < 2 || !out || out_max < (size_t)n + 16) return 0;

    /* Only permute blocks WITHIN a single function. Cross-function permutation
     * breaks stack, RET/RETAA (end), STP X29,X30,[SP,#-N]! (start). */
    int func_start[64], func_end[64]; int nfunc = 0;
    func_start[0] = 0;
    for (int i = 0; i < n; i++) {
        if (insns[i].op == ARM_OP_RET || insns[i].op == ARM_OP_RETAA) {
            if (nfunc < 64) {
                func_end[nfunc] = i + 1;
                nfunc++;
                if (i + 1 < n) func_start[nfunc < 64 ? nfunc : 63] = i + 1;
            }
        }
    }
    if (nfunc == 0 || func_end[nfunc-1] < n) {
        if (nfunc < 64) { func_end[nfunc] = n; nfunc++; }
    }

    size_t total_pos = 0;
    for (int fi = 0; fi < nfunc; fi++) {
        int fs = func_start[fi], fe = func_end[fi];
        int fn = fe - fs;
        if (fn < 4) {
            for (int i = fs; i < fe; i++) {
                if (total_pos >= out_max) return 0;
                out[total_pos++] = insns[i].raw;
            }
            continue;
        }

        /* Build blocks within this function */
        bool *leader = calloc(fn, 1); if (!leader) return 0;
        leader[0] = 1;
        for (int i = 0; i < fn; i++) {
            int gi = fs + i; /* global index */
            if (insns[gi].is_control_flow) {
                if (i + 1 < fn) leader[i + 1] = 1;
                if (insns[gi].op == ARM_OP_B || insns[gi].op == ARM_OP_BL || insns[gi].op == ARM_OP_B_COND ||
                    insns[gi].op == ARM_OP_CBZ || insns[gi].op == ARM_OP_CBNZ || insns[gi].op == ARM_OP_TBZ || insns[gi].op == ARM_OP_TBNZ) {
                    int tgt = i + (insns[gi].target / 4);
                    if (tgt >= 0 && tgt < fn) leader[tgt] = 1;
                }
            }
        }
        block_t blocks[256]; int nb = 0;
        for (int i = 0; i < fn; i++) {
            if (leader[i]) {
                if (nb > 0) blocks[nb - 1].end = i;
                if (nb < 256) { blocks[nb].start = i; blocks[nb].end = fn; blocks[nb].ft_tgt = -1; nb++; }
            }
        }
        free(leader); if (nb < 2) {
            for (int i = fs; i < fe; i++) {
                if (total_pos >= out_max) return 0;
                out[total_pos++] = insns[i].raw;
            }
            continue;
        }
        for (int bi = 0; bi < nb; bi++) {
            int last = blocks[bi].end - 1;
            int gi = fs + last;
            if (last >= 0 && insns[gi].op != ARM_OP_RET && insns[gi].op != ARM_OP_RETAA && insns[gi].op != ARM_OP_B)
                blocks[bi].ft_tgt = (bi + 1 < nb) ? bi + 1 : -1;
        }
        /* Shuffle blocks 1..nb-1 (keep entry block 0 first) */
        int order[256]; for (int i = 0; i < nb; i++) order[i] = i;
        for (int i = nb - 1; i > 1; i--) {
            int j = 1 + aether_rand_n(rng, i);
            int t = order[i]; order[i] = order[j]; order[j] = t;
        }
        int new_off[256], tramp_pos[256]; size_t func_pos = total_pos;
        for (int oi = 0; oi < nb; oi++) {
            int bi = order[oi];
            new_off[bi] = total_pos - func_pos;
            for (int i = blocks[bi].start; i < blocks[bi].end; i++) {
                if (total_pos >= out_max) return 0;
                out[total_pos++] = insns[fs + i].raw;
            }
            tramp_pos[bi] = -1;
            if (blocks[bi].ft_tgt >= 0 && (oi + 1 >= nb || order[oi + 1] != blocks[bi].ft_tgt)) {
                if (total_pos >= out_max) return 0;
                tramp_pos[bi] = total_pos - func_pos;
                out[total_pos++] = 0x14000000;
            }
        }

        for (int bi = 0; bi < nb; bi++) {
            if (tramp_pos[bi] >= 0) {
                int tgt = new_off[blocks[bi].ft_tgt];
                int disp = (tgt - tramp_pos[bi]) * 4;
                if (disp >= -(1 << 27) && disp < (1 << 27))
                    out[func_pos + tramp_pos[bi]] = 0x14000000 | ((disp >> 2) & 0x3FFFFFF);
            }
            for (int i = blocks[bi].start; i < blocks[bi].end; i++) {
                int new_i = new_off[bi] + (i - blocks[bi].start);
                int gi = fs + i;
                if (!insns[gi].is_control_flow) continue;
                int old_tgt = i + (insns[gi].target / 4);
                if (old_tgt < 0 || old_tgt >= fn) continue;
                int tgt_bi = -1;
                for (int k = 0; k < nb; k++) if (old_tgt >= blocks[k].start && old_tgt < blocks[k].end) { tgt_bi = k; break; }
                if (tgt_bi < 0) continue;
                int new_tgt = new_off[tgt_bi] + (old_tgt - blocks[tgt_bi].start);
                int disp = (new_tgt - new_i) * 4;
                if (insns[gi].op == ARM_OP_B || insns[gi].op == ARM_OP_BL) {
                    if (disp >= -(1 << 27) && disp < (1 << 27))
                        out[func_pos + new_i] = (insns[gi].raw & 0xFC000000) | ((disp >> 2) & 0x3FFFFFF);
                } else if (insns[gi].op == ARM_OP_B_COND || insns[gi].op == ARM_OP_CBZ || insns[gi].op == ARM_OP_CBNZ) {
                    if (disp >= -(1 << 20) && disp < (1 << 20))
                        out[func_pos + new_i] = (insns[gi].raw & 0xFF00001F) | (((disp >> 2) & 0x7FFFF) << 5);
                } else if (insns[gi].op == ARM_OP_TBZ || insns[gi].op == ARM_OP_TBNZ) {
                    if (disp >= -(1 << 15) && disp < (1 << 15))
                        out[func_pos + new_i] = (insns[gi].raw & 0xFFF8001F) | (((disp >> 2) & 0x3FFF) << 5);
                }
            }
        }
    }
    return total_pos;
}

static uint8_t pick_live_reg(regset_t live, aether_rng_t *rng) {
    uint8_t regs[29]; int n = 0;
    for (int i = 0; i < 29; i++) if (live & REG_BIT(i)) regs[n++] = i;
    return n ? regs[aether_rand_n(rng, n)] : 0;
}

int gen_opaque_predicate(mutate_ctx_t *ctx, uint32_t out[2], bool branch_taken, int32_t target_offset) {
    if (!ctx || !out || !flags_are_dead(ctx->live, ctx->idx)) return 0;
    regset_t live = ctx->live[ctx->idx].live_out & 0x1FFFFFFFu;
    if (!live) return 0;
    
    uint32_t r = rng(ctx);
    int choice = r % 2; /* Only 2 working patterns */
    uint8_t reg = pick_live_reg(live, ctx->rng);
    
    int32_t disp = target_offset;
    if (disp < -(1 << 20) || disp >= (1 << 20) || (disp & 3)) return 0;
    uint32_t imm19 = (disp >> 2) & 0x7FFFF;
    
    if (choice == 0) {
        out[0] = 0xEB00001F | (reg << 16) | (reg << 5);
        out[1] = 0x54000000 | (imm19 << 5) | (branch_taken ? 0x0 : 0x1);
        return 2;
    } else {
        regset_t dead = dead_regs(ctx->live, ctx->idx);
        if (!dead) return 0;
        uint8_t rd = pick_dead(ctx, dead);
        if (rd == 0xFF) return 0;
        out[0] = 0xCB000000 | rd | (reg << 16) | (reg << 5);
        out[1] = 0x34000000 | (imm19 << 5) | rd | (branch_taken ? 0 : (1u << 24));
        return 2;
    }
}

int reorder_window(arm64_inst_t *insns, const inst_live_t *live, int start, int end, aether_rng_t *rng) {
    if (end - start < 2) return 0;
    int n = end - start;
    if (n > 16) n = 16;
    
    inst_live_t local_live[16];
    memcpy(local_live, live + start, n * sizeof(inst_live_t));
    
    int swaps = 0;
    for (int trial = 0; trial < n * 2; trial++) {
        int i = start + aether_rand_n(rng, n);
        int j = start + aether_rand_n(rng, n);
        if (i == j || i >= end || j >= end) continue;
        if (insns[i].is_control_flow || insns[j].is_control_flow) continue;
        
        int lo = i < j ? i : j, hi = i < j ? j : i;
        bool safe = true;
        for (int k = lo + 1; k < hi && safe; k++) {
            if (!can_reorder(insns, local_live, lo, k)) safe = false;
            if (!can_reorder(insns, local_live, k, hi)) safe = false;
        }
        if (!safe) continue;
        
        if (can_reorder(insns, local_live, i, j)) {
            arm64_inst_t tmp = insns[i];
            insns[i] = insns[j];
            insns[j] = tmp;
            swaps++;
            /* Recompute liveness after swap */
            liveness_window(insns + start, n, local_live, 0, n - 1);
        }
    }
    return swaps;
}


/* CFF */

size_t flatten_control_flow(const arm64_inst_t *insns, int n, uint32_t *out, size_t out_max, aether_rng_t *rng) {
    if (n < 3 || !out || out_max < (size_t)n * 3) return 0;
    
    bool *leader = calloc(n, 1); if (!leader) return 0;
    leader[0] = 1;
    for (int i = 0; i < n; i++) {
        if (insns[i].is_control_flow && i + 1 < n) leader[i + 1] = 1;
    }
    
    typedef struct { int start, end, state; } fblock_t;
    fblock_t blocks[64]; int nb = 0;
    for (int i = 0; i < n; i++) {
        if (leader[i]) {
            if (nb > 0) blocks[nb - 1].end = i;
            if (nb < 64) {
                blocks[nb].start = i;
                blocks[nb].end = n;
                nb++;
            }
        }
    }
    free(leader);
    if (nb < 2) return 0;

    for (int bi = 0; bi < nb; bi++) {
        int state;
        retry:
        state = (aether_rand(rng) & 0xFFE) + 1; /* 0xff for 0  */
        for (int j = 0; j < bi; j++)
            if (blocks[j].state == state) goto retry;
        blocks[bi].state = state;
    }
    
    uint8_t sr = 16;
    
    size_t pos = 0;
    out[pos++] = 0xD2800000 | ((uint32_t)blocks[0].state << 5) | sr;
    int init_b_pos = pos;
    out[pos++] = 0x14000000;
    
    int block_off[64], block_tramp[64];
    for (int bi = 0; bi < nb; bi++) {
        block_off[bi] = (int)pos;
        for (int i = blocks[bi].start; i < blocks[bi].end; i++) {
            if (pos >= out_max - 16) return 0;
            if (insns[i].is_control_flow) continue;
            out[pos++] = insns[i].raw;
        }
        /* State transition */
        int last = blocks[bi].end - 1;
        if (last >= 0 && insns[last].is_control_flow) {
            if (insns[last].op == ARM_OP_B_COND || insns[last].op == ARM_OP_CBZ || insns[last].op == ARM_OP_CBNZ) {
                int tgt = last + (insns[last].target / 4);
                int tgt_bi = -1, fall_bi = (bi + 1 < nb) ? bi + 1 : -1;
                for (int k = 0; k < nb; k++)
                    if (tgt >= blocks[k].start && tgt < blocks[k].end) { tgt_bi = k; break; }
                if (tgt_bi >= 0 && fall_bi >= 0) {
                    uint8_t cond = 0;
                    if (insns[last].op == ARM_OP_B_COND) cond = insns[last].cond;
                    else if (insns[last].op == ARM_OP_CBZ) cond = 0x0;
                    else if (insns[last].op == ARM_OP_CBNZ) cond = 0x1;
                    out[pos++] = 0xD2800000 | ((uint32_t)blocks[tgt_bi].state << 5) | 9;
                    out[pos++] = 0xD2800000 | ((uint32_t)blocks[fall_bi].state << 5) | 10;
                    out[pos++] = 0x9A800000 | sr | (9u << 5) | (10u << 16) | ((uint32_t)cond << 12);
                }
            } else if (insns[last].op == ARM_OP_B) {
                int tgt = last + (insns[last].target / 4);
                int tgt_bi = -1;
                for (int k = 0; k < nb; k++)
                    if (tgt >= blocks[k].start && tgt < blocks[k].end) { tgt_bi = k; break; }
                if (tgt_bi >= 0)
                    out[pos++] = 0xD2800000 | ((uint32_t)blocks[tgt_bi].state << 5) | sr;
            } else if (insns[last].op == ARM_OP_RET) {
                out[pos++] = 0xD2800000 | sr;
            }
        } else if (bi + 1 < nb) {
            out[pos++] = 0xD2800000 | ((uint32_t)blocks[bi + 1].state << 5) | sr;
        }
        block_tramp[bi] = (int)pos;
        out[pos++] = 0x14000000;
    }
    
    /* Dispatcher */
    int disp_start = (int)pos;
    
    {
        int d = disp_start - init_b_pos;
        out[init_b_pos] = 0x14000000 | ((uint32_t)(d >> 2) & 0x3FFFFFF);
    }
    for (int bi = 0; bi < nb; bi++) {
        int d = disp_start - block_tramp[bi];
        out[block_tramp[bi]] = 0x14000000 | ((uint32_t)(d >> 2) & 0x3FFFFFF);
    }
    
    for (int bi = 0; bi < nb; bi++) {
        if (pos + 2 >= out_max) return 0;
        out[pos++] = 0xF100001F | ((uint32_t)blocks[bi].state << 10) | ((uint32_t)sr << 5);
        int disp = block_off[bi] - (int)pos;
        out[pos++] = 0x54000000 | (((uint32_t)(disp >> 2) & 0x7FFFF) << 5) | 0x0; /* B.EQ */
    }
    
    out[pos++] = 0xF100001F | ((uint32_t)sr << 5); 
    out[pos++] = 0x54000040; /* B.EQ +2 -> RET */
    /* Loop back to dispatcher top */
    {
        int d = disp_start - (int)pos;
        out[pos++] = 0x14000000 | ((uint32_t)(d >> 2) & 0x3FFFFFF);
    }
    out[pos++] = 0xD65F03C0; /* RET */
    
    return pos;
}
