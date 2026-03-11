#include "arm64.h"

static inline uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static inline uint32_t bits(uint32_t x, int hi, int lo) {
    return (x >> lo) & ((1u << (hi - lo + 1)) - 1u);
}
static inline int64_t sxt(uint64_t v, int n) {
    uint64_t m = 1ULL << (n - 1);
    return (int64_t)((v ^ m) - m);
}

static inline void rd_track(arm64_inst_t *o, uint8_t r) {
    if (r < 31 && o->num_regs_read < 4)
        o->regs_read[o->num_regs_read++] = r;
}
static inline void wr_track(arm64_inst_t *o, uint8_t r) {
    if (r < 31 && o->num_regs_written < 2)
        o->regs_written[o->num_regs_written++] = r;
}

static uint64_t decode_bitmask(bool sf, uint32_t N, uint32_t immr, uint32_t imms) {
    int len = 0;
    uint32_t combined = (N << 6) | (~imms & 0x3F);
    /* Find highest set bit */
    for (int i = 6; i >= 1; i--) {
        if (combined & (1u << i)) { len = i; break; }
    }
    if (len == 0) return 0;
    int esize = 1 << len;
    int levels = esize - 1;
    int s = imms & levels;
    int r = immr & levels;
    uint64_t welem = (1ULL << (s + 1)) - 1;
    /* Rotate right by r within esize */
    if (r) welem = ((welem >> r) | (welem << (esize - r))) & ((1ULL << esize) - 1);
    /* Replicate across 64 bits */
    uint64_t mask = 0;
    for (int i = 0; i < 64; i += esize)
        mask |= welem << i;
    if (!sf) mask &= 0xFFFFFFFFULL;
    return mask;
}

bool arm64_decode(const uint8_t *code, arm64_inst_t *out) {
    memset(out, 0, sizeof(*out));
    uint32_t w = rd_u32(code);
    out->raw = w;
    out->valid = true;
    out->rd = w & 0x1F;
    out->rn = (w >> 5) & 0x1F;
    out->rm = (w >> 16) & 0x1F;
    out->ra = (w >> 10) & 0x1F;

    /* B / BL */
    if ((w & 0x7C000000) == 0x14000000) {
        bool link = (w >> 31) & 1;
        int64_t off = sxt(bits(w, 25, 0), 26) << 2;
        out->op = link ? ARM_OP_BL : ARM_OP_B;
        out->target = off;
        out->imm = off;
        out->is_control_flow = true;
        if (link) wr_track(out, 30);
        return true;
    }
    /* B.cond */
    if ((w & 0xFF000010) == 0x54000000) {
        out->op = ARM_OP_B_COND;
        out->target = sxt(bits(w, 23, 5), 19) << 2;
        out->cond = (arm_cond_t)(w & 0xF);
        out->reads_flags = true;
        out->is_control_flow = true;
        return true;
    }
    /* CBZ / CBNZ */
    if ((w & 0x7E000000) == 0x34000000) {
        out->op = ((w >> 24) & 1) ? ARM_OP_CBNZ : ARM_OP_CBZ;
        out->target = sxt(bits(w, 23, 5), 19) << 2;
        out->is_64bit = (w >> 31) & 1;
        out->is_control_flow = true;
        rd_track(out, out->rd);
        return true;
    }
    /* TBZ / TBNZ */
    if ((w & 0x7E000000) == 0x36000000) {
        out->op = ((w >> 24) & 1) ? ARM_OP_TBNZ : ARM_OP_TBZ;
        out->target = sxt(bits(w, 18, 5), 14) << 2;
        out->bit_pos = (((w >> 31) & 1) << 5) | bits(w, 23, 19);
        out->is_64bit = (w >> 31) & 1;
        out->is_control_flow = true;
        rd_track(out, out->rd);
        return true;
    }
    /* BR */
    if ((w & 0xFFFFFC1F) == 0xD61F0000) {
        out->op = ARM_OP_BR;
        out->is_control_flow = true;
        rd_track(out, out->rn);
        return true;
    }
    /* BLR */
    if ((w & 0xFFFFFC1F) == 0xD63F0000) {
        out->op = ARM_OP_BLR;
        out->is_control_flow = true;
        rd_track(out, out->rn);
        wr_track(out, 30);
        return true;
    }
    /* RET */
    if ((w & 0xFFFFFC1F) == 0xD65F0000) {
        out->op = ARM_OP_RET;
        out->is_control_flow = true;
        rd_track(out, out->rn);
        return true;
    }
    /* RETAA / RETAB */
    if ((w & 0xFFFFFBFF) == 0xD65F0BFF) {
        out->op = ARM_OP_RETAA;
        out->is_control_flow = true;
        return true;
    }

    /* PAC */
    if ((w & 0xFFFFFBFF) == 0xD503233F) { out->op = ARM_OP_PACIASP; out->is_privileged = true; return true; }
    if ((w & 0xFFFFFBFF) == 0xD50323BF) { out->op = ARM_OP_AUTIASP; out->is_privileged = true; return true; }
    if ((w & 0xFFFFFC00) == 0xDAC10000) { out->op = ARM_OP_PACIASP; out->is_privileged = true; return true; }
    if ((w & 0xFFFFFC00) == 0xDAC11000) { out->op = ARM_OP_AUTIASP; out->is_privileged = true; return true; }

    if ((w & 0x1F000000) == 0x11000000) {
        bool sf = (w >> 31) & 1;
        bool op = (w >> 30) & 1;  /* 0=ADD 1=SUB */
        bool S  = (w >> 29) & 1;
        bool sh = (w >> 22) & 1;
        uint64_t imm12 = bits(w, 21, 10);
        out->imm = imm12 << (sh ? 12 : 0);
        out->is_64bit = sf;
        out->sets_flags = S;
        out->rn_is_sp = true;

        if (S && out->rd == 31) {
            out->op = op ? ARM_OP_CMP : ARM_OP_CMN;
            rd_track(out, out->rn);
        } else {
            out->op = S ? (op ? ARM_OP_SUBS : ARM_OP_ADDS) :
                          (op ? ARM_OP_SUB  : ARM_OP_ADD);
            rd_track(out, out->rn);
            wr_track(out, out->rd);
        }
        return true;
    }

    if ((w & 0x1F000000) == 0x0B000000) {
        bool sf = (w >> 31) & 1;
        bool op = (w >> 30) & 1;
        bool S  = (w >> 29) & 1;
        out->shift_type = bits(w, 23, 22);
        out->shift_amount = bits(w, 15, 10);
        out->is_64bit = sf;
        out->sets_flags = S;

        if (S && out->rd == 31) {
            out->op = op ? ARM_OP_CMP : ARM_OP_CMN;
            rd_track(out, out->rn);
            rd_track(out, out->rm);
        } else {
            out->op = S ? (op ? ARM_OP_SUBS : ARM_OP_ADDS) :
                          (op ? ARM_OP_SUB  : ARM_OP_ADD);
            rd_track(out, out->rn);
            rd_track(out, out->rm);
            wr_track(out, out->rd);
        }
        return true;
    }

    if ((w & 0x1F000000) == 0x0A000000) {
        bool sf = (w >> 31) & 1;
        uint32_t opc = bits(w, 30, 29);
        bool N = (w >> 21) & 1;
        out->shift_type = bits(w, 23, 22);
        out->shift_amount = bits(w, 15, 10);
        out->is_64bit = sf;

        /* MOV reg alias: ORR Xd, XZR, Xm (opc=1, N=0, Rn=31, shift=0, amt=0) */
        if (opc == 1 && !N && out->rn == 31 && out->shift_type == 0 && out->shift_amount == 0) {
            out->op = ARM_OP_MOV_REG;
            rd_track(out, out->rm);
            wr_track(out, out->rd);
            return true;
        }
        /* MVN alias: ORN Xd, XZR, Xm (opc=1, N=1, Rn=31) */
        if (opc == 1 && N && out->rn == 31) {
            out->op = ARM_OP_MVN;
            rd_track(out, out->rm);
            wr_track(out, out->rd);
            return true;
        }
        /* TST alias: ANDS XZR, Xn, Xm */
        if (opc == 3 && out->rd == 31) {
            out->op = ARM_OP_TST;
            out->sets_flags = true;
            rd_track(out, out->rn);
            rd_track(out, out->rm);
            return true;
        }

        switch (opc) {
            case 0: out->op = N ? ARM_OP_BIC : ARM_OP_AND; break;
            case 1: out->op = N ? ARM_OP_ORN : ARM_OP_ORR; break;
            case 2: out->op = N ? ARM_OP_EON : ARM_OP_EOR; break;
            case 3: out->op = ARM_OP_ANDS; out->sets_flags = true; break;
        }
        rd_track(out, out->rn);
        rd_track(out, out->rm);
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x1F800000) == 0x12000000) {
        bool sf = (w >> 31) & 1;
        uint32_t opc = bits(w, 30, 29);
        uint32_t N = (w >> 22) & 1;
        uint32_t immr = bits(w, 21, 16);
        uint32_t imms = bits(w, 15, 10);
        out->imm = (int64_t)decode_bitmask(sf, N, immr, imms);
        out->is_64bit = sf;

        if (opc == 3 && out->rd == 31) {
            out->op = ARM_OP_TST;
            out->sets_flags = true;
            rd_track(out, out->rn);
            return true;
        }
        switch (opc) {
            case 0: out->op = ARM_OP_AND; break;
            case 1: out->op = ARM_OP_ORR; break;
            case 2: out->op = ARM_OP_EOR; break;
            case 3: out->op = ARM_OP_ANDS; out->sets_flags = true; break;
        }
        rd_track(out, out->rn);
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x1F800000) == 0x12800000) {
        bool sf = (w >> 31) & 1;
        uint32_t opc = bits(w, 30, 29);
        uint32_t hw = bits(w, 22, 21);
        uint64_t imm16 = bits(w, 20, 5);
        uint64_t shift = (uint64_t)hw * 16;
        out->is_64bit = sf;
        wr_track(out, out->rd);

        if (opc == 3) { /* MOVK */
            out->op = ARM_OP_MOVK;
            out->imm = (int64_t)imm16;
            out->shift_amount = (uint8_t)shift;
            rd_track(out, out->rd); /* also reads dest */
            return true;
        }
        out->op = ARM_OP_MOV_IMM;
        if (opc == 2) /* MOVZ */
            out->imm = (int64_t)(imm16 << shift);
        else { /* MOVN */
            uint64_t mask = sf ? ~0ULL : 0xFFFFFFFFULL;
            out->imm = (int64_t)((~(imm16 << shift)) & mask);
        }
        return true;
    }

    /* ADRP */
    if ((w & 0x9F000000) == 0x90000000) {
        uint32_t lo = bits(w, 30, 29);
        uint32_t hi = bits(w, 23, 5);
        out->op = ARM_OP_ADRP;
        out->imm = sxt(((uint64_t)hi << 2) | lo, 21) << 12;
        out->is_64bit = true;
        out->is_control_flow = true; /* PC-relative - must not be reordered */
        wr_track(out, out->rd);
        return true;
    }
    /* ADR */
    if ((w & 0x9F000000) == 0x10000000) {
        uint32_t lo = bits(w, 30, 29);
        uint32_t hi = bits(w, 23, 5);
        out->op = ARM_OP_ADR;
        out->imm = sxt(((uint64_t)hi << 2) | lo, 21);
        out->is_64bit = true;
        out->is_control_flow = true; /* PC-relative - same here */
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x1FE00000) == 0x1A800000) {
        bool op = (w >> 30) & 1;
        uint32_t op2 = bits(w, 11, 10);
        out->cond = (arm_cond_t)bits(w, 15, 12);
        out->is_64bit = (w >> 31) & 1;
        out->reads_flags = true;

        if (!op && op2 == 0)      out->op = ARM_OP_CSEL;
        else if (!op && op2 == 1) out->op = ARM_OP_CSINC;
        else if (op && op2 == 0)  out->op = ARM_OP_CSINV;
        else                      out->op = ARM_OP_CSNEG;

        rd_track(out, out->rn);
        rd_track(out, out->rm);
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x1FE00000) == 0x1A400000) {
        bool op = (w >> 30) & 1;
        out->op = op ? ARM_OP_CCMP : ARM_OP_CCMN;
        out->cond = (arm_cond_t)bits(w, 15, 12);
        out->imm = bits(w, 3, 0); /* nzcv */
        out->is_64bit = (w >> 31) & 1;
        out->sets_flags = true;
        out->reads_flags = true;
        rd_track(out, out->rn);
        if (!((w >> 11) & 1)) rd_track(out, out->rm); /* register form */
        return true;
    }

    if ((w & 0x1F000000) == 0x1B000000) {
        bool sf = (w >> 31) & 1;
        uint32_t op31 = bits(w, 23, 21);
        bool o0 = (w >> 15) & 1;
        out->is_64bit = sf;

        if (op31 == 0) {
            if (out->ra == 31)
                out->op = ARM_OP_MUL;
            else
                out->op = o0 ? ARM_OP_MSUB : ARM_OP_MADD;
        } else if (op31 == 1) {
            out->op = o0 ? ARM_OP_MSUB : ARM_OP_SMULL;
        } else if (op31 == 5) {
            out->op = o0 ? ARM_OP_MSUB : ARM_OP_UMULL;
        } else if (op31 == 2) {
            out->op = ARM_OP_SMULH;
        } else if (op31 == 6) {
            out->op = ARM_OP_UMULH;
        } else {
            out->op = ARM_OP_MUL;
        }
        rd_track(out, out->rn);
        rd_track(out, out->rm);
        if (out->ra != 31 && out->op != ARM_OP_MUL) rd_track(out, out->ra);
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x1FE00000) == 0x1AC00000) {
        uint32_t opc = bits(w, 15, 10);
        out->is_64bit = (w >> 31) & 1;
        switch (opc) {
            case 0x02: out->op = ARM_OP_UDIV; break;
            case 0x03: out->op = ARM_OP_SDIV; break;
            case 0x08: out->op = ARM_OP_LSL; break;
            case 0x09: out->op = ARM_OP_LSR; break;
            case 0x0A: out->op = ARM_OP_ASR; break;
            case 0x0B: out->op = ARM_OP_ROR; break;
            default: out->valid = false; return false;
        }
        rd_track(out, out->rn);
        rd_track(out, out->rm);
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x1F800000) == 0x13000000) {
        uint32_t opc = bits(w, 30, 29);
        out->is_64bit = (w >> 31) & 1;
        uint32_t immr = bits(w, 21, 16);
        uint32_t imms = bits(w, 15, 10);
        out->imm = immr;
        out->shift_amount = (uint8_t)imms;
        switch (opc) {
            case 0: out->op = ARM_OP_SBFM; break;
            case 1: out->op = ARM_OP_BFM; break;
            case 2: out->op = ARM_OP_UBFM; break;
            default: out->op = ARM_OP_BFM; break;
        }
        rd_track(out, out->rn);
        wr_track(out, out->rd);
        if (opc == 1) rd_track(out, out->rd); /* BFM also reads Rd */
        return true;
    }

    if ((w & 0x1F800000) == 0x13800000) {
        out->op = (out->rn == out->rm) ? ARM_OP_ROR : ARM_OP_EXTR;
        out->is_64bit = (w >> 31) & 1;
        out->imm = bits(w, 15, 10);
        rd_track(out, out->rn);
        rd_track(out, out->rm);
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x3B000000) == 0x39000000) {
        uint32_t size = bits(w, 31, 30);
        uint32_t opc = bits(w, 23, 22);
        uint32_t imm12 = bits(w, 21, 10);
        out->imm = (int64_t)(imm12 << size);
        out->is_64bit = (size == 3);
        out->access_size = 1 << size;
        out->addr_mode = ADDR_OFFSET;
        out->rn_is_sp = true;

        if (opc == 0) {
            out->op = (size == 0) ? ARM_OP_STRB : (size == 1) ? ARM_OP_STRH : ARM_OP_STR;
            rd_track(out, out->rd);
        } else if (opc == 1) {
            out->op = (size == 0) ? ARM_OP_LDRB : (size == 1) ? ARM_OP_LDRH : ARM_OP_LDR;
            wr_track(out, out->rd);
        } else {
            /* opc >= 2 signed loads. size=3,opc=2 is PRFM as NOP */
            if (size == 3) { out->op = ARM_OP_NOP; return true; }
            out->op = (size == 0) ? ARM_OP_LDRSB : (size == 1) ? ARM_OP_LDRSH : ARM_OP_LDRSW;
            wr_track(out, out->rd);
        }
        rd_track(out, out->rn);
        return true;
    }

    /* Bit 26 (V) distinguishes integer (0) from SIMD (1) pairs */
    if ((w & 0x3E000000) == 0x28000000) {
        uint32_t opc = bits(w, 31, 30);
        bool L = (w >> 22) & 1;
        int32_t imm7 = (int32_t)sxt(bits(w, 21, 15), 7);
        uint32_t scale = (opc == 0) ? 2 : 3;
        uint32_t idx = bits(w, 24, 23); /* 0=post, 1=signed-off, 2=pre */
        out->imm = imm7 << scale;
        out->is_64bit = (opc == 2);
        out->access_size = 1 << scale;
        out->rn_is_sp = true;
        out->op = L ? ARM_OP_LDP : ARM_OP_STP;

        if (idx == 1)      out->addr_mode = ADDR_POST_INDEX;
        else if (idx == 2) out->addr_mode = ADDR_OFFSET;
        else               out->addr_mode = ADDR_PRE_INDEX;

        if (L) { wr_track(out, out->rd); wr_track(out, out->ra); }
        else   { rd_track(out, out->rd); rd_track(out, out->ra); }
        rd_track(out, out->rn);
        if (out->addr_mode != ADDR_OFFSET) wr_track(out, out->rn);
        return true;
    }

    /* Load register */
    if ((w & 0x3B000000) == 0x18000000) {
        out->op = ARM_OP_LDR;
        out->target = sxt(bits(w, 23, 5), 19) << 2;
        out->imm = out->target;
        out->is_64bit = ((w >> 30) & 1);
        out->access_size = out->is_64bit ? 8 : 4;
        out->addr_mode = ADDR_LITERAL;
        wr_track(out, out->rd);
        return true;
    }

    if ((w & 0x3B000000) == 0x38000000) {
        uint32_t size = bits(w, 31, 30);
        uint32_t opc = bits(w, 23, 22);
        uint32_t idx = bits(w, 11, 10);
        out->is_64bit = (size == 3);
        out->access_size = 1 << size;
        out->rn_is_sp = true;

        if ((w >> 21) & 1) {
            /* Register offset */
            out->addr_mode = ADDR_REG_OFFSET;
            rd_track(out, out->rm);
        } else {
            out->imm = sxt(bits(w, 20, 12), 9);
            if (idx == 0)      out->addr_mode = ADDR_OFFSET;      /* unscaled */
            else if (idx == 1) out->addr_mode = ADDR_POST_INDEX;
            else               out->addr_mode = ADDR_PRE_INDEX;   /* idx 3 */
        }

        if (opc & 1) { out->op = ARM_OP_LDR; wr_track(out, out->rd); }
        else         { out->op = ARM_OP_STR; rd_track(out, out->rd); }
        rd_track(out, out->rn);
        if (out->addr_mode == ADDR_PRE_INDEX || out->addr_mode == ADDR_POST_INDEX)
            wr_track(out, out->rn);
        return true;
    }

    /* loads/stores */
    if ((w & 0x3F000000) == 0x08000000) {
        bool L = (w >> 22) & 1;
        out->is_64bit = (w >> 30) & 1;
        out->access_size = out->is_64bit ? 8 : 4;
        out->addr_mode = ADDR_OFFSET;
        out->rn_is_sp = true;
        if (L) { out->op = ARM_OP_LDXR; wr_track(out, out->rd); }
        else   { out->op = ARM_OP_STXR; rd_track(out, out->rd); }
        rd_track(out, out->rn);
        return true;
    }

    /* System */

    /* NOP */
    if (w == 0xD503201F) { out->op = ARM_OP_NOP; return true; }
    /* Hint space (YIELD, WFE, WFI, SEV, etc) */
    if ((w & 0xFFFFF01F) == 0xD503201F) { out->op = ARM_OP_NOP; return true; }
    /* DMB */
    if ((w & 0xFFFFF0FF) == 0xD50330BF) { out->op = ARM_OP_DMB; return true; }
    /* DSB */
    if ((w & 0xFFFFF0FF) == 0xD503309F) { out->op = ARM_OP_DSB; return true; }
    /* ISB */
    if ((w & 0xFFFFF0FF) == 0xD50330DF) { out->op = ARM_OP_ISB; return true; }
    /* BRK */
    if ((w & 0xFFE0001F) == 0xD4200000) {
        out->op = ARM_OP_BRK;
        out->imm = bits(w, 20, 5);
        return true;
    }
    /* SVC */
    if ((w & 0xFFE0001F) == 0xD4000001) {
        out->op = ARM_OP_SVC;
        out->imm = bits(w, 20, 5);
        out->is_privileged = true;
        return true;
    }
    /* MRS */
    if ((w & 0xFFF00000) == 0xD5300000) {
        out->op = ARM_OP_MRS;
        out->is_privileged = true;
        wr_track(out, out->rd);
        return true;
    }
    /* MSR */
    if ((w & 0xFFF00000) == 0xD5100000) {
        out->op = ARM_OP_MSR;
        out->is_privileged = true;
        rd_track(out, out->rd);
        return true;
    }

    /* SIMD/FP load/store pair */
    if ((w & 0x3E000000) == 0x2C000000) {
        out->op = ARM_OP_SIMD;
        rd_track(out, out->rn); /* base register still matters */
        return true;
    }

    /* SIMD/FP (recognize, don't decode internals) */
    if (((w >> 25) & 0xF) == 0x7 || ((w >> 25) & 0xF) == 0xF) {
        out->op = ARM_OP_SIMD;
        return true;
    }
    /* SIMD load/store structure */
    if ((w & 0xBF800000) == 0x0D000000 || (w & 0xBF800000) == 0x0D800000) {
        out->op = ARM_OP_SIMD;
        rd_track(out, out->rn);
        return true;
    }

    /* f00 */
    out->valid = false;
    return false;
}
