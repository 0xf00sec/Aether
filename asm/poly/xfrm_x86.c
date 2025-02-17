#include "xfrm_x86.h"
#include <string.h>

/* pick dead volatile reg */
static uint8_t pick_dead_reg(x86_mutate_ctx_t *ctx) {
    x86_regset_t dead = x86_dead_regs(&ctx->live[ctx->idx], ctx->idx);
    if (!dead) return X86_REG_NONE;
    int count = 0;
    uint8_t candidates[16];
    for (uint8_t r = 0; r < 16; r++)
        if (dead & X86_REG_BIT(r)) candidates[count++] = r;
    if (!count) return X86_REG_NONE;
    return candidates[aether_rand(ctx->rng) % count];
}

static inline uint8_t rex_w(uint8_t reg) {
    return 0x48 | ((reg >= 8) ? 1 : 0);
}
static inline uint8_t rex_wr(uint8_t reg, uint8_t rm) {
    return 0x48 | ((reg >= 8) ? 4 : 0) | ((rm >= 8) ? 1 : 0);
}
static inline uint8_t modrm(uint8_t mod, uint8_t reg, uint8_t rm) {
    return (mod << 6) | ((reg & 7) << 3) | (rm & 7);
}

/* Semantically null ops on dead regs */

int x86_gen_junk(x86_mutate_ctx_t *ctx, uint8_t *out) {
    uint8_t r = pick_dead_reg(ctx);
    if (r == X86_REG_NONE) return 0;
    bool flags_dead = x86_flags_are_dead(&ctx->live[ctx->idx], ctx->idx);

    uint32_t choice = aether_rand(ctx->rng) % (flags_dead ? 8 : 3);
    int len = 0;

    switch (choice) {
    case 0: /* MOV r,imm32 */
        out[len++] = rex_w(r);
        out[len++] = 0xC7;
        out[len++] = modrm(3, 0, r);
        { uint32_t v = aether_rand(ctx->rng);
          memcpy(out + len, &v, 4); len += 4; }
        return len;
    case 1: /* LEA reg, [reg+0] */
        out[len++] = rex_wr(r, r);
        out[len++] = 0x8D;
        out[len++] = modrm(1, r, r);
        if ((r & 7) == 4) out[len++] = 0x24; /* SIB for RSP-based */
        out[len++] = 0x00;
        return len;
    case 2: /* XCHG reg, reg */
        out[len++] = rex_wr(r, r);
        out[len++] = 0x87;
        out[len++] = modrm(3, r, r);
        return len;
    case 3: /* XOR reg, reg */
        out[len++] = rex_wr(r, r);
        out[len++] = 0x31;
        out[len++] = modrm(3, r, r);
        return len;
    case 4: /* ADD reg, 0 */
        out[len++] = rex_w(r);
        out[len++] = 0x83;
        out[len++] = modrm(3, 0, r);
        out[len++] = 0x00;
        return len;
    case 5: /* SUB reg, 0 */
        out[len++] = rex_w(r);
        out[len++] = 0x83;
        out[len++] = modrm(3, 5, r);
        out[len++] = 0x00;
        return len;
    case 6: /* TEST reg, reg */
        out[len++] = rex_wr(r, r);
        out[len++] = 0x85;
        out[len++] = modrm(3, r, r);
        return len;
    case 7: /* OR reg, 0 */
        out[len++] = rex_w(r);
        out[len++] = 0x83;
        out[len++] = modrm(3, 1, r);
        out[len++] = 0x00;
        return len;
    }
    return 0;
}

/* Junk that reads live regs without modifying them */
int x86_gen_live_junk(x86_mutate_ctx_t *ctx, uint8_t *out) {
    if (!x86_flags_are_dead(&ctx->live[ctx->idx], ctx->idx)) return 0;
    const x86_inst_t *inst = &ctx->insns[ctx->idx];
    if (inst->num_regs_read == 0) return 0;

    uint8_t r = inst->regs_read[aether_rand(ctx->rng) % inst->num_regs_read];
    if (r >= 16 || r == X86_REG_RSP || r == X86_REG_RBP) return 0;

    int len = 0;
    switch (aether_rand(ctx->rng) % 3) {
    case 0: /* TEST reg, reg */
        out[len++] = rex_wr(r, r);
        out[len++] = 0x85;
        out[len++] = modrm(3, r, r);
        return len;
    case 1: /* CMP reg, 0 */
        out[len++] = rex_w(r);
        out[len++] = 0x83;
        out[len++] = modrm(3, 7, r);
        out[len++] = 0x00;
        return len;
    case 2: /* TEST reg, imm8 (only for RAX) */
        if (r == X86_REG_RAX) {
            out[len++] = 0xA8;
            out[len++] = (uint8_t)aether_rand(ctx->rng);
            return len;
        }
        out[len++] = rex_wr(r, r);
        out[len++] = 0x85;
        out[len++] = modrm(3, r, r);
        return len;
    }
    return 0;
}

/* equivalent substitution */

int x86_equiv_subst(x86_mutate_ctx_t *ctx, uint8_t *out) {
    const x86_inst_t *inst = &ctx->insns[ctx->idx];
    if (!inst->valid || inst->is_control_flow || inst->is_simd) return 0;
    uint8_t mod = inst->has_modrm ? x86_modrm_mod(inst->modrm) : 0;
    if (mod != 3) return 0; /* only reg-reg for now */

    int len = 0;

    /* XOR reg, reg -> MOV reg, 0 (if flags dead) */
    if (inst->op == X86_OP_XOR && inst->reg == inst->rm &&
        x86_flags_are_dead(&ctx->live[ctx->idx], ctx->idx)) {
        out[len++] = rex_w(inst->rm);
        out[len++] = 0xC7;
        out[len++] = modrm(3, 0, inst->rm);
        out[len++] = 0; out[len++] = 0; out[len++] = 0; out[len++] = 0;
        return len;
    }

    /* MOV reg, 0 -> XOR reg, reg (if flags dead) */
    if (inst->op == X86_OP_MOV && inst->has_imm && inst->imm == 0 &&
        x86_flags_are_dead(&ctx->live[ctx->idx], ctx->idx)) {
        uint8_t r = inst->rm < 16 ? inst->rm : inst->reg;
        if (r >= 16) return 0;
        out[len++] = rex_wr(r, r);
        out[len++] = 0x31;
        out[len++] = modrm(3, r, r);
        return len;
    }

    /* ADD reg, 1 -> INC reg (if flags behavior matches - both set flags) */
    if (inst->op == X86_OP_ADD && inst->has_imm && inst->imm == 1) {
        out[len++] = rex_w(inst->rm);
        out[len++] = 0xFF;
        out[len++] = modrm(3, 0, inst->rm);
        return len;
    }

    /* SUB reg, 1 -> DEC reg */
    if (inst->op == X86_OP_SUB && inst->has_imm && inst->imm == 1) {
        out[len++] = rex_w(inst->rm);
        out[len++] = 0xFF;
        out[len++] = modrm(3, 1, inst->rm);
        return len;
    }

    /* MOV r1, r2 -> LEA r1, [r2] (if flags dead - LEA doesn't set flags) */
    if (inst->op == X86_OP_MOV && mod == 3 && !inst->has_imm &&
        inst->rm != X86_REG_RSP && inst->rm != X86_REG_RBP) {
        /* Only if flags are dead */
        out[len++] = rex_wr(inst->reg, inst->rm);
        out[len++] = 0x8D;
        if ((inst->rm & 7) == 5) { /* RBP/R13 needs disp8=0 */
            out[len++] = modrm(1, inst->reg, inst->rm);
            out[len++] = 0x00;
        } else if ((inst->rm & 7) == 4) { /* RSP/R12 needs SIB */
            out[len++] = modrm(0, inst->reg, 4);
            out[len++] = 0x24; /* SIB: base=RSP, no index */
        } else {
            out[len++] = modrm(0, inst->reg, inst->rm);
        }
        return len;
    }

    /* SUB reg, imm -> ADD reg, -imm (if imm fits) */
    if (inst->op == X86_OP_SUB && inst->has_imm && inst->imm != 0 &&
        inst->imm > -128 && inst->imm < 128) {
        int8_t neg = (int8_t)(-(int8_t)inst->imm);
        out[len++] = rex_w(inst->rm);
        out[len++] = 0x83;
        out[len++] = modrm(3, 0, inst->rm); /* ADD /0 */
        out[len++] = (uint8_t)neg;
        return len;
    }

    return 0;
}

/* opaque predicates */

int x86_gen_opaque(x86_mutate_ctx_t *ctx, uint8_t *out, int32_t skip_bytes) {
    if (!x86_flags_are_dead(&ctx->live[ctx->idx], ctx->idx)) return 0;
    uint8_t r = pick_dead_reg(ctx);
    if (r == X86_REG_NONE) return 0;
    if (skip_bytes < -128 || skip_bytes > 127) return 0; /* rel8 only */

    int len = 0;
    switch (aether_rand(ctx->rng) % 3) {
    case 0: /* XOR r,r; TEST r,r; JZ +skip (always taken) */
        out[len++] = rex_wr(r, r); out[len++] = 0x31; out[len++] = modrm(3, r, r);
        out[len++] = rex_wr(r, r); out[len++] = 0x85; out[len++] = modrm(3, r, r);
        out[len++] = 0x74; out[len++] = (uint8_t)skip_bytes;
        return len;
    case 1: /* MOV r, 1; AND r, 1; TEST r,r; JNZ +skip (always taken) */
        out[len++] = rex_w(r); out[len++] = 0xC7; out[len++] = modrm(3, 0, r);
        out[len++] = 1; out[len++] = 0; out[len++] = 0; out[len++] = 0;
        out[len++] = rex_w(r); out[len++] = 0x83; out[len++] = modrm(3, 4, r); out[len++] = 1;
        out[len++] = rex_wr(r, r); out[len++] = 0x85; out[len++] = modrm(3, r, r);
        out[len++] = 0x75; out[len++] = (uint8_t)skip_bytes;
        return len;
    case 2: /* SUB r,r; JE +skip (always taken) */
        out[len++] = rex_wr(r, r); out[len++] = 0x29; out[len++] = modrm(3, r, r);
        out[len++] = 0x74; out[len++] = (uint8_t)skip_bytes;
        return len;
    }
    return 0;
}

/* window reorder */

bool x86_can_reorder(const x86_inst_t *insns, const x86_inst_live_t *live, int a, int b) {
    if (a == b) return false;
    const x86_inst_t *ia = &insns[a], *ib = &insns[b];
    if (!ia->valid || !ib->valid) return false;
    if (ia->is_control_flow || ib->is_control_flow) return false;
    if (ia->is_privileged || ib->is_privileged) return false;
    if (ia->has_lock || ib->has_lock) return false;

    /* Check WAR, WAW, RAW hazards */
    x86_regset_t a_def = live[a].def, a_use = live[a].use;
    x86_regset_t b_def = live[b].def, b_use = live[b].use;

    if (a_def & b_use) return false; /* RAW: a writes, b reads */
    if (b_def & a_use) return false; /* WAR: b writes, a reads */
    if (a_def & b_def) return false; /* WAW: both write same */

    if ((ia->addr_mode == X86_ADDR_MEM || ia->addr_mode == X86_ADDR_RIP) ||
        (ib->addr_mode == X86_ADDR_MEM || ib->addr_mode == X86_ADDR_RIP))
        return false;

    return true;
}

int x86_reorder_window(x86_inst_t *insns, x86_inst_live_t *live,
                       int start, int end, aether_rng_t *rng) {
    int swaps = 0;
    for (int i = start; i < end - 1; i++) {
        int j = i + 1 + (aether_rand(rng) % (end - i - 1));
        if (j >= end) j = end - 1;
        if (x86_can_reorder(insns, live, i, j)) {
            x86_inst_t tmp = insns[i]; insns[i] = insns[j]; insns[j] = tmp;
            x86_inst_live_t lt = live[i]; live[i] = live[j]; live[j] = lt;
            swaps++;
        }
    }
    return swaps;
}
