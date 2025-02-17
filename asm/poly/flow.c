#include "flow.h"
#include <stdlib.h>

/* use/def extraction */

static void inst_usedef(const arm64_inst_t *inst, regset_t *use, regset_t *def) {
    *use = *def = 0;
    if (!inst->valid) {
        /* assume reads/writes everything (barrier) */
        *use = *def = 0xFFFFFFFFu;
        return;
    }

    for (int i = 0; i < inst->num_regs_read; i++)
        *use |= REG_BIT(inst->regs_read[i]);
    for (int i = 0; i < inst->num_regs_written; i++)
        *def |= REG_BIT(inst->regs_written[i]);

    if (inst->reads_flags) *use |= FLAGS_BIT;
    if (inst->sets_flags)  *def |= FLAGS_BIT;

    if (inst->rn_is_sp && inst->rn == 31) {
        *use |= REG_BIT(30); /* SP read as base - encode in bit 30 area */
        if (inst->addr_mode == ADDR_PRE_INDEX || inst->addr_mode == ADDR_POST_INDEX)
            *def |= REG_BIT(30); /* SP written by writeback */
    }

    if (inst->op == ARM_OP_BL || inst->op == ARM_OP_BLR) {
        *use |= 0x000000FFu;              /* X0-X7 (arguments) */
        *def |= 0x0007FFFFu | FLAGS_BIT;  /* X0-X18 + flags */
    }

    if (inst->op == ARM_OP_SVC) {
        *use |= 0x0001003Fu;  /* X0-X5 + X16 */
        *def |= REG_BIT(0);   /* return value */
    }

    /* RET: implicitly reads X0 (return value) + X30 (link register) */
    if (inst->op == ARM_OP_RET || inst->op == ARM_OP_RETAA) {
        *use |= REG_BIT(0) | REG_BIT(30);
    }
}

/* window-mode liveness */

void liveness_window(const arm64_inst_t *insns, int n,
                     inst_live_t *out, int win_start, int win_end) {
    if (win_end >= n) win_end = n - 1;
    if (win_start < 0) win_start = 0;

    /* Compute use/def for window */
    for (int i = win_start; i <= win_end; i++)
        inst_usedef(&insns[i], &out[i].use, &out[i].def);

    /*
     * So everything potentially live.
     * This is the default way the engine can only use registers we
     * prove are dead, so over-approximation never breaks correctness.
     *
     * scan a few instructions past win_end to narrow it.
     */
    regset_t live = 0xFFFFFFFFu; /* assume worst case */

    /* Scan up to 16 instructions past window to refine live_out.
     * Any register written before being read in the look-ahead is dead at win_end. */
    regset_t la_def = 0, la_use = 0;
    int la_limit = (win_end + 17 < n) ? win_end + 17 : n;
    for (int i = win_end + 1; i < la_limit; i++) {
        regset_t u, d;
        inst_usedef(&insns[i], &u, &d);
        la_use |= u & ~la_def;  /* only count reads not already covered by a write */
        la_def |= d;
        if (insns[i].is_control_flow) break; /* stop at branch */
    }
    /* Registers defined in look-ahead but never used before that def: dead at win_end */
    regset_t proven_dead = la_def & ~la_use;
    live &= ~proven_dead;

    for (int i = win_end; i >= win_start; i--) {
        out[i].live_out = live;
        live = out[i].use | (live & ~out[i].def);
        out[i].live_in = live;
    }
}

#define MAX_BLOCKS 256

int liveness_full(const arm64_inst_t *insns, int n, inst_live_t *out) {
    if (n <= 0) return 0;

    /* Compute use/def for all instructions */
    for (int i = 0; i < n; i++)
        inst_usedef(&insns[i], &out[i].use, &out[i].def);

    bool *is_leader = calloc(n, sizeof(bool));
    is_leader[0] = true;

    for (int i = 0; i < n; i++) {
        if (insns[i].is_control_flow) {
            /* Next instruction is a leader (if it exists) */
            if (i + 1 < n) is_leader[i + 1] = true;
            /* Branch target is a leader */
            int64_t tgt_off = insns[i].target;
            if (tgt_off != 0) {
                int tgt_idx = i + (int)(tgt_off / 4);
                if (tgt_idx >= 0 && tgt_idx < n)
                    is_leader[tgt_idx] = true;
            }
        }
    }

    /* Build block list */
    int block_start[MAX_BLOCKS];
    int block_count[MAX_BLOCKS];
    int nblocks = 0;
    for (int i = 0; i < n && nblocks < MAX_BLOCKS; i++) {
        if (is_leader[i]) {
            if (nblocks > 0)
                block_count[nblocks - 1] = i - block_start[nblocks - 1];
            block_start[nblocks] = i;
            nblocks++;
        }
    }
    if (nblocks > 0)
        block_count[nblocks - 1] = n - block_start[nblocks - 1];

    free(is_leader);

    /* Per-block live_out, initialized conservatively */
    regset_t blk_live_out[MAX_BLOCKS];
    for (int b = 0; b < nblocks; b++) {
        int last = block_start[b] + block_count[b] - 1;
        if (last == n - 1 || insns[last].op == ARM_OP_RET || insns[last].op == ARM_OP_RETAA)
            blk_live_out[b] = REG_BIT(0) | REG_BIT(29) | REG_BIT(30); /* return: X0, FP, LR */
        else
            blk_live_out[b] = 0xFFFFFFFFu;
    }

    /* Iterate to fixed point */
    for (int iter = 0; iter < 1000; iter++) {
        bool changed = false;

        for (int b = nblocks - 1; b >= 0; b--) {
            int s = block_start[b];
            int e = s + block_count[b] - 1;

            /* Compute block live_out from successors' live_in */
            regset_t new_out = 0;
            /* Fallthrough successor */
            if (e + 1 < n && !insns[e].is_control_flow)
                new_out |= out[e + 1].live_in;
            else if (e + 1 < n && insns[e].op != ARM_OP_B && insns[e].op != ARM_OP_BR &&
                     insns[e].op != ARM_OP_RET && insns[e].op != ARM_OP_RETAA)
                new_out |= out[e + 1].live_in; /* conditional: falls through */

            /* Branch target successor */
            if (insns[e].is_control_flow && insns[e].target != 0) {
                int tgt = e + (int)(insns[e].target / 4);
                if (tgt >= 0 && tgt < n)
                    new_out |= out[tgt].live_in;
            }

            /* RET/RETAA: only return-convention regs */
            if (insns[e].op == ARM_OP_RET || insns[e].op == ARM_OP_RETAA)
                new_out = REG_BIT(0) | REG_BIT(29) | REG_BIT(30);

            if (new_out != blk_live_out[b]) {
                blk_live_out[b] = new_out;
                changed = true;
            }

            /* Backward pass within block */
            regset_t live = blk_live_out[b];
            for (int i = e; i >= s; i--) {
                out[i].live_out = live;
                live = out[i].use | (live & ~out[i].def);
                out[i].live_in = live;
            }
        }

        if (!changed) break;
    }

    return nblocks;
}

/* stack slot liveness */

/* Check if instruction is an SP-relative store or load with a known offset */
static bool is_sp_access(const arm64_inst_t *inst, int16_t *offset, uint8_t *size, bool *is_store) {
    if (!inst->valid || !inst->rn_is_sp || inst->rn != 31) return false;
    if (inst->addr_mode == ADDR_REG_OFFSET || inst->addr_mode == ADDR_LITERAL) return false;
    if (inst->access_size == 0) return false;

    switch (inst->op) {
        case ARM_OP_STR: case ARM_OP_STRB: case ARM_OP_STRH:
        case ARM_OP_STP:
            *is_store = true; break;
        case ARM_OP_LDR: case ARM_OP_LDRB: case ARM_OP_LDRH:
        case ARM_OP_LDRSB: case ARM_OP_LDRSH: case ARM_OP_LDRSW:
        case ARM_OP_LDP:
            *is_store = false; break;
        default: return false;
    }
    *offset = (int16_t)inst->imm;
    *size = inst->access_size;
    return true;
}

static int find_or_add_slot(stack_slot_t *slots, uint8_t *num, int16_t offset, uint8_t size) {
    for (int i = 0; i < *num; i++)
        if (slots[i].offset == offset && slots[i].size == size) return i;
    if (*num >= MAX_SLOTS) return -1;
    int idx = *num;
    slots[idx].offset = offset;
    slots[idx].size = size;
    (*num)++;
    return idx;
}

int stack_liveness(const arm64_inst_t *insns, int n, slot_live_t *out) {
    stack_slot_t slots[MAX_SLOTS];
    uint8_t num_slots = 0;
    memset(slots, 0, sizeof(slots));

    for (int i = 0; i < n; i++) {
        int16_t off; uint8_t sz; bool store;
        out[i].def = out[i].use = 0;
        if (!is_sp_access(&insns[i], &off, &sz, &store)) continue;

        int s = find_or_add_slot(slots, &num_slots, off, sz);
        if (s < 0) continue;
        if (store) out[i].def |= (1u << s);
        else       out[i].use |= (1u << s);

        if (insns[i].op == ARM_OP_STP || insns[i].op == ARM_OP_LDP) {
            int s2 = find_or_add_slot(slots, &num_slots, off + sz, sz);
            if (s2 >= 0) {
                if (store) out[i].def |= (1u << s2);
                else       out[i].use |= (1u << s2);
            }
        }
    }

    /* Copy slot table to all entries */
    for (int i = 0; i < n; i++) {
        memcpy(out[i].slots, slots, sizeof(slots));
        out[i].num_slots = num_slots;
    }
    if (num_slots == 0) return 0;

    uint16_t live = 0;
    for (int i = n - 1; i >= 0; i--) {
        /* Pure SP adjustment (SUB/ADD SP, SP, #N) invalidates all slot offsets */
        if (insns[i].rn_is_sp && insns[i].rn == 31 &&
            (insns[i].op == ARM_OP_SUB || insns[i].op == ARM_OP_ADD) &&
            insns[i].rd == 31) {
            live = 0;
            out[i].live_out = out[i].live_in = 0;
            continue;
        }
        out[i].live_out = live;
        live = out[i].use | (live & ~out[i].def);
        out[i].live_in = live;
    }
    return num_slots;
}

/* def-use chains */

int build_def_use(const arm64_inst_t *insns, const inst_live_t *live,
                  int n, uint8_t reg, def_use_t *chains, int max_chains) {
    int nc = 0;
    regset_t bit = REG_BIT(reg);

    for (int i = 0; i < n && nc < max_chains; i++) {
        regset_t u, d;
        inst_usedef(&insns[i], &u, &d);
        if (!(d & bit)) continue;

        def_use_t *c = &chains[nc];
        c->reg = reg;
        c->def_idx = (uint16_t)i;
        c->num_uses = 0;

        /* Scan forward for uses before next def.
         * At branches: use liveness to decide whether to continue.
         * If reg is live-out at the branch, the value reaches a use
         * on some path - keep scanning the fallthrough. */
        for (int j = i + 1; j < n; j++) {
            regset_t uj, dj;
            inst_usedef(&insns[j], &uj, &dj);
            if (uj & bit) {
                if (c->num_uses < 8)
                    c->use_idx[c->num_uses++] = (uint16_t)j;
            }
            if (dj & bit) break; /* redefined - chain ends */

            if (insns[j].is_control_flow) {
                /* If reg is dead after this branch, no path needs it - stop */
                if (!(live[j].live_out & bit)) break;
                /* Unconditional branch with no fallthrough - can't scan past */
                if (insns[j].op == ARM_OP_B || insns[j].op == ARM_OP_BR ||
                    insns[j].op == ARM_OP_RET || insns[j].op == ARM_OP_RETAA)
                    break;
                /* reg is live, continue scanning fallthrough */
            }
        }
        nc++;
    }
    return nc;
}

/* loop detection */

int detect_loops(const arm64_inst_t *insns, int n, bool *loop_body) {
    memset(loop_body, 0, n * sizeof(bool));
    int nloops = 0;

    for (int i = 0; i < n; i++) {
        if (!insns[i].is_control_flow || insns[i].target == 0) continue;
        /* BL/BLR are calls, not loop back-edges */
        if (insns[i].op == ARM_OP_BL || insns[i].op == ARM_OP_BLR) continue;
        int tgt = i + (int)(insns[i].target / 4);
        if (tgt < 0 || tgt >= n) continue;
        if (tgt > i) continue; /* forward branch - not a back-edge */
        /* reject absurdly large loops (>256 insns = likely cross-function) */
        if (i - tgt > 256) continue;

        for (int j = tgt; j <= i; j++)
            loop_body[j] = true;
        nloops++;
    }
    return nloops;
}

regset_t loop_live_regs(const arm64_inst_t *insns, const inst_live_t *live,
                        int n, const bool *loop_body, int idx) {
    if (!loop_body[idx]) return 0;

    /* Find the tightest loop containing idx by scanning for the nearest
     * back-edge whose range covers idx */
    int best_lo = -1, best_hi = -1;
    int best_span = n;

    for (int i = idx; i < n && i < idx + 257; i++) {
        if (!insns[i].is_control_flow || insns[i].target >= 0) continue;
        if (insns[i].op == ARM_OP_BL || insns[i].op == ARM_OP_BLR) continue;
        int tgt = i + (int)(insns[i].target / 4);
        if (tgt < 0 || tgt > idx) continue; /* doesn't contain idx */
        int span = i - tgt;
        if (span < best_span) {
            best_lo = tgt;
            best_hi = i;
            best_span = span;
        }
    }

    if (best_lo < 0) return 0; /* no enclosing back-edge found */

    regset_t all_live = 0;
    for (int i = best_lo; i <= best_hi; i++)
        all_live |= live[i].live_in | live[i].live_out;
    return all_live;
}
