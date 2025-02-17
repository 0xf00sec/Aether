#include "flow_x86.h"
#include <stdlib.h>

/* use/def extraction */

static void inst_usedef(const x86_inst_t *inst, x86_regset_t *use, x86_regset_t *def) {
    *use = *def = 0;
    if (!inst->valid || inst->op == X86_OP_NONE) {
        *use = *def = 0xFFFFFFFFu; /* barrier */
        return;
    }

    for (int i = 0; i < inst->num_regs_read; i++)
        if (inst->regs_read[i] < 16) *use |= X86_REG_BIT(inst->regs_read[i]);
    for (int i = 0; i < inst->num_regs_written; i++)
        if (inst->regs_written[i] < 16) *def |= X86_REG_BIT(inst->regs_written[i]);

    if (inst->reads_flags) *use |= X86_FLAGS_BIT;
    if (inst->sets_flags)  *def |= X86_FLAGS_BIT;

    /* Clobbers all volatile regs + flags, reads RSP */
    if (inst->op == X86_OP_CALL) {
        *use |= X86_REG_BIT(X86_REG_RDI) | X86_REG_BIT(X86_REG_RSI) |
                X86_REG_BIT(X86_REG_RDX) | X86_REG_BIT(X86_REG_RCX) |
                X86_REG_BIT(X86_REG_R8)  | X86_REG_BIT(X86_REG_R9);  /* SysV args */
        *def |= X86_REG_BIT(X86_REG_RAX) | X86_REG_BIT(X86_REG_RCX) |
                X86_REG_BIT(X86_REG_RDX) | X86_REG_BIT(X86_REG_RSI) |
                X86_REG_BIT(X86_REG_RDI) | X86_REG_BIT(X86_REG_R8)  |
                X86_REG_BIT(X86_REG_R9)  | X86_REG_BIT(X86_REG_R10) |
                X86_REG_BIT(X86_REG_R11) | X86_FLAGS_BIT;
    }

    /* Reads RAX (return value) + RSP */
    if (inst->op == X86_OP_RET) {
        *use |= X86_REG_BIT(X86_REG_RAX) | X86_REG_BIT(X86_REG_RSP) |
                X86_REG_BIT(X86_REG_RBX) | X86_REG_BIT(X86_REG_RBP) |
                X86_REG_BIT(X86_REG_R12) | X86_REG_BIT(X86_REG_R13) |
                X86_REG_BIT(X86_REG_R14) | X86_REG_BIT(X86_REG_R15);
    }

    /* Reads RDI,RSI,RDX,R10,R8,R9,RAX; clobbers RCX,R11,RAX */
    if (inst->op == X86_OP_SYSCALL) {
        *use |= X86_REG_BIT(X86_REG_RAX) | X86_REG_BIT(X86_REG_RDI) |
                X86_REG_BIT(X86_REG_RSI) | X86_REG_BIT(X86_REG_RDX) |
                X86_REG_BIT(X86_REG_R10) | X86_REG_BIT(X86_REG_R8)  |
                X86_REG_BIT(X86_REG_R9);
        *def |= X86_REG_BIT(X86_REG_RAX) | X86_REG_BIT(X86_REG_RCX) |
                X86_REG_BIT(X86_REG_R11) | X86_FLAGS_BIT;
    }
}

/* window-mode liveness */

void x86_liveness_window(const x86_inst_t *insns, int n,
                         x86_inst_live_t *out, int win_start, int win_end) {
    if (win_end >= n) win_end = n - 1;
    if (win_start < 0) win_start = 0;

    for (int i = win_start; i <= win_end; i++)
        inst_usedef(&insns[i], &out[i].use, &out[i].def);

    /* everything live at exit */
    x86_regset_t live = 0xFFFFFFFFu;

    /* look-ahead to narrow live_out */
    x86_regset_t la_def = 0, la_use = 0;
    int la_limit = (win_end + 17 < n) ? win_end + 17 : n;
    for (int i = win_end + 1; i < la_limit; i++) {
        x86_regset_t u, d;
        inst_usedef(&insns[i], &u, &d);
        la_use |= u & ~la_def;
        la_def |= d;
        if (insns[i].is_control_flow) break;
    }
    live &= ~(la_def & ~la_use);

    /* i-- pass */
    for (int i = win_end; i >= win_start; i--) {
        out[i].live_out = live;
        live = out[i].use | (live & ~out[i].def);
        out[i].live_in = live;
    }
}

#define MAX_BLOCKS 256

/* Find instruction index from byte offset (binary search) */
static int offset_to_idx(const int *offsets, int n, int byte_off) {
    for (int i = 0; i < n; i++)
        if (offsets[i] == byte_off) return i;
    return -1;
}

int x86_liveness_full(const x86_inst_t *insns, int n, x86_inst_live_t *out) {
    if (n <= 0) return 0;

    /* Build byte-offset table for branch target resolution */
    int *offsets = calloc(n, sizeof(int));
    int off = 0;
    for (int i = 0; i < n; i++) { offsets[i] = off; off += insns[i].len; }

    /* Compute use/def */
    for (int i = 0; i < n; i++)
        inst_usedef(&insns[i], &out[i].use, &out[i].def);

    /* Find leaders */
    bool *is_leader = calloc(n, sizeof(bool));
    is_leader[0] = true;
    for (int i = 0; i < n; i++) {
        if (insns[i].is_control_flow) {
            if (i + 1 < n) is_leader[i + 1] = true;
            if (insns[i].target != 0) {
                int tgt_byte = offsets[i] + insns[i].len + (int)insns[i].target;
                int tgt_idx = offset_to_idx(offsets, n, tgt_byte);
                if (tgt_idx >= 0) is_leader[tgt_idx] = true;
            }
        }
    }

    /* Build blocks */
    int block_start[MAX_BLOCKS], block_count[MAX_BLOCKS];
    int nblocks = 0;
    for (int i = 0; i < n && nblocks < MAX_BLOCKS; i++) {
        if (is_leader[i]) {
            if (nblocks > 0) block_count[nblocks - 1] = i - block_start[nblocks - 1];
            block_start[nblocks++] = i;
        }
    }
    if (nblocks > 0) block_count[nblocks - 1] = n - block_start[nblocks - 1];
    free(is_leader);

    /* Per-block live_out */
    x86_regset_t blk_live_out[MAX_BLOCKS];
    for (int b = 0; b < nblocks; b++) {
        int last = block_start[b] + block_count[b] - 1;
        if (last == n - 1 || insns[last].op == X86_OP_RET)
            blk_live_out[b] = X86_REG_BIT(X86_REG_RAX) | X86_REG_BIT(X86_REG_RSP) |
                              X86_REG_BIT(X86_REG_RBP) | X86_REG_BIT(X86_REG_RBX) |
                              X86_REG_BIT(X86_REG_R12) | X86_REG_BIT(X86_REG_R13) |
                              X86_REG_BIT(X86_REG_R14) | X86_REG_BIT(X86_REG_R15);
        else
            blk_live_out[b] = 0xFFFFFFFFu;
    }

    /* Fixed-point iteration */
    for (int iter = 0; iter < 1000; iter++) {
        bool changed = false;
        for (int b = nblocks - 1; b >= 0; b--) {
            int s = block_start[b];
            int e = s + block_count[b] - 1;
            x86_regset_t new_out = 0;

            if (e + 1 < n && (!insns[e].is_control_flow ||
                insns[e].op == X86_OP_JCC || insns[e].op == X86_OP_LOOP ||
                insns[e].op == X86_OP_CALL))
                new_out |= out[e + 1].live_in;

            /* Branch target */
            if (insns[e].is_control_flow && insns[e].target != 0) {
                int tgt_byte = offsets[e] + insns[e].len + (int)insns[e].target;
                int tgt_idx = offset_to_idx(offsets, n, tgt_byte);
                if (tgt_idx >= 0) new_out |= out[tgt_idx].live_in;
            }

            if (insns[e].op == X86_OP_RET)
                new_out = X86_REG_BIT(X86_REG_RAX) | X86_REG_BIT(X86_REG_RSP) |
                          X86_REG_BIT(X86_REG_RBP) | X86_REG_BIT(X86_REG_RBX) |
                          X86_REG_BIT(X86_REG_R12) | X86_REG_BIT(X86_REG_R13) |
                          X86_REG_BIT(X86_REG_R14) | X86_REG_BIT(X86_REG_R15);

            if (new_out != blk_live_out[b]) { blk_live_out[b] = new_out; changed = true; }

            x86_regset_t live = blk_live_out[b];
            for (int i = e; i >= s; i--) {
                out[i].live_out = live;
                live = out[i].use | (live & ~out[i].def);
                out[i].live_in = live;
            }
        }
        if (!changed) break;
    }

    free(offsets);
    return nblocks;
}
