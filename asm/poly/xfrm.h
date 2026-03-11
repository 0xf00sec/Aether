#ifndef AETHER_MUTATE_H
#define AETHER_MUTATE_H

#include "flow.h"
#include "chacha_rng.h"

typedef struct {
    const arm64_inst_t *insns;
    const inst_live_t  *live;
    const slot_live_t  *slive;
    const bool         *loop_body;
    int                 n;
    int                 idx;
    aether_rng_t         *rng;
} mutate_ctx_t;

uint32_t gen_junk(mutate_ctx_t *ctx);
int gen_junk_sequence(mutate_ctx_t *ctx, uint32_t *out, int n_junk);
int rename_reg(uint8_t *code, int n, const inst_live_t *live,
               const def_use_t *chain, uint8_t new_reg);
bool can_reorder(const arm64_inst_t *insns, const inst_live_t *live, int a, int b);

/*
 * swap instruction at idx for semantically same seq.
 * Writes 1-3 instructions to out[]. Returns count, 0 if no match.
 * Can use dead scratch regs.
 */
int equiv_subst(mutate_ctx_t *ctx, uint32_t *out);

/*
 * make junk using live regs, no side effects.
 * Looks real, leaves flags dead.
 */
uint32_t gen_live_junk(mutate_ctx_t *ctx);

/*
 * shuffle basic blocks, fix branches.
 * Returns new code size (words), 0 on fail. out_max in words.
 */
size_t permute_blocks(const arm64_inst_t *insns, int n, uint32_t *out, size_t out_max, aether_rng_t *rng);

/*
 * always-true/false branch that looks conditional.
 * Returns 2 instrs: setup + branch. branch_taken: always taken? target_offset in bytes.
 */
int gen_opaque_predicate(mutate_ctx_t *ctx, uint32_t out[2], bool branch_taken, int32_t target_offset);

/*
 * shuffle insns[start..end] respecting deps.
 * Returns number of reorderings done.
 */
int reorder_window(arm64_inst_t *insns, const inst_live_t *live, int start, int end, aether_rng_t *rng);

/*
 * turn direct flow into dispatcher state machine.
 * Returns new code size (words), 0 on fail. Uses X28 as state var.
 * out_max in words.
 */
size_t flatten_control_flow(const arm64_inst_t *insns, int n, uint32_t *out, size_t out_max, aether_rng_t *rng);

#endif
