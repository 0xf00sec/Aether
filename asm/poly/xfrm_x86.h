#ifndef AETHER_MUTATE_X86_H
#define AETHER_MUTATE_X86_H

#include "x86.h"
#include "flow_x86.h"
#include "chacha_rng.h"

typedef struct {
    const x86_inst_t      *insns;
    const x86_inst_live_t *live;
    int                    n;
    int                    idx;
    aether_rng_t            *rng;
} x86_mutate_ctx_t;

/* Generate dead-register junk instruction */
int x86_gen_junk(x86_mutate_ctx_t *ctx, uint8_t *out);
int x86_gen_live_junk(x86_mutate_ctx_t *ctx, uint8_t *out);

int x86_equiv_subst(x86_mutate_ctx_t *ctx, uint8_t *out);

int x86_gen_opaque(x86_mutate_ctx_t *ctx, uint8_t *out, int32_t skip_bytes);

/* Can instructions at index a and b be aight reordered? */
bool x86_can_reorder(const x86_inst_t *insns, const x86_inst_live_t *live, int a, int b);

/* Reorder instructions in window [start, end) */
int x86_reorder_window(x86_inst_t *insns, x86_inst_live_t *live,
                       int start, int end, aether_rng_t *rng);

#endif
