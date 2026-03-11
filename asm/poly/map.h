#ifndef AETHER_REGALLOC_H
#define AETHER_REGALLOC_H

#include "arm64.h"
#include "flow.h"
#include "chacha_rng.h"

/* Recolor registers in code[0..n-1] using interference graph.
 * Returns number of registers renamed. Modifies code in-place. */
int regalloc_recolor(uint8_t *code, int n, const arm64_inst_t *insns,
                     const inst_live_t *live, aether_rng_t *rng);

#endif
