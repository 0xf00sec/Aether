#ifndef AETHER_REGALLOC_X86_H
#define AETHER_REGALLOC_X86_H

#include "x86.h"
#include "flow_x86.h"
#include "chacha_rng.h"

int x86_regalloc_recolor(uint8_t *code, const x86_inst_t *insns, int n,
                         const x86_inst_live_t *live, aether_rng_t *rng);

#endif
