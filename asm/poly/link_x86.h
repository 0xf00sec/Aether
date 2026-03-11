#ifndef AETHER_INTEGRATE_X86_H
#define AETHER_INTEGRATE_X86_H

#include <stddef.h>
#include <stdint.h>
#include "chacha_rng.h"

/* Full x86-64 mutation */
size_t aether_mutate_x86(uint8_t *code, size_t size, size_t max_size,
                       aether_rng_t *rng, unsigned intensity, unsigned passes);

size_t aether_mutate_x86_single(uint8_t *code, size_t size, size_t max_size,
                               aether_rng_t *rng, unsigned intensity);

#endif
