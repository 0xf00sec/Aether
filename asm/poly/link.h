#ifndef AETHER_INTEGRATE_H
#define AETHER_INTEGRATE_H

#include <stddef.h>
#include <stdint.h>
#include "chacha_rng.h"

size_t aether_mutate(uint8_t *code, size_t size, size_t max_size,
                   aether_rng_t *rng, unsigned intensity, unsigned passes,
                   uint64_t text_vmaddr, uint64_t text_vmend);

#endif
