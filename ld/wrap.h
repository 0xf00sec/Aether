#ifndef AETHER_WRAP_MACHO_H
#define AETHER_WRAP_MACHO_H

#include <stddef.h>
#include <stdint.h>

/* tz a minimal Mach-O dylib around raw ARM64 code.
 * Caller owns the returned buffer */
uint8_t *wrap_macho(const uint8_t *code, size_t code_sz, size_t *out_sz);

#endif
