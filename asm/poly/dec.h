#ifndef POLY_DECRYPT_H
#define POLY_DECRYPT_H

#include <stdint.h>
#include <stddef.h>

/* Generate encryption key from generation number + seed */
uint64_t derive_key(uint32_t generation, uint32_t seed);

/* Each generation encrypts its __TEXT with a unique key.
 * The reflective loader decrypts during segment mapping. */
void encrypt_text(uint8_t *code, size_t len, uint64_t key);

/* Decrypt __TEXT section */
void decrypt_text(uint8_t *code, size_t len, uint64_t key);

#endif
