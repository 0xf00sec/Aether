#ifndef ENVKEY_H
#define ENVKEY_H

#include <stdint.h>
#include <stddef.h>

// Derive AES key from system env
void derive_env_key(uint8_t key[16], uint8_t iv[16]) __attribute__((visibility("hidden")));

#endif
