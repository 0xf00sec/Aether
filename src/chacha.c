#include "wisp.h"

//===================================================================
/// CHACHA20
//===================================================================

/**
 * chacha20_block
 *
 * Generates a ChaCha20 block using the provided key, counter, and nonce.
 * This routine performs 20 rounds (10 double rounds) of the ChaCha20 quarter-round
 * operations and then adds the original state to the transformed state.
 */
void chacha20_block(const uint32_t key[8], uint32_t counter, const uint32_t nonce[3], uint32_t out[16]) {
    uint32_t state[16], orig[16];
    const uint32_t constants[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6B206574 };

    // Initialize state with constants and key.
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    _memcpy(&state[4], key, 32);
    state[12] = counter;
    _memcpy(&state[13], nonce, 12);

    // Original state.
    _memcpy(orig, state, sizeof(state));

    // Perform 20 rounds (10 iterations of double rounds).
    for (int i = 0; i < 10; i++) {
        QR(state[0], state[4], state[8],  state[12]);
        QR(state[1], state[5], state[9],  state[13]);
        QR(state[2], state[6], state[10], state[14]);
        QR(state[3], state[7], state[11], state[15]);

        QR(state[0], state[5], state[10], state[15]);
        QR(state[1], state[6], state[11], state[12]);
        QR(state[2], state[7], state[8],  state[13]);
        QR(state[3], state[4], state[9],  state[14]);
    }

    // Combine the state with the original state to produce the final output.
    for (int i = 0; i < 16; i++)
        out[i] = state[i] + orig[i];
}

/**
 * chacha20_random
 *
 * Returns a random 32-bit value from the ChaCha20-based RNG.
 * When the internal buffer is exhausted, it regenerates a new block.
 */
uint32_t chacha20_random(ChaChaRNG *rng) {
    if (rng->position >= 64) {
        uint32_t key[8], nonce[3];
        _memcpy(key, rng->key, 32);
        _memcpy(nonce, rng->iv, 12);
        chacha20_block(key, (uint32_t)rng->counter, nonce, (uint32_t *)rng->key_stream);
        rng->counter++;
        rng->position = 0;
    }
    uint32_t value;
    _memcpy(&value, rng->key_stream + rng->position, sizeof(value));
    rng->position += sizeof(value);
    return value;
}

/**
 * chacha20_init
 *
 * Initializes the ChaCha20 RNG using the provided seed.
 * The key and IV are derived via double SHA-256 hashing of the seed.
 */
void chacha20_init(ChaChaRNG *rng, const uint8_t *seed, size_t len) {
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(seed, (CC_LONG)len, hash);
    _memcpy(rng->key, hash, K);

    uint8_t iv_hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(hash, CC_SHA256_DIGEST_LENGTH, iv_hash);
    _memcpy(rng->iv, iv_hash, 12);

    rng->position = 64;
    rng->counter = ((uint64_t)time(NULL)) ^ getpid();
}

//===================================================================
/// UTILITY
//===================================================================

/**
 * A custom memory copy function that uses volatile pointers
 * for certain compiler optimizations.
 */
void _memcpy(void *dst, const void *src, size_t len) {
    volatile uint8_t *d = dst;
    const volatile uint8_t *s = src;
    while (len--)
        *d++ = *s++;
}

/**
 * Zeroes out memory at the given location.
 */
void zer(void *p, size_t len) {
    volatile uint8_t *x = p;
    while (len--)
        *x++ = 0;
}
