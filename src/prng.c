#include <aether.h>

/* ChaCha20 quarter round ARX on 4 state words */
__attribute__((always_inline)) inline void QR(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8)  | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7)  | (*b >> 25);
}

/* ChaCha20 block 20 rounds (10 column + 10 diagonal) */
__attribute__((always_inline)) inline void chacha20_block(const uint32_t key[8], uint32_t counter,
                                                          const uint32_t nonce[3], uint32_t out[16]) {
    uint32_t state[16], orig[16];
    uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6B206574}; // "expand 32-byte k"

    memcpy(state, constants, sizeof(constants));
    memcpy(&state[4], key, 32);
    state[12] = counter;
    memcpy(&state[13], nonce, 12);
    memcpy(orig, state, sizeof(state));             

    for (int i = 0; i < 10; i++) {
        QR(&state[0], &state[4], &state[8],  &state[12]);
        QR(&state[1], &state[5], &state[9],  &state[13]);
        QR(&state[2], &state[6], &state[10], &state[14]);
        QR(&state[3], &state[7], &state[11], &state[15]);
        
        QR(&state[0], &state[5], &state[10], &state[15]);
        QR(&state[1], &state[6], &state[11], &state[12]);
        QR(&state[2], &state[7], &state[8],  &state[13]);
        QR(&state[3], &state[4], &state[9],  &state[14]);
    }

    for (int i = 0; i < 16; i++) out[i] = state[i] + orig[i];
}

/* Get next random u32 */
__attribute__((always_inline)) inline uint32_t chacha20_random(chacha_state_t *rng) {
    if (rng->position >= 64) {
        uint32_t key[8], nonce[3];
        memcpy(key, rng->key, 32);
        memcpy(nonce, rng->iv, 12);
        chacha20_block(key, (uint32_t)rng->counter, nonce, (uint32_t *)rng->stream);
        rng->counter++;
        rng->position = 0;
    }

    uint32_t value;
    memcpy(&value, rng->stream + rng->position, sizeof(value));
    rng->position += sizeof(value);
    return value;
}

/* Random int in [0, n-1] without modulo bias */
uint32_t rand_n(chacha_state_t *rng, uint32_t n) {
    if (n == 0) return 0;
    uint32_t x, lim = UINT32_MAX - (UINT32_MAX % n);
    do { x = chacha20_random(rng); } while (x >= lim);
    return x % n;
}

/* Seed PRNG with SHA256-derived key/nonce */
__attribute__((always_inline)) inline void chacha20_init(chacha_state_t *rng, const uint8_t *seed, size_t len) {
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];

    CC_SHA256(seed, (CC_LONG)len, hash);
    memcpy(rng->key, hash, K_SZ);

    uint8_t ivh[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(hash, CC_SHA256_DIGEST_LENGTH, ivh);
    memcpy(rng->iv, ivh, 12);

    rng->position = 64; // Force new block on first call

    uint64_t counter;
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(counter), &counter) != 0) {
        panic();
    }
    rng->counter = counter;
}
