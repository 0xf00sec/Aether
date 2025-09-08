#include <wisp.h>


/*-------------------------------------------
///        ChaCha20 rng                      
-------------------------------------------*/
static inline void QR(uint32_t state[16], int a, int b, int c, int d) {
    state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 16) | (state[d] >> 16);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 12) | (state[b] >> 20);
    state[a] += state[b]; state[d] ^= state[a]; state[d] = (state[d] << 8) | (state[d] >> 24);
    state[c] += state[d]; state[b] ^= state[c]; state[b] = (state[b] << 7) | (state[b] >> 25);
}

void chacha20_block(const uint32_t *key, uint32_t counter, const uint32_t *nonce, uint32_t *out) {
    uint32_t state[16], orig[16];
    const uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6B206574};

    memcpy(state, constants, sizeof(constants));
    memcpy(&state[4], key, 8 * sizeof(uint32_t));
    state[12] = counter;
    memcpy(&state[13], nonce, 3 * sizeof(uint32_t));
    memcpy(orig, state, sizeof(state));

    for (int i = 0; i < 10; i++) {
        QR(state, 0, 4, 8, 12);
        QR(state, 1, 5, 9, 13);
        QR(state, 2, 6, 10, 14);
        QR(state, 3, 7, 11, 15);
        QR(state, 0, 5, 10, 15);
        QR(state, 1, 6, 11, 12);
        QR(state, 2, 7, 8, 13);
        QR(state, 3, 4, 9, 14);
    }

    for (int i = 0; i < 16; i++)
        out[i] = state[i] + orig[i];
}

uint32_t chacha20_random(chacha_state_t *rng) {
    if (!rng) return 0;

    if (rng->position >= STRM__) {
        chacha20_block(rng->key, rng->counter, rng->iv, (uint32_t *)rng->stream);
        rng->counter++;
        rng->position = 0;
    }

    uint32_t val;
    memcpy(&val, rng->stream + rng->position, sizeof(val));
    rng->position += sizeof(val);
    return val;
}

uint32_t rand_n(chacha_state_t *rng, uint32_t n) {
    if (!rng || n == 0) return 0;
    uint32_t x, lim = UINT32_MAX - (UINT32_MAX % n);
    do { x = chacha20_random(rng); } while (x >= lim);
    return x % n;
}

void chacha20_init(chacha_state_t *rng, const uint8_t *seed, size_t len) {
    if (!rng || !seed) return;
    if (len > 4096) len = 4096;

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    uint8_t ivh[CC_SHA256_DIGEST_LENGTH];

    CC_SHA256(seed, (CC_LONG)len, digest);
    memcpy(rng->key, digest, sizeof(rng->key));

    CC_SHA256(digest, CC_SHA256_DIGEST_LENGTH, ivh);
    memcpy(rng->iv, ivh, sizeof(rng->iv));

    memset(rng->stream, 0, sizeof(rng->stream));
    rng->position = STRM__; 

    uint32_t ctr = 0;
    if (SecRandomCopyBytes(kSecRandomDefault, sizeof(ctr), &ctr) != 0) {
        memcpy(&ctr, ivh, sizeof(ctr));
    }
    rng->counter = ctr;
}
