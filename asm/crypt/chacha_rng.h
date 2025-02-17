#ifndef CHACHA_RNG_H
#define CHACHA_RNG_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    uint8_t  key[32];
    uint8_t  iv[12];
    uint32_t stream[16];
    unsigned pos;      /* index into stream[] (0-15) */
    uint64_t counter;
} aether_rng_t;

static inline void chacha_qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d <<  8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b <<  7) | (*b >> 25);
}

static inline void chacha_block(aether_rng_t *r) {
    uint32_t s[16], o[16];
    static const uint32_t K[4] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    memcpy(s, K, 16);
    memcpy(s + 4, r->key, 32);
    s[12] = (uint32_t)r->counter;
    memcpy(s + 13, r->iv, 12);
    memcpy(o, s, 64);
    for (int i = 0; i < 10; i++) {
        chacha_qr(&s[0],&s[4],&s[8], &s[12]); chacha_qr(&s[1],&s[5],&s[9], &s[13]);
        chacha_qr(&s[2],&s[6],&s[10],&s[14]); chacha_qr(&s[3],&s[7],&s[11],&s[15]);
        chacha_qr(&s[0],&s[5],&s[10],&s[15]); chacha_qr(&s[1],&s[6],&s[11],&s[12]);
        chacha_qr(&s[2],&s[7],&s[8], &s[13]); chacha_qr(&s[3],&s[4],&s[9], &s[14]);
    }
    for (int i = 0; i < 16; i++) r->stream[i] = s[i] + o[i];
    r->counter++;
    r->pos = 0;
}

static inline uint32_t aether_rand(aether_rng_t *r) {
    if (r->pos >= 16) chacha_block(r);
    return r->stream[r->pos++];
}

/* [0, n) */
static inline uint32_t aether_rand_n(aether_rng_t *r, uint32_t n) {
    if (n <= 1) return 0;
    uint32_t lim = UINT32_MAX - (UINT32_MAX % n), x;
    do { x = aether_rand(r); } while (x >= lim);
    return x % n;
}

/* Seed from raw bytes */
static inline void aether_rng_seed(aether_rng_t *r, const void *seed, size_t len) {
    memset(r, 0, sizeof(*r));
    if (len > 32) len = 32;
    memcpy(r->key, seed, len);
    /* Derive IV from key by one extra ChaCha block */
    r->counter = 0;
    r->pos = 16; /* force block generation */
    uint32_t tmp[4];
    for (int i = 0; i < 4; i++) tmp[i] = aether_rand(r);
    memcpy(r->iv, tmp, 12);
    r->counter = 1;
    r->pos = 16;
}

static inline void aether_rng_init(aether_rng_t *r) {uint8_t entropy[32];arc4random_buf(entropy, 32);aether_rng_seed(r, entropy, 32);}
#endif
