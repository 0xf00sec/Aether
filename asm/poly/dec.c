#include "dec.h"

uint64_t derive_key(uint32_t generation, uint32_t seed) {
    /* Mix generation + seed with multiple rounds */
    uint64_t k = ((uint64_t)generation << 32) | seed;
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccdULL;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53ULL;
    k ^= k >> 33;
    return k;
}

void encrypt_text(uint8_t *code, size_t len, uint64_t key) {
    uint64_t *p = (uint64_t *)code;
    size_t n = len / 8;
    
    /* X0R stream derived from position */
    for (size_t i = 0; i < n; i++) {
        uint64_t k = key ^ (i * 0x9e3779b97f4a7c15ULL);
        k ^= k >> 27;
        k *= 0x3c79ac492ba7b653ULL;
        k ^= k >> 33;
        p[i] ^= k;
    }
    
    /* Handle remaining bytes */
    uint8_t *tail = (uint8_t *)(p + n);
    size_t rem = len % 8;
    if (rem) {
        uint64_t k = key ^ (n * 0x9e3779b97f4a7c15ULL);
        k ^= k >> 27;
        k *= 0x3c79ac492ba7b653ULL;
        k ^= k >> 33;
        for (size_t i = 0; i < rem; i++)
            tail[i] ^= (k >> (i * 8)) & 0xff;
    }
}

void decrypt_text(uint8_t *code, size_t len, uint64_t key) {
    /* XOR is symmetric */
    encrypt_text(code, len, key);
}
