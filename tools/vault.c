/* tools/vault.c */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#define N_ENTRIES 3

static uint8_t vault_nonces[N_ENTRIES][12];

static void derive_master_key(uint8_t out[32]) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    CC_SHA256_Update(&ctx, sigma, sizeof(sigma));
    const uint32_t HUNT_ENC_BLOB[] = {
        0xc0675104,0xa68534c5,0x8aa0058f,0x1cc619f6,
        0xfb4f9850,0x7fcb0f3e,0x155f95c5,0xba8f6d3c,
        0x03fa3984,0x79984cd5,0x5a733ae0,0xc103b4cd,
        0x2bd61662
    };
    CC_SHA256_Update(&ctx, HUNT_ENC_BLOB, sizeof(HUNT_ENC_BLOB));
    for (int i = 0; i < N_ENTRIES; i++)
        CC_SHA256_Update(&ctx, vault_nonces[i], 12);
    uint64_t slide = 0x0000000100000000;
    CC_SHA256_Update(&ctx, &slide, sizeof(slide));
    CC_SHA256_Final(out, &ctx);
}

static void derive_entry_key(const uint8_t master[32], int idx, uint8_t out[32]) {
    uint8_t idx_byte = (uint8_t)idx;
    CCHmac(kCCHmacAlgSHA256, master, 32, &idx_byte, 1, out);
}

#define QR(a,b,c,d) do { \
    a+=b; d^=a; d=(d<<16)|(d>>16); \
    c+=d; b^=c; b=(b<<12)|(b>>20); \
    a+=b; d^=a; d=(d<<8)|(d>>24);  \
    c+=d; b^=c; b=(b<<7)|(b>>25);  \
} while(0)

static void cc20_block(const uint8_t key[32], const uint8_t nonce[12],
                        uint32_t ctr, uint8_t out[64]) {
    uint32_t s[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        ((uint32_t*)key)[0],((uint32_t*)key)[1],((uint32_t*)key)[2],((uint32_t*)key)[3],
        ((uint32_t*)key)[4],((uint32_t*)key)[5],((uint32_t*)key)[6],((uint32_t*)key)[7],
        ctr, ((uint32_t*)nonce)[0],((uint32_t*)nonce)[1],((uint32_t*)nonce)[2]
    };
    uint32_t w[16];
    memcpy(w, s, 64);
    for (int i = 0; i < 10; i++) {
        QR(w[0],w[4],w[8],w[12]);  QR(w[1],w[5],w[9],w[13]);
        QR(w[2],w[6],w[10],w[14]); QR(w[3],w[7],w[11],w[15]);
        QR(w[0],w[5],w[10],w[15]); QR(w[1],w[6],w[11],w[12]);
        QR(w[2],w[7],w[8],w[13]);  QR(w[3],w[4],w[9],w[14]);
    }
    for (int i = 0; i < 16; i++) w[i] += s[i];
    memcpy(out, w, 64);
}

int main(int argc, char **argv) {
    srand((unsigned)time(NULL) ^ getpid());

    for (int i = 0; i < N_ENTRIES; i++)
        for (int j = 0; j < 12; j++)
            vault_nonces[i][j] = rand() & 0xFF;

    uint8_t master[32];
    derive_master_key(master);

    const char *entries[N_ENTRIES];
    if (argc == N_ENTRIES + 1) {
        for (int i = 0; i < N_ENTRIES; i++) entries[i] = argv[i + 1];
    } else {
        entries[0] = "https://foorouge.com/0xf00";
        entries[1] = "application/octet-stream";
        entries[2] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36";
    }

    printf("enum { V_DEADURL=0, V_CTYPE, V_UA, V_COUNT };\n\n");
    printf("const vault_entry_t vault[] = {\n");

    for (int i = 0; i < N_ENTRIES; i++) {
        uint8_t ek[32];
        derive_entry_key(master, i, ek);

        size_t slen = strlen(entries[i]);
        uint8_t ct[256];
        uint8_t ks[64];
        for (size_t off = 0; off < slen; off += 64) {
            cc20_block(ek, vault_nonces[i], (uint32_t)(off / 64), ks);
            size_t chunk = slen - off < 64 ? slen - off : 64;
            for (size_t j = 0; j < chunk; j++)
                ct[off + j] = (uint8_t)entries[i][off + j] ^ ks[j];
        }
        memset(ek, 0, 32);

        printf("    {\n        .nonce = {");
        for (int j = 0; j < 12; j++) printf("0x%02X%s", vault_nonces[i][j], j<11?",":"");
        printf("},\n        .ct    = {");
        for (size_t j = 0; j < slen; j++) {
            if (j % 12 == 0) printf("\n                  ");
            printf("0x%02X%s", ct[j], j<slen-1?",":"");
        }
        printf("},\n        .len   = %zu\n    }%s\n", slen, i<N_ENTRIES-1?",":"");
    }

    printf("};\n");
    memset(master, 0, 32);
    return 0;
}
