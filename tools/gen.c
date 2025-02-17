#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#define QR(a,b,c,d) do { \
    a+=b; d^=a; d=(d<<16)|(d>>16); \
    c+=d; b^=c; b=(b<<12)|(b>>20); \
    a+=b; d^=a; d=(d<<8)|(d>>24);  \
    c+=d; b^=c; b=(b<<7)|(b>>25);  \
} while(0)

static void chacha_block(const uint8_t key[32], const uint8_t nonce[12],
                          uint32_t counter, uint8_t out[64]) {
    uint32_t s[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        ((uint32_t*)key)[0], ((uint32_t*)key)[1], ((uint32_t*)key)[2], ((uint32_t*)key)[3],
        ((uint32_t*)key)[4], ((uint32_t*)key)[5], ((uint32_t*)key)[6], ((uint32_t*)key)[7],
        counter,
        ((uint32_t*)nonce)[0], ((uint32_t*)nonce)[1], ((uint32_t*)nonce)[2]
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

static void randbytes(uint8_t *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) { read(fd, buf, n); close(fd); }
}

static void derive_vault_key(uint8_t out[32]) {
    uint32_t s[8] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0xFEEDFACF, 0x00004000, 0x00000019, 0x80000028,
    };
    for (int r = 0; r < 16; r++) {
        #define KMIX(a,b,c,d) \
            s[a]+=s[b]; s[d]^=s[a]; s[d]=(s[d]<<16)|(s[d]>>16); \
            s[c]+=s[d]; s[b]^=s[c]; s[b]=(s[b]<<12)|(s[b]>>20); \
            s[a]+=s[b]; s[d]^=s[a]; s[d]=(s[d]<<8)|(s[d]>>24);  \
            s[c]+=s[d]; s[b]^=s[c]; s[b]=(s[b]<<7)|(s[b]>>25);
        KMIX(0,2,4,6) KMIX(1,3,5,7)
        KMIX(0,3,6,5) KMIX(1,2,7,4)
        #undef KMIX
    }
    memcpy(out, s, 32);
}

static void print_hex(const uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (i && i % 12 == 0) printf("\n             ");
        printf("0x%02X", d[i]);
        if (i + 1 < n) printf(",");
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s \"string1\" \"string2\" ...\n", argv[0]);
        return 1;
    }

    printf("static const vault_entry_t vault[] = {\n");

    for (int i = 1; i < argc; i++) {
        const char *s = argv[i];
        size_t slen = strlen(s);
        if (slen > 255) { fprintf(stderr, "string too long: %s\n", s); continue; }

        uint8_t nonce[12];
        randbytes(nonce, 12);

        uint8_t dk[32]; derive_vault_key(dk);
        uint8_t ct[256] = {0};
        uint8_t ks[64];
        for (size_t off = 0; off < slen; off += 64) {
            chacha_block(dk, nonce, (uint32_t)(off / 64), ks);
            size_t chunk = slen - off < 64 ? slen - off : 64;
            for (size_t j = 0; j < chunk; j++)
                ct[off + j] = (uint8_t)s[off + j] ^ ks[j];
        }
        memset(dk, 0, 32);

        printf("    {\n");
        printf("        .nonce = {"); print_hex(nonce, 12); printf("},\n");
        printf("        .ct    = {"); print_hex(ct, slen); printf("},\n");
        printf("        .len   = %zu\n", slen);
        printf("    }%s\n", i < argc - 1 ? "," : "");
    }

    printf("};\n");
    return 0;
}
