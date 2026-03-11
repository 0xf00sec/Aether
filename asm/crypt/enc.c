#include "enc.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#include <string.h>

void derive_aes_key(const uint8_t *stub_code, size_t stub_len,
                    uint64_t entropy,
                    uint8_t key[AES_KEY_SIZE],
                    uint8_t iv[AES_IV_SIZE]) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, stub_code, (CC_LONG)stub_len);
    CC_SHA256_Update(&ctx, &entropy, sizeof(entropy));
    
    uint8_t hash[SHA256_SIZE];
    CC_SHA256_Final(hash, &ctx);
    
    memcpy(key, hash, AES_KEY_SIZE);
    memcpy(iv, hash + AES_KEY_SIZE, AES_IV_SIZE);
}

void derive_next_key(const uint8_t prev_key[AES_KEY_SIZE],
                     uint32_t generation,
                     uint8_t next_key[AES_KEY_SIZE],
                     uint8_t next_iv[AES_IV_SIZE]) {
    /* HMAC-SHA256(prev_key, generation) */
    uint8_t hmac[SHA256_SIZE];
    CCHmac(kCCHmacAlgSHA256, prev_key, AES_KEY_SIZE,
           &generation, sizeof(generation), hmac);
    
    memcpy(next_key, hmac, AES_KEY_SIZE);
    memcpy(next_iv, hmac + AES_KEY_SIZE, AES_IV_SIZE);
}

size_t aes_encrypt(const uint8_t *plaintext, size_t plain_len,
                   const uint8_t key[AES_KEY_SIZE],
                   const uint8_t iv[AES_IV_SIZE],
                   uint8_t **ciphertext) {
    size_t max_out = plain_len + kCCBlockSizeAES128;
    *ciphertext = malloc(max_out);
    if (!*ciphertext) return 0;
    
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key, AES_KEY_SIZE,
        iv,
        plaintext, plain_len,
        *ciphertext, max_out,
        &moved
    );
    
    if (status != kCCSuccess) {
        free(*ciphertext);
        *ciphertext = NULL;
        return 0;
    }
    
    return moved;
}

size_t aes_decrypt(const uint8_t *ciphertext, size_t cipher_len,
                   const uint8_t key[AES_KEY_SIZE],
                   const uint8_t iv[AES_IV_SIZE],
                   uint8_t **plaintext) {
    *plaintext = malloc(cipher_len);
    if (!*plaintext) return 0;
    
    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionPKCS7Padding,
        key, AES_KEY_SIZE,
        iv,
        ciphertext, cipher_len,
        *plaintext, cipher_len,
        &moved
    );
    
    if (status != kCCSuccess) {
        free(*plaintext);
        *plaintext = NULL;
        return 0;
    }
    
    return moved;
}
