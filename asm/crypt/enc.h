#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#define AES_KEY_SIZE 16      /* AES-128 */
#define AES_IV_SIZE  16
#define SHA256_SIZE  32

void derive_aes_key(const uint8_t *stub_code, size_t stub_len,
                    uint64_t entropy,
                    uint8_t key[AES_KEY_SIZE],
                    uint8_t iv[AES_IV_SIZE]) __attribute__((visibility("hidden")));

/* Derive next generation key from previous key (key chain).
 * Uses HMAC-SHA256 for forward secrecy. */
void derive_next_key(const uint8_t prev_key[AES_KEY_SIZE],
                     uint32_t generation,
                     uint8_t next_key[AES_KEY_SIZE],
                     uint8_t next_iv[AES_IV_SIZE]) __attribute__((visibility("hidden")));

/* AES-128-CBC encrypt. Returns ciphertext size */
size_t aes_encrypt(const uint8_t *plaintext, size_t plain_len,
                   const uint8_t key[AES_KEY_SIZE],
                   const uint8_t iv[AES_IV_SIZE],
                   uint8_t **ciphertext) __attribute__((visibility("hidden")));

/* AES-128-CBC decrypt. Returns plaintext size. */
size_t aes_decrypt(const uint8_t *ciphertext, size_t cipher_len,
                   const uint8_t key[AES_KEY_SIZE],
                   const uint8_t iv[AES_IV_SIZE],
                   uint8_t **plaintext) __attribute__((visibility("hidden")));

#endif
