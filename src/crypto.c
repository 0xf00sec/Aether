#include <aether.h>

/* AES encrypt/decrypt with PKCS7 padding */
__attribute__((always_inline))
size_t crypt_payload(const int mode, const uint8_t *key, const uint8_t *iv,
                     const uint8_t *src, uint8_t *dst, const size_t size) {
    CCCryptorRef ctx = NULL;
    CCCryptorStatus status = CCCryptorCreate(mode ? kCCEncrypt : kCCDecrypt, kCCAlgorithmAES,
                                             kCCOptionPKCS7Padding, key, K_SZ, iv, &ctx);
    if (status != kCCSuccess || ctx == NULL) return 0;

    size_t max_out = size + kCCBlockSizeAES128;
    uint8_t *tmp = (uint8_t*)malloc(max_out);
    if (!tmp) {
        CCCryptorRelease(ctx);
        return 0;
    }

    size_t written = 0;
    status = CCCryptorUpdate(ctx, src, size, tmp, max_out, &written);
    if (status != kCCSuccess) {
        free(tmp);
        CCCryptorRelease(ctx);
        return 0;
    }

    size_t finalWritten = 0;
    status = CCCryptorFinal(ctx, tmp + written, max_out - written, &finalWritten);
    if (status != kCCSuccess) {
        free(tmp);
        CCCryptorRelease(ctx);
        return 0;
    }

    size_t total = written + finalWritten;
    size_t to_copy = (total > size) ? size : total;
    if (to_copy > 0 && dst != NULL) memcpy(dst, tmp, to_copy);

    free(tmp);
    CCCryptorRelease(ctx);
    return to_copy;
}

size_t cipher(const uint8_t *key, const uint8_t *iv, const uint8_t *src, uint8_t *dst, const size_t size) {
    return crypt_payload(kCCEncrypt, key, iv, src, dst, size);
}

size_t decipher(const uint8_t *key, const uint8_t *iv, const uint8_t *src, uint8_t *dst, const size_t size) {
    return crypt_payload(kCCDecrypt, key, iv, src, dst, size);
}
