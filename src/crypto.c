#include "wisp.h"

//===================================================================
/// CCCryptorRef
//===================================================================

__attribute__((always_inline)) static inline CCCryptorRef create_cryptor(int enc,
                                                                          const uint8_t *key,
                                                                          const uint8_t *iv) {
    CCCryptorRef cryptor = NULL;
    CCCryptorStatus status = CCCryptorCreate(enc ? kCCEncrypt : kCCDecrypt,
                                             kCCAlgorithmAES,
                                             0,          
                                             key,          // key
                                             K,            // KSize
                                             iv,          
                                             &cryptor);
    return (status == kCCSuccess) ? cryptor : NULL;
}

//===================================================================
/// CCCryptor
//===================================================================

void crypt_payload(int enc, const uint8_t *key, const uint8_t *iv,
                   const uint8_t *in, uint8_t *out, size_t len) {
    CCCryptorRef cryptor = create_cryptor(enc, key, iv);
    if (!cryptor)
        return;

    size_t moved = 0;
    if (CCCryptorUpdate(cryptor, in, len, out, len, &moved) != kCCSuccess) {
        CCCryptorRelease(cryptor);
        return;
    }

    size_t finalBytes = 0;
    if (CCCryptorFinal(cryptor, out + moved, len - moved, &finalBytes) != kCCSuccess) {
        CCCryptorRelease(cryptor);
        return;
    }

    CCCryptorRelease(cryptor);
}
