#include <wisp.h>

/*-------------------------------------------
///         Encryption / Wrapping                       
-------------------------------------------*/
__attribute__((always_inline)) 
size_t crypt_payload(const int mode,
                            const uint8_t *key,
                            const uint8_t *iv,
                            const uint8_t *src,
                            uint8_t *dst,
                            const size_t size)
{
    CCCryptorRef ctx;
    CCCryptorStatus status = CCCryptorCreate(mode ? kCCEncrypt : kCCDecrypt,
                                            kCCAlgorithmAES, 
                                            kCCOptionPKCS7Padding,
                                            key, KEY_SIZE, 
                                            iv, &ctx);
    if (status != kCCSuccess)
        return 0;

    size_t written = 0;
    size_t max_out = size + IV_SIZE; 
    
    status = CCCryptorUpdate(ctx, src, size, dst, max_out, &written);
    if (status != kCCSuccess) {
        CCCryptorRelease(ctx);
        return 0;
    }

    size_t finalWritten;
    status = CCCryptorFinal(ctx, dst + written, max_out - written, &finalWritten);
    if (status != kCCSuccess) {
        CCCryptorRelease(ctx);
        return 0;
    }

    written += finalWritten;
    CCCryptorRelease(ctx);
    return written;
}