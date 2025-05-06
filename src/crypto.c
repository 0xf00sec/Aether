#include <wisp.h>

/*-------------------------------------------
/// Encryption / Wrapping
-------------------------------------------*/
__attribute__((always_inline)) inline void crypt_payload(const int mode,
                                                         const uint8_t *key,
                                                         const uint8_t *iv,
                                                         const uint8_t *src,
                                                         uint8_t *dst,
                                                         const size_t size)
{
	CCCryptorRef ctx;
	if (CCCryptorCreate(mode ? kCCEncrypt : kCCDecrypt,
	                    kCCAlgorithmAES, 0, key, KEY_SIZE, iv, &ctx) != kCCSuccess)
		return;

	size_t written = 0;
	if (CCCryptorUpdate(ctx, src, size, dst, size, &written) != kCCSuccess)
		goto exit;

	CCCryptorFinal(ctx, dst + written, size - written, &written);

exit:
	CCCryptorRelease(ctx);
}