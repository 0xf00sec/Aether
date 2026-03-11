#include "sec.h"
#include <Security/Security.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonRandom.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

int rsa_init(void) { return 0; } /* no-op: Security.framework always available */

/* base64 decode */
static uint8_t *b64dec(const char *in, size_t in_len, size_t *out_len) {
    /* build decode table on stack */
    uint8_t t[256]; memset(t, 0xFF, 256);
    for (int i = 0; i < 26; i++) { t['A'+i] = i; t['a'+i] = 26+i; }
    for (int i = 0; i < 10; i++) t['0'+i] = 52+i;
    t['+'] = 62; t['/'] = 63;

    uint8_t *out = malloc((in_len * 3) / 4 + 4);
    if (!out) return NULL;
    size_t o = 0;
    uint32_t acc = 0; int bits = 0;
    for (size_t i = 0; i < in_len; i++) {
        uint8_t v = t[(uint8_t)in[i]];
        if (v == 0xFF) continue; /* skip whitespace, padding */
        acc = (acc << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (acc >> bits) & 0xFF; }
    }
    *out_len = o;
    return out;
}

/* PEM -> SecKeyRef */
void *rsa_load_pubkey(const uint8_t *pem, size_t pem_len) {
    /* find base64 content between PEM headers */
    const char *begin = strstr((const char *)pem, "BEGIN");
    if (!begin) return NULL;
    begin = strchr(begin, '\n');
    if (!begin) return NULL;
    begin++;
    const char *end = strstr(begin, "END");
    if (!end) return NULL;

    size_t der_len;
    uint8_t *der = b64dec(begin, end - begin, &der_len);
    if (!der) return NULL;

    CFDataRef keyData = CFDataCreate(NULL, der, der_len);
    free(der);

    CFMutableDictionaryRef attrs = CFDictionaryCreateMutable(NULL, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(attrs, kSecAttrKeyType, kSecAttrKeyTypeRSA);
    CFDictionarySetValue(attrs, kSecAttrKeyClass, kSecAttrKeyClassPublic);

    SecKeyRef key = SecKeyCreateWithData(keyData, attrs, NULL);
    CFRelease(keyData);
    CFRelease(attrs);
    return key;
}

void rsa_free_pubkey(void *key) {
    if (key) CFRelease((SecKeyRef)key);
}

/* Hybrid RSA+AES envelope */
uint8_t *rsa_seal(const void *pubkey, const uint8_t *data, size_t data_len,
                  size_t *out_len) {
    SecKeyRef key = (SecKeyRef)pubkey;

    /* Random AES-128 key + IV */
    uint8_t aes_key[16], iv[16];
    if (CCRandomGenerateBytes(aes_key, 16) != kCCSuccess) return NULL;
    if (CCRandomGenerateBytes(iv, 16) != kCCSuccess) return NULL;

    /* AES-128-CBC encrypt */
    size_t max_ct = data_len + kCCBlockSizeAES128;
    uint8_t *ct = malloc(max_ct);
    if (!ct) return NULL;
    size_t ct_len = 0;
    CCCryptorStatus cs = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                  aes_key, 16, iv, data, data_len, ct, max_ct, &ct_len);
    if (cs != kCCSuccess) { free(ct); return NULL; }

    /* RSA-OAEP encrypt: aes_key(16) || iv(16) = 32 bytes */
    uint8_t key_material[32];
    memcpy(key_material, aes_key, 16);
    memcpy(key_material + 16, iv, 16);
    memset(aes_key, 0, 16);

    CFDataRef km_data = CFDataCreate(NULL, key_material, 32);
    memset(key_material, 0, 32);
    CFDataRef ek_cf = SecKeyCreateEncryptedData(key, kSecKeyAlgorithmRSAEncryptionOAEPSHA256,
                                                 km_data, NULL);
    CFRelease(km_data);
    if (!ek_cf) { free(ct); return NULL; }

    size_t ek_len = CFDataGetLength(ek_cf);
    const uint8_t *ek = CFDataGetBytePtr(ek_cf);

    /* Wire: [4:ek_len][ek][4:ct_len][ct] */
    *out_len = 4 + ek_len + 4 + ct_len;
    uint8_t *out = malloc(*out_len);
    if (!out) { CFRelease(ek_cf); free(ct); return NULL; }

    uint8_t *p = out;
    uint32_t net;
    net = htonl((uint32_t)ek_len); memcpy(p, &net, 4); p += 4;
    memcpy(p, ek, ek_len);         p += ek_len;
    net = htonl((uint32_t)ct_len);  memcpy(p, &net, 4); p += 4;
    memcpy(p, ct, ct_len);

    CFRelease(ek_cf);
    free(ct);
    return out;
}
