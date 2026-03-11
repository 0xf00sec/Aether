#ifndef AETHER_RSACRYPT_H
#define AETHER_RSACRYPT_H

#include <stdint.h>
#include <stddef.h>

/* rsa_init: init crypto, 0=ok */
int rsa_init(void);

/* rsa_load_pubkey: parse PEM, return handle or NULL */
void *rsa_load_pubkey(const uint8_t *pem, size_t pem_len);
void  rsa_free_pubkey(void *key);

/* rsa_seal: RSA+AES envelope encrypt
 * Wire: [4:ek_len][ek:RSA-OAEP-SHA256(aes||iv)][4:ct_len][ct:AES-128-CBC(data)] */
uint8_t *rsa_seal(const void *pubkey, const uint8_t *data, size_t data_len,
                  size_t *out_len);

#endif
