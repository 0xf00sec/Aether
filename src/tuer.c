#include <aether.h>
#include <sys/mman.h>
#include <fcntl.h>

// Fill buffer with wipe pattern
static void f_buffer(unsigned char *buf, size_t len, wipe_pattern_t pattern, unsigned char custom) {
    switch (pattern) {
        case WIPE_ZERO:   
            memset(buf, 0x00, len); 
            break;
        case WIPE_ONE:    
            memset(buf, 0xFF, len); 
            break;
        case WIPE_RANDOM: 
            for (size_t i = 0; i < len; i++) 
                buf[i] = arc4random_uniform(256); 
            break;
        case WIPE_CUSTOM: 
            memset(buf, custom, len); 
            break;
    }
}

// Overwrite 
static int w_file(int fd, unsigned char *buf, size_t len, const wipe_conf_t *config) {
    for (int pass = 0; pass < config->passes; pass++) {
        f_buffer(buf, len, config->patterns[pass], config->custom);
        
        if (lseek(fd, 0, SEEK_SET) == -1) return -1;
        if (write(fd, buf, len) != (ssize_t)len) return -1;
        if (fsync(fd) != 0) return -1;
    }
    return 0;
}

/**
 * Corrupts magic number and random offsets in header.
 * Makes binary unloadable before wiping.
 */
static int corrupt_macho(int fd) {
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 4096) return -1;

    unsigned char *header = mmap(NULL, 4096, PROT_READ | PROT_WRITE, 
                                 MAP_ANON | MAP_PRIVATE, -1, 0);
    if (header == MAP_FAILED) return -1;

    if (pread(fd, header, 4096, 0) != 4096) goto cleanup;

    // Corrupt magic number
    uint32_t rnd = arc4random_uniform(0xFFFFFFFF);
    memcpy(header, &rnd, sizeof(rnd));

    // Corrupt random offsets
    for (int i = 0; i < 16; i++) {
        size_t off = arc4random_uniform(4096 - sizeof(uint32_t));
        rnd = arc4random_uniform(0xFFFFFFFF);
        memcpy(header + off, &rnd, sizeof(rnd));
    }

    if (pwrite(fd, header, 4096, 0) != 4096) goto cleanup;
    fsync(fd);

cleanup:
    {
        volatile unsigned char *vp = (volatile unsigned char *)header;
        for (size_t i = 0; i < 4096; i++) {
            vp[i] = 0;
        }
    }
    munmap(header, 4096);
    return 0;
}

static int _nuke(const char *path, const wipe_conf_t *config) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    size_t sz = (size_t)st.st_size;
    if (!sz) return unlink(path);

    unsigned char *buf = mmap(NULL, sz, PROT_READ | PROT_WRITE, 
                              MAP_ANON | MAP_PRIVATE, -1, 0);
    if (buf == MAP_FAILED) return -1;

    mlock(buf, sz);

    int fd = open(path, O_RDWR);
    if (fd < 0) { 
        munlock(buf, sz);
        munmap(buf, sz); 
        return -1; 
    }

    int res = w_file(fd, buf, sz, config);
    close(fd);

    volatile unsigned char *vp = (volatile unsigned char *)buf;
    for (size_t i = 0; i < sz; i++) {
        vp[i] = 0;
    }
    
    munlock(buf, sz);
    munmap(buf, sz);

    if (res != 0) return -1;
    return unlink(path);
}

static wipe_conf_t *prep_nuker(int passes) {
    wipe_conf_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) return NULL;

    cfg->patterns = malloc(sizeof(wipe_pattern_t) * passes);
    if (!cfg->patterns) { 
        free(cfg); 
        return NULL; 
    }

    // Just random data - fast and good enough
    for (int i = 0; i < passes; i++) {
        cfg->patterns[i] = WIPE_RANDOM;
    }
    cfg->passes = passes;
    cfg->custom = 0;

    return cfg;
}

static void _burn(wipe_conf_t *cfg) {
    if (cfg) {
        free(cfg->patterns);
        free(cfg);
    }
}

static int _self(const char *path) {
    int passes = 1;
    wipe_conf_t *cfg = prep_nuker(passes);
    if (!cfg) return -1;

    int fd = open(path, O_RDWR);
    if (fd >= 0) {
        corrupt_macho(fd);
        close(fd);
    }

    // Quick wipe and unlink
    int r = _nuke(path, cfg);
    _burn(cfg);
    return r;
}

/**
 * Forks child to wipe binary, parent exits immediately.
 * in <1 second.
 */
void k_ill(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) != 0) {
        exit(EXIT_FAILURE);
    }

    pid_t parent_pid = getpid();
    pid_t pid = fork();
    
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    
    if (pid == 0) {
        // Child wait briefly, then wipe
        usleep(500000); 
        
        // Quick check if parent is dead
        if (kill(parent_pid, 0) != 0) {
            _self(path);
        }
        exit(EXIT_SUCCESS);
    }
    
    // Parent exits immediately
    exit(EXIT_SUCCESS);
}

/**
 * Wipes self and exits.
 */
__attribute__((noreturn)) void panic(void) {
    k_ill();
    __builtin_unreachable();
}