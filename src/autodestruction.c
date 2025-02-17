#include "wisp.h"

//===================================================================
/// WIPER?
//===================================================================

/**
 * fill
 * Depending on the pattern type, overwritten with zeros,
 * ones, random bytes, or a custom byte value.
 */
__attribute__((always_inline)) 
static inline void fill(unsigned char *buffer, size_t size,
                        wipe_pattern_t pattern, unsigned char custom) {
    switch (pattern) {
        case ZERO:
            memset(buffer, 0x00, size);
            break;
        case ONE:
            memset(buffer, 0xFF, size);
            break;
        case RAND:
            for (size_t i = 0; i < size; i++) {
                buffer[i] = rand() % 256;
            }
            break;
        case CUST:
            memset(buffer, custom, size);
            break;
    }
}

/**
 * overwrite
 */
__attribute__((always_inline)) 
static inline int overwrite(const char *filename, const wipe_config_t *config) {
    struct stat st;
    if (stat(filename, &st) != 0) {
        return -1;
    }
    size_t size = (size_t)st.st_size;
    if (size == 0) { // Nothing to wipe; just remove.
        unlink(filename);
        return 0;
    }

    unsigned char *buffer = malloc(size);
    if (!buffer) {
        return -1;
    }

    FILE *fp = fopen(filename, "r+");
    if (!fp) {
        free(buffer);
        return -1;
    }

    for (int pass = 0; pass < config->passes; pass++) {
        fill(buffer, size, config->patterns[pass], config->custom);
        rewind(fp);
        size_t written = 0;
        while (written < size) {
            size_t chunk = ((size - written) > 4096) ? 4096 : (size - written);
            size_t bytes = fwrite(buffer + written, 1, chunk, fp);
            if (bytes != chunk) {
                fclose(fp);
                free(buffer);
                return -1;
            }
            written += bytes;
        }
        fflush(fp);
        fsync(fileno(fp));
    }

    fclose(fp);
    free(buffer);

    if (unlink(filename) != 0) {
        return -1;
    }
    return 0;
}

/**
 * SelfDelete
 */
__attribute__((always_inline)) 
static inline int selfDes(const char *filepath) {
    srand((unsigned int)time(NULL));

    int passes = 7;
    wipe_pattern_t *patterns = malloc(sizeof(wipe_pattern_t) * passes);
    if (!patterns)
        return -1;

    // random for all but the final pass.
    for (int i = 0; i < passes - 1; i++) {
        patterns[i] = RAND;
    }
    // Final pass: wipe with zeros.
    patterns[passes - 1] = ZERO;

    wipe_config_t config = {
        .passes = passes,
        .patterns = patterns,
        .custom = 0
    };

    int ret = overwrite(filepath, &config);
    free(patterns);
    return ret;
}

//===================================================================
/// API
//===================================================================

/**
 * autodes
 */
int autodes(void) {
    char exePath[1024] = {0};
    uint32_t bufsize = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &bufsize) != 0) {
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return -1;
    } else if (pid == 0) {
        execl(exePath, exePath, "--selfdestruct", (char *)NULL);
        exit(EXIT_FAILURE);
    }
    return 0;
}

/**
 * destruct_mode
 */
void destruct_mode(void) {
    char exePath[1024] = {0};
    uint32_t bufsize = sizeof(exePath);
    if (_NSGetExecutablePath(exePath, &bufsize) != 0) {
        exit(EXIT_FAILURE);
    }
    
    selfDes(exePath);  // wipe the binary.
    sleep(1);
    exit(EXIT_SUCCESS);
}
