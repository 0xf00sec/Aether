#include <wisp.h>

__attribute__((always_inline)) inline int trim_newlines(uint8_t *buf, size_t len) {
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        if (buf[i] != '\n' && buf[i] != '\r') {
            buf[j++] = buf[i];
        }
    }
    return j;
}

__attribute__((always_inline)) inline int path_exists(const char *p) {
    if (access(p, F_OK) == 0) return 1;

    char *lower = strdup(p);
    for (int i = 0; lower[i]; i++) lower[i] = tolower(lower[i]);
    int exists = (access(lower, F_OK) == 0);
    free(lower);
    return exists;
}

__attribute__((always_inline)) inline char *trim_w1(char *str) {
    if (!str) return NULL;
    char *end;
    while (isspace((unsigned char)*str)) str++;
    if (*str == 0) return str;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = 0;
    return str;
}

__attribute__((always_inline)) inline char *decrypt_path(const uint8_t *key, const uint8_t *iv, const uint8_t *data, size_t len) {
    uint8_t *buf = malloc(len + 1);
    if (!buf) return NULL;

    decipher(key, iv, data, buf, len);
    buf[len] = '\0';
    return trim_w1((char *)buf);
}

__attribute__((always_inline)) int scan(void) {
    for (size_t i = 0; i < paths_count; i++) {
        const enc_vault_t *p = &paths[i];
        char *plain = decrypt_path(p->key, p->iv, p->data, p->len);
        if (!plain) continue;

        if (path_exists(plain)) {
            printf("[!]%s\n", plain);
            panic();
        }

        char home_path[PATH_MAX];
        snprintf(home_path, sizeof(home_path), "%s%s", getenv("HOME"), plain + 1);
        if (path_exists(home_path)) {
            panic();
        }
        free(plain);
    }
    return 0;
}
