#include <wisp.h>

#if defined(__x86_64__)
__attribute__((always_inline)) inline void O2(void *dest, const void *src, size_t n) {
    __asm__ volatile (
        "rep movsb"
        : "=D"(dest), "=S"(src), "=c"(n)
        : "0"(dest), "1"(src), "2"(n)
        : "memory"
    );
}
#else
    memcpy(dest, src, n);
#endif

__attribute__((always_inline)) inline void zer0(void *ptr, size_t n) {
    memset(ptr, 0, n);
    __asm__ volatile ("" : : "r"(ptr) : "memory");
}

__attribute__((always_inline)) inline int oprw(const char *path) {
    return open(path, O_RDWR, 0);
}

__attribute__((always_inline)) inline void clso(int fd) {
    close(fd);
}

__attribute__((always_inline)) inline int reset(int fd) {
    return lseek(fd, 0, SEEK_SET);
}

__attribute__((always_inline)) inline int wrby(int fd, unsigned char *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t bytes = write(fd, buf + written, len - written);
        if (bytes <= 0) return -1;
        written += (size_t)bytes;
    }
    return 0;
}

__attribute__((always_inline)) inline int find_self(char *out, uint32_t *size) {
    return _NSGetExecutablePath(out, size);
}

__attribute__((always_inline)) inline int _snprintf(char *str, size_t size, const char *format, ...) {
    if (!str || !format) return -1;
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

__attribute__((always_inline)) inline char* _strncpy(char *dest, const char *src, size_t n) {
    if (!dest || !src) return dest;
    return strncpy(dest, src, n);
}

__attribute__((always_inline)) inline void hexdump(const uint8_t *data, size_t len, const char *label) {
    size_t dump_len = len < 256 ? len : 256;
    DBG("%s (first %zu bytes):", label, dump_len);
    for (size_t i = 0; i < dump_len; i += 16) {
        char buf[128]; size_t pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - pos, "%08zx  ", i);
        for (size_t j = 0; j < 16 && i + j < dump_len; j++) 
            pos += snprintf(buf + pos, sizeof(buf)-pos, "%02x ", data[i+j]);
        pos += snprintf(buf + pos, sizeof(buf)-pos, " |");
        for (size_t j = 0; j < 16 && i + j < dump_len; j++) {
            uint8_t c = data[i+j];
            pos += snprintf(buf + pos, sizeof(buf)-pos, "%c", (c >= 32 && c <= 126) ? c : '.');
        }
        strncat(buf, "|", sizeof(buf)-strlen(buf)-1);
        DBG("%s", buf);
    }
}