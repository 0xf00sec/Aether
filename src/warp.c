#include "wisp.h"
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

//===================================================================
/// STRING & MEMORY 
//===================================================================

/**
 * Zero out a memory block.
 */
void _bzero(void *s, size_t n) {
    if (s)
        memset(s, 0, n);
}

/**
 * Write formatted data to a string.
 */
int _snprintf(char *str, size_t size, const char *format, ...) {
    if (!str || !format)
        return -1;

    int ret = 0;
    va_list args;
    va_start(args, format);
    ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

/**
 * Copy a string with a maximum limit.
 */
char* _strncpy(char *dest, const char *src, size_t n) {
    if (!dest || !src)
        return dest;
    return strncpy(dest, src, n);
}
