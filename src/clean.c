#include <wisp.h>

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

void z0ro(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

//////////

/* void show_inst_changes(const uint8_t *before, const uint8_t *after, size_t len, uintptr_t base) {
    csh handle;
    cs_insn *insn1, *insn2;
    size_t count1, count2;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;

    count1 = cs_disasm(handle, before, len, base, 1, &insn1);
    count2 = cs_disasm(handle, after,  len, base, 1, &insn2);

    if (count1 > 0 && count2 > 0) {
        if (strcmp(insn1->mnemonic, insn2->mnemonic) != 0 ||
            strcmp(insn1->op_str, insn2->op_str) != 0) {
            dprintf(1, "@0x%lx: %s %s  ->  %s %s\n",
                base,
                insn1->mnemonic, insn1->op_str,
                insn2->mnemonic, insn2->op_str);
        }
    }

    cs_free(insn1, count1);
    cs_free(insn2, count2);
    cs_close(&handle);
}

void dump_meta_diff(const uint8_t *before, const uint8_t *after, size_t size, uintptr_t base) {
    for (size_t i = 0; i < size; ) {
        if (before[i] != after[i]) {
            size_t chunk = 16; // enough to capture one instruction
            show_inst_changes(before + i, after + i, chunk, base + i);
        }
        i++;
    }
}

void dump_bytes(const uint8_t *buf, size_t len, size_t max) {
    size_t n = len < max ? len : max;
    for (size_t i = 0; i < n; i++) {
        if (i % 16 == 0) write(1, "\n", 1);
        char tmp[4];
        int l = snprintf(tmp, sizeof(tmp), "%02x ", buf[i]);
        write(1, tmp, l);
    }
    write(1, "\n", 1);
}

void dump_diff(const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            char line[64];
            int l = snprintf(line, sizeof(line),
                             "@%zx: %02x -> %02x\n", i, a[i], b[i]);
            write(1, line, l);
        }
    }
} */