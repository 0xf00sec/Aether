#include <wisp.h>

void dump_bytes_fd(int out_fd, const uint8_t *buf, size_t len, size_t max) {
    size_t n = len < max ? len : max;
    for (size_t i = 0; i < n; i++) {
        if (i % 16 == 0) write(out_fd, "\n", 1);
        char tmp[4];
        int l = snprintf(tmp, sizeof(tmp), "%02x ", buf[i]);
        write(out_fd, tmp, l);
    }
    write(out_fd, "\n", 1);
}

void dump_diff_fd(int out_fd, const uint8_t *a, const uint8_t *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (a[i] != b[i]) {
            char line[64];
            int l = snprintf(line, sizeof(line),
                             "@%zx: %02x -> %02x\n", i, a[i], b[i]);
            write(out_fd, line, l);
        }
    }
}

void show_inst_changes_fd(int out_fd, const uint8_t *before, const uint8_t *after,
                          size_t len, uintptr_t base) {
    csh handle;
    cs_insn *insn1 = NULL, *insn2 = NULL;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;

    size_t count1 = cs_disasm(handle, before, len, base, 1, &insn1);
    size_t count2 = cs_disasm(handle, after,  len, base, 1, &insn2);

    if (count1 && count2) {
        if (strcmp(insn1->mnemonic, insn2->mnemonic) != 0 ||
            strcmp(insn1->op_str, insn2->op_str) != 0) {
            dprintf(out_fd, "@0x%lx: %s %s  ->  %s %s\n",
                    base,
                    insn1->mnemonic, insn1->op_str,
                    insn2->mnemonic, insn2->op_str);
        }
    }

    cs_free(insn1, count1);
    cs_free(insn2, count2);
    cs_close(&handle);
}

void dump_meta_diff_fd(int out_fd, const uint8_t *before, const uint8_t *after,
                       size_t size, uintptr_t base) {
    size_t i = 0;
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;

    while (i < size) {
        if (before[i] != after[i]) {
            cs_insn *insn = NULL;
            size_t count = cs_disasm(handle, before + i, size - i, base + i, 1, &insn);
            if (count > 0) {
                show_inst_changes_fd(out_fd, before + i, after + i, insn->size, base + i);
                i += insn->size;
                cs_free(insn, count);
                continue;
            }
        }
        i++;
    }

    cs_close(&handle);
}
