#include "wisp.h"

extern struct mach_header_64 _mh_execute_header;

//===================================================================
///  HELPER
//===================================================================

/**
 * Locate the __fdata section in the __DATA segment.
 */
static bool get_fdata_offset(struct mach_header_64 *header, uint64_t *offset, size_t *section_size) {
    struct load_command *lc = (struct load_command *)((char *)header + sizeof(*header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec = (struct section_64 *)((char *)seg + sizeof(*seg));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (!strcmp(sec[j].sectname, "__fdata") && !strcmp(sec[j].segname, "__DATA")) {
                    *offset = sec[j].offset;
                    *section_size = sec[j].size;
                    return true;
                }
            }
        }
        lc = (struct load_command *)((char *)lc + lc->cmdsize);
    }
    return false;
}

//===================================================================
/// SAVE
//===================================================================

/**
 * Save data into the __fdata section of the current executable.
 */
void save(uint8_t *data, size_t sz) {
    char path[1024] = {0};
    uint32_t path_size = sizeof(path);
    
    // Retrieve the executable's path.
    if (_NSGetExecutablePath(path, &path_size) != 0)
        return;
    
    int fd = open(path, O_RDWR);
    if (fd < 0)
        return;
    
    struct mach_header_64 *header = &_mh_execute_header;
    uint64_t offset = 0;
    size_t sect_size = 0;
    if (!get_fdata_offset(header, &offset, &sect_size)) {
        fprintf(stderr, "Section not found\n");
        close(fd);
        return;
    }
    
    if (sz > sect_size) {
        fprintf(stderr, "Got %zu bytes, only have %zu bytes\n", sz, sect_size);
        close(fd);
        return;
    }
    
    if (lseek(fd, offset, SEEK_SET) == -1) {
        close(fd);
        return;
    }
    
    size_t total_written = 0;
    while (total_written < sz) {
        ssize_t written = write(fd, data + total_written, sz - total_written);
        if (written <= 0)
            break;
        total_written += written;
    }
    
    if (total_written != sz)
        close(fd);
    else
        close(fd);
}

/**
/**
 * Capstone to disassemble the code and scans for instructions
 * that belong to the privileged instruction group. 
 * This is a basic validation routine that does not account for all edge cases, which may render
 * it unreliable and to kill.
 */
bool check_priv(uint8_t *code, size_t sz) {
    csh handle;
    cs_insn *insn = NULL;
    bool priv_found = false;
    
    if (cs_open(TARGET_ARCH, TARGET_MODE, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Cap failed\n");
        return true;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    size_t count = cs_disasm(handle, code, sz, (uintptr_t)code, 0, &insn);
    if (count > 0) {
#ifdef ARCH_X86
        for (size_t i = 0; i < count; i++) {
            cs_detail *d = insn[i].detail;
            for (size_t j = 0; j < d->groups_count; j++) {
                if (d->groups[j] == CS_GRP_PRIVILEGE) {
                    fprintf(stderr, "Bingo: %s %s\n", insn[i].mnemonic, insn[i].op_str);
                    priv_found = true;
                    break;
                }
            }
            if (priv_found)
                break;
        }
#endif
    } else {
        fprintf(stderr, "Disassa failed\n");
        priv_found = true;
    }
    
    cs_free(insn, count);
    cs_close(&handle);
    return priv_found;
}

/**
 * Execute code residing in memory.
 */
void execute(uint8_t *code, size_t sz) {
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t addr = (uintptr_t)code;
    uintptr_t start = addr & ~(page_size - 1);
    size_t offset = addr - start;
    size_t total = offset + sz;
    size_t aligned_size = (total + page_size - 1) & ~(page_size - 1);
    
    if (mprotect((void *)start, aligned_size, PROT_READ | PROT_EXEC) != 0) {
        perror("mprotect");
        return;
    }
    
#if defined(__arm__) || defined(__aarch64__)
    __builtin___clear_cache((char *)code, (char *)code + sz);
#endif
    
    if (check_priv(code, sz))
        return;
    
    void (*fn)(void) = (void (*)(void))code;
    fn();
}
