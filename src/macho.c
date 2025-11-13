#include <aether.h>

/*
 * Wrap mutated code into a valid Mach-O binary
 * https://github.com/aidansteele/osx-abi-macho-file-format-reference
 */

static macho_builder_t *
builder_init(size_t code_size)
{
    macho_builder_t *b = calloc(1, sizeof(*b));
    if (!b)
        return NULL;

    size_t hdr_sz      = sizeof(macho_header_t);
    size_t code_off    = ALIGN_P(hdr_sz);
    size_t code_sz_aln = ALIGN_P(code_size);
    size_t link_off    = code_off + code_sz_aln;
    size_t sym_sz      = 1024;
    size_t str_sz      = 1024;
    size_t link_sz     = sym_sz + str_sz;

    b->capacity   = link_off + link_sz;
    b->buffer     = calloc(1, b->capacity);
    if (!b->buffer) {
        free(b);
        return NULL;
    }

    b->size        = 0;
    b->header_size = hdr_sz;
    b->code_size   = code_size;

    DBG("  Header size: %zu bytes\n", hdr_sz);
    DBG("  Code offset: %zu bytes (page-aligned)\n", code_off);
    DBG("  Code size:   %zu bytes\n", code_size);
    return b;
}

static void
builder_free(macho_builder_t *b)
{
    if (!b)
        return;
    free(b->buffer);
    free(b);
}

static void
build_header(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    h->header.magic = MH_MAGIC_64;

#if defined(__x86_64__)
    h->header.cputype    = CPU_TYPE_X86_64;
    h->header.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
#elif defined(__aarch64__)
    h->header.cputype    = CPU_TYPE_ARM64;
    h->header.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
#else
    h->header.cputype    = CPU_TYPE_X86_64;
    h->header.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
#endif

    h->header.filetype = MH_EXECUTE;
    h->header.ncmds    = 6;
    h->header.flags    = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;

    size_t load_sz =
        sizeof(struct segment_command_64) +
        sizeof(struct segment_command_64) + sizeof(struct section_64) +
        sizeof(struct segment_command_64) +
        sizeof(struct symtab_command) +
        sizeof(struct dysymtab_command) +
        sizeof(struct entry_point_command);

    h->header.sizeofcmds = load_sz;

    DBG("cmds=%u, sizeofcmds=%u\n",
           h->header.ncmds, h->header.sizeofcmds);
}

static void
build_page0(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    strncpy(h->pagezero_segment.segname, "__PAGEZERO", 16);
    h->pagezero_segment.cmd      = LC_SEGMENT_64;
    h->pagezero_segment.cmdsize  = sizeof(struct segment_command_64);
    h->pagezero_segment.vmaddr   = 0;
    h->pagezero_segment.vmsize   = PS_64;
    h->pagezero_segment.fileoff  = 0;
    h->pagezero_segment.filesize = 0;
    h->pagezero_segment.maxprot  = 0;
    h->pagezero_segment.initprot = 0;
    h->pagezero_segment.nsects   = 0;
    h->pagezero_segment.flags    = 0;

    DBG("Built __PAGEZERO segment\n");
}

static void
build_text(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    size_t vmaddr   = PS_64;
    size_t fileoff  = 0;
    size_t code_off = ALIGN_P(b->header_size);
    size_t fsize    = code_off + ALIGN_P(b->code_size);

    b->code_offset = code_off;

    strncpy(h->text_segment.segname, "__TEXT", 16);
    h->text_segment.cmd      = LC_SEGMENT_64;
    h->text_segment.cmdsize  = sizeof(struct segment_command_64) + sizeof(struct section_64);
    h->text_segment.vmaddr   = vmaddr;
    h->text_segment.vmsize   = fsize;
    h->text_segment.fileoff  = fileoff;
    h->text_segment.filesize = fsize;
    h->text_segment.maxprot  = VM_PROT_READ | VM_PROT_EXECUTE;
    h->text_segment.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    h->text_segment.nsects   = 1;
    h->text_segment.flags    = 0;

    strncpy(h->text_section.sectname, "__text", 16);
    strncpy(h->text_section.segname, "__TEXT", 16);
    h->text_section.addr       = vmaddr + code_off;
    h->text_section.size       = b->code_size;
    h->text_section.offset     = code_off;
    h->text_section.align      = 4;
    h->text_section.reloff     = 0;
    h->text_section.nreloc     = 0;
    h->text_section.flags      = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
    h->text_section.reserved1  = 0;
    h->text_section.reserved2  = 0;
    h->text_section.reserved3  = 0;

    DBG("Built __TEXT segment (vmaddr=0x%llx, size=0x%llx)\n",
           h->text_segment.vmaddr, h->text_segment.vmsize);
}

static void
build_linkedit(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    size_t fileoff  = h->text_segment.fileoff + h->text_segment.filesize;
    size_t vmaddr   = h->text_segment.vmaddr + h->text_segment.vmsize;
    size_t size     = 2048;

    b->symtab_offset = fileoff;
    b->strtab_offset = fileoff + 1024;
    b->strtab_size   = 1024;

    strncpy(h->linkedit_segment.segname, "__LINKEDIT", 16);
    h->linkedit_segment.cmd      = LC_SEGMENT_64;
    h->linkedit_segment.cmdsize  = sizeof(struct segment_command_64);
    h->linkedit_segment.vmaddr   = vmaddr;
    h->linkedit_segment.vmsize   = ALIGN_P(size);
    h->linkedit_segment.fileoff  = fileoff;
    h->linkedit_segment.filesize = size;
    h->linkedit_segment.maxprot  = VM_PROT_READ;
    h->linkedit_segment.initprot = VM_PROT_READ;
    h->linkedit_segment.nsects   = 0;
    h->linkedit_segment.flags    = 0;

    DBG("Built __LINKEDIT segment (fileoff=0x%llx)\n",
           h->linkedit_segment.fileoff);
}

static void
build_symtab(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    h->symtab_cmd.cmd     = LC_SYMTAB;
    h->symtab_cmd.cmdsize = sizeof(struct symtab_command);
    h->symtab_cmd.symoff  = b->symtab_offset;
    h->symtab_cmd.nsyms   = 0;
    h->symtab_cmd.stroff  = b->strtab_offset;
    h->symtab_cmd.strsize = b->strtab_size;

    DBG("Built LC_SYMTAB command (nsyms=%u)\n", h->symtab_cmd.nsyms);
}

static void
build_dysymtab(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    memset(&h->dysymtab_cmd, 0, sizeof(h->dysymtab_cmd));
    h->dysymtab_cmd.cmd     = LC_DYSYMTAB;
    h->dysymtab_cmd.cmdsize = sizeof(struct dysymtab_command);

    DBG("Built LC_DYSYMTAB command\n");
}

static void
build_entry(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;

    h->entry_cmd.cmd      = LC_MAIN;
    h->entry_cmd.cmdsize  = sizeof(struct entry_point_command);
    h->entry_cmd.entryoff = b->code_offset;
    h->entry_cmd.stacksize = 0;

    DBG("Built LC_MAIN command (entryoff=0x%llx)\n",
           h->entry_cmd.entryoff);
}

static void
write_code(macho_builder_t *b, const uint8_t *code, size_t code_sz)
{
    if (code_sz != b->code_size)
        DBG("Code size mismatch (%zu vs %zu)\n", code_sz, b->code_size);

    size_t aligned = ALIGN_P(code_sz);
    if (b->code_offset + aligned > b->capacity) {
        DBG("Code offset: 0x%zx, aligned: 0x%zx, required: 0x%zx, capacity: 0x%zx\n",
               b->code_offset, aligned, b->code_offset + aligned, b->capacity);
        return;
    }

    memcpy(b->buffer + b->code_offset, code, code_sz);
    if (aligned > code_sz)
        memset(b->buffer + b->code_offset + code_sz, 0, aligned - code_sz);

    DBG("Wrote %zu bytes at 0x%zx (aligned to %zu)\n",
           code_sz, b->code_offset, aligned);
}

static void
init_symbol(macho_builder_t *b)
{
    b->buffer[b->strtab_offset] = '\0';
}

static size_t
calculate_fsz(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;
    return h->linkedit_segment.fileoff + h->linkedit_segment.filesize;
}

/* Validate the built structure */
static bool
macho_stuff(macho_builder_t *b)
{
    macho_header_t *h = (macho_header_t *)b->buffer;
    size_t end;

    if (h->header.magic != MH_MAGIC_64) goto fail;
#if defined(__x86_64__)
    if (h->header.cputype != CPU_TYPE_X86_64) goto fail;
#elif defined(__aarch64__)
    if (h->header.cputype != CPU_TYPE_ARM64) goto fail;
#endif
    if (h->header.filetype != MH_EXECUTE) goto fail;
    if (!h->header.ncmds || h->header.ncmds > 100) goto fail;

    end = sizeof(struct mach_header_64) + h->header.sizeofcmds;
    if (end > b->code_offset) goto fail;

    if (h->text_segment.fileoff % PS_64) goto fail;
    if (h->linkedit_segment.fileoff % PS_64) goto fail;
    if (h->text_segment.vmaddr < h->pagezero_segment.vmaddr + h->pagezero_segment.vmsize) goto fail;
    if (!(h->text_segment.initprot & VM_PROT_EXECUTE)) goto fail;
    if (h->text_segment.fileoff != 0) goto fail;

    if (h->text_section.offset < h->text_segment.fileoff ||
        h->text_section.offset + h->text_section.size >
        h->text_segment.fileoff + h->text_segment.filesize) goto fail;

    if (h->entry_cmd.entryoff < h->text_segment.fileoff ||
        h->entry_cmd.entryoff >= h->text_segment.fileoff + h->text_segment.filesize) goto fail;

    if (!b->code_size || b->code_size > 100 * 1024 * 1024) goto fail;

    DBG("[+] Validation passed\n");
    return true;

fail:
    return false;
}

/* Wrap code in minimal Mach-O structure */
uint8_t *
wrap_macho(const uint8_t *code, size_t code_sz, size_t *out_sz)
{
    if (!code || !code_sz || !out_sz) {
        DBG("Invalid parameters\n");
        return NULL;
    }
    if (code_sz > 100 * 1024 * 1024) {
        DBG("Code size too large (%zu bytes)\n", code_sz);
        return NULL;
    }

    macho_builder_t *b = builder_init(code_sz);
    if (!b) {
        DBG("Failed to initialize builder\n");
        return NULL;
    }

    build_header(b);
    build_page0(b);
    build_text(b);
    build_linkedit(b);
    build_symtab(b);
    build_dysymtab(b);
    build_entry(b);
    write_code(b, code, code_sz);
    init_symbol(b);

    if (!macho_stuff(b)) {
        DBG("Validation failed\n");
        builder_free(b);
        return NULL;
    }

    size_t final_sz = calculate_fsz(b);
    *out_sz = final_sz;

    uint8_t *res = b->buffer;
    b->buffer = NULL;

    builder_free(b);
    DBG("Built Mach-O (%zu bytes)\n", final_sz);
    return res;
}

/* Quick Mach-O validation */
bool
V_machO(const uint8_t *data, size_t size)
{
    if (!data || size < sizeof(struct mach_header_64))
        return false;

    const struct mach_header_64 *mh = (const struct mach_header_64 *)data;
    if (mh->magic != MH_MAGIC_64)
        return false;

#if defined(__x86_64__)
    if (mh->cputype != CPU_TYPE_X86_64)
        return false;
#elif defined(__aarch64__)
    if (mh->cputype != CPU_TYPE_ARM64)
        return false;
#endif

    if (mh->filetype != MH_EXECUTE &&
        mh->filetype != MH_DYLIB &&
        mh->filetype != MH_BUNDLE)
        return false;

    size_t cmd_sz = sizeof(*mh) + mh->sizeofcmds;
    return cmd_sz <= size;
}
