#include <aether.h>

/**
 * Wraps mutated code into valid Mach-O binary
 * Mutated code, making it loadable by our loader.
 *  https://github.com/aidansteele/osx-abi-macho-file-format-reference
 */

static macho_builder_t* builder_init(size_t code_size) {
    macho_builder_t *builder = calloc(1, sizeof(macho_builder_t));
    if (!builder) return NULL;
    
    // Calculate
    size_t header_size = sizeof(macho_header_t);
    size_t code_offset = ALIGN_PAGE(header_size);  // This is where code actually starts
    size_t aligned_code_size = ALIGN_PAGE(code_size);
    size_t linkedit_offset = code_offset + aligned_code_size;
    size_t symtab_size = 1024;  // symbols
    size_t strtab_size = 1024;  // strings
    size_t linkedit_size = symtab_size + strtab_size;
    
    builder->capacity = linkedit_offset + linkedit_size;
    builder->buffer = calloc(1, builder->capacity);
    
    if (!builder->buffer) {
        free(builder);
        return NULL;
    }
    
    builder->size = 0;
    builder->header_size = header_size;
    builder->code_size = code_size;
    
    printf("  Header size: %zu bytes\n", header_size);
    printf("  Code offset: %zu bytes (page-aligned)\n", code_offset);
    printf("  Code size: %zu bytes\n", code_size);
    
    return builder;
}

static void builder_free(macho_builder_t *builder) {
    if (!builder) return;
    free(builder->buffer);
    free(builder);
}

static void build_header(macho_builder_t *builder) {
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    // Mach-O header
    hdr->header.magic = MH_MAGIC_64;
    
#if defined(__x86_64__)
    hdr->header.cputype = CPU_TYPE_X86_64;
    hdr->header.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
#elif defined(__aarch64__)
    hdr->header.cputype = CPU_TYPE_ARM64;
    hdr->header.cpusubtype = CPU_SUBTYPE_ARM64_ALL;
#else
    hdr->header.cputype = CPU_TYPE_X86_64;
    hdr->header.cpusubtype = CPU_SUBTYPE_X86_64_ALL;
#endif
    
    hdr->header.filetype = MH_EXECUTE;
    hdr->header.ncmds = 6;  // PAGEZERO, TEXT, LINKEDIT, SYMTAB, DYSYMTAB, MAIN
    hdr->header.flags = MH_NOUNDEFS | MH_DYLDLINK | MH_TWOLEVEL | MH_PIE;
    
    size_t load_cmds_size = 
        sizeof(struct segment_command_64) +  // PAGEZERO
        sizeof(struct segment_command_64) + sizeof(struct section_64) +  // TEXT
        sizeof(struct segment_command_64) +  // LINKEDIT
        sizeof(struct symtab_command) +
        sizeof(struct dysymtab_command) +
        sizeof(struct entry_point_command);
    
    hdr->header.sizeofcmds = load_cmds_size;
    
    printf("cmds=%u, sizeofcmds=%u \n", 
        hdr->header.ncmds, hdr->header.sizeofcmds);
}

static void build_page0(macho_builder_t *builder) { 
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    strncpy(hdr->pagezero_segment.segname, "__PAGEZERO", 16);
    hdr->pagezero_segment.cmd = LC_SEGMENT_64;
    hdr->pagezero_segment.cmdsize = sizeof(struct segment_command_64);
    hdr->pagezero_segment.vmaddr = 0;
    hdr->pagezero_segment.vmsize = PAGE_SIZE_64;
    hdr->pagezero_segment.fileoff = 0;
    hdr->pagezero_segment.filesize = 0;
    hdr->pagezero_segment.maxprot = 0;
    hdr->pagezero_segment.initprot = 0;
    hdr->pagezero_segment.nsects = 0;
    hdr->pagezero_segment.flags = 0;
    
    printf("Built __PAGEZERO segment\n");
}

static void build_text(macho_builder_t *builder) {
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    // Calculate offsets
    size_t text_vmaddr = PAGE_SIZE_64; 
    size_t text_fileoff = 0;  
    size_t code_fileoff = ALIGN_PAGE(builder->header_size); 
    size_t text_filesize = code_fileoff + ALIGN_PAGE(builder->code_size);  // segment size
    
    builder->code_offset = code_fileoff;
    
    // __TEXT segment 
    strncpy(hdr->text_segment.segname, "__TEXT", 16);
    hdr->text_segment.cmd = LC_SEGMENT_64;
    hdr->text_segment.cmdsize = sizeof(struct segment_command_64) + sizeof(struct section_64);
    hdr->text_segment.vmaddr = text_vmaddr;
    hdr->text_segment.vmsize = text_filesize;
    hdr->text_segment.fileoff = text_fileoff;  // Starts at 0 
    hdr->text_segment.filesize = text_filesize;
    hdr->text_segment.maxprot = VM_PROT_READ | VM_PROT_EXECUTE;
    hdr->text_segment.initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    hdr->text_segment.nsects = 1;
    hdr->text_segment.flags = 0;
    
    // We only need the code part
    strncpy(hdr->text_section.sectname, "__text", 16);
    strncpy(hdr->text_section.segname, "__TEXT", 16);
    hdr->text_section.addr = text_vmaddr + code_fileoff; 
    hdr->text_section.size = builder->code_size;
    hdr->text_section.offset = code_fileoff; 
    hdr->text_section.align = 4;  
    hdr->text_section.reloff = 0;
    hdr->text_section.nreloc = 0;
    hdr->text_section.flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
    hdr->text_section.reserved1 = 0;
    hdr->text_section.reserved2 = 0;
    hdr->text_section.reserved3 = 0;
    
    printf("Built __TEXT segment (vmaddr=0x%llx, size=0x%llx)\n",
        hdr->text_segment.vmaddr, hdr->text_segment.vmsize);
}


static void build_linkedit(macho_builder_t *builder) {
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    // __LINKEDIT comes after __TEXT segment
    size_t linkedit_fileoff = hdr->text_segment.fileoff + hdr->text_segment.filesize;
    size_t linkedit_vmaddr = hdr->text_segment.vmaddr + hdr->text_segment.vmsize;
    size_t linkedit_size = 2048;  
    
    builder->symtab_offset = linkedit_fileoff;
    builder->strtab_offset = linkedit_fileoff + 1024;
    builder->strtab_size = 1024;
    
    strncpy(hdr->linkedit_segment.segname, "__LINKEDIT", 16);
    hdr->linkedit_segment.cmd = LC_SEGMENT_64;
    hdr->linkedit_segment.cmdsize = sizeof(struct segment_command_64);
    hdr->linkedit_segment.vmaddr = linkedit_vmaddr;
    hdr->linkedit_segment.vmsize = ALIGN_PAGE(linkedit_size);
    hdr->linkedit_segment.fileoff = linkedit_fileoff;
    hdr->linkedit_segment.filesize = linkedit_size;
    hdr->linkedit_segment.maxprot = VM_PROT_READ;
    hdr->linkedit_segment.initprot = VM_PROT_READ;
    hdr->linkedit_segment.nsects = 0;
    hdr->linkedit_segment.flags = 0;
    
    printf("Built __LINKEDIT segment (fileoff=0x%llx)\n",
        hdr->linkedit_segment.fileoff);
}

static void build_symtab(macho_builder_t *builder) {
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    hdr->symtab_cmd.cmd = LC_SYMTAB;
    hdr->symtab_cmd.cmdsize = sizeof(struct symtab_command);
    hdr->symtab_cmd.symoff = builder->symtab_offset;
    hdr->symtab_cmd.nsyms = 0;  // No symbols for now
    hdr->symtab_cmd.stroff = builder->strtab_offset;
    hdr->symtab_cmd.strsize = builder->strtab_size;
    
    printf("Built LC_SYMTAB command\n");
}

static void build_dysymtab(macho_builder_t *builder) {
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    hdr->dysymtab_cmd.cmd = LC_DYSYMTAB;
    hdr->dysymtab_cmd.cmdsize = sizeof(struct dysymtab_command);
    
    // All zeros for minimal pieace
    hdr->dysymtab_cmd.ilocalsym = 0;
    hdr->dysymtab_cmd.nlocalsym = 0;
    hdr->dysymtab_cmd.iextdefsym = 0;
    hdr->dysymtab_cmd.nextdefsym = 0;
    hdr->dysymtab_cmd.iundefsym = 0;
    hdr->dysymtab_cmd.nundefsym = 0;
    hdr->dysymtab_cmd.tocoff = 0;
    hdr->dysymtab_cmd.ntoc = 0;
    hdr->dysymtab_cmd.modtaboff = 0;
    hdr->dysymtab_cmd.nmodtab = 0;
    hdr->dysymtab_cmd.extrefsymoff = 0;
    hdr->dysymtab_cmd.nextrefsyms = 0;
    hdr->dysymtab_cmd.indirectsymoff = 0;
    hdr->dysymtab_cmd.nindirectsyms = 0;
    hdr->dysymtab_cmd.extreloff = 0;
    hdr->dysymtab_cmd.nextrel = 0;
    hdr->dysymtab_cmd.locreloff = 0;
    hdr->dysymtab_cmd.nlocrel = 0;
    
    printf("Built LC_DYSYMTAB command\n");
}

static void build_entry(macho_builder_t *builder) {
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    hdr->entry_cmd.cmd = LC_MAIN;
    hdr->entry_cmd.cmdsize = sizeof(struct entry_point_command);
    hdr->entry_cmd.entryoff = builder->code_offset;  // Entry at start of code
    hdr->entry_cmd.stacksize = 0;  // Use default stack size
    
    printf("Built LC_MAIN command (entryoff=0x%llx)\n",
        hdr->entry_cmd.entryoff);
}

/**
 * Write code section
 */
static void write_code(macho_builder_t *builder, const uint8_t *code, size_t code_size) {
    if (code_size != builder->code_size) {
        printf("WARNING - code size mismatch (%zu vs %zu)\n",
            code_size, builder->code_size);
    }
    
    // Calculate 
    size_t aligned_size = ALIGN_PAGE(code_size);
    
    // Never hurt 
    if (builder->code_offset + aligned_size > builder->capacity) {
        printf("  Code offset: 0x%zx\n", builder->code_offset);
        printf("  Aligned size: 0x%zx\n", aligned_size);
        printf("  Required: 0x%zx\n", builder->code_offset + aligned_size);
        printf("  Capacity: 0x%zx\n", builder->capacity);
        return;
    }
    
    // Copy 
    memcpy(builder->buffer + builder->code_offset, code, code_size);
    
    // Zero-fill
    if (aligned_size > code_size) {
        memset(builder->buffer + builder->code_offset + code_size, 0, 
               aligned_size - code_size);
    }
    
    printf("Wrote %zu bytes of code at offset 0x%zx\n",
        code_size, builder->code_offset);
    printf("  Aligned to %zu bytes\n", aligned_size);
}

/**
 * maybe later
 */
static void init_symbol(macho_builder_t *builder) {
    // Initialize string table with null byte
    builder->buffer[builder->strtab_offset] = '\0';
    
    // We Could add symbols here if needed, 
    // but I don't think we need any
}

static size_t calculate_fsz(macho_builder_t *builder) { 
    macho_header_t *hdr = (macho_header_t *)builder->buffer;
    
    // Size = LINKEDIT end
    size_t final_size = hdr->linkedit_segment.fileoff + hdr->linkedit_segment.filesize;
    
    return final_size;
}

/**
 * The built structure
 */
static bool macho_stuff(macho_builder_t *builder) { 
    macho_header_t *hdr = (macho_header_t *)builder->buffer;

    if (hdr->header.magic != MH_MAGIC_64) {
        printf("[!] Invalid magic number (0x%x)\n", hdr->header.magic);
        return false;
    }
    
#if defined(__x86_64__)
    if (hdr->header.cputype != CPU_TYPE_X86_64) {
        printf("[!] We expected x86_64\n");
        return false;
    }
#elif defined(__aarch64__)
    if (hdr->header.cputype != CPU_TYPE_ARM64) {
        printf("[!] We expected ARM64\n");
        return false;
    }
#endif
    
    if (hdr->header.filetype != MH_EXECUTE) {
        printf("[!] Invalid file type (%u)\n", hdr->header.filetype);
        return false;
    }
    
    if (hdr->header.ncmds == 0 || hdr->header.ncmds > 100) {
        printf("[!] Invalid number of load commands (%u)\n", hdr->header.ncmds);
        return false;
    }
    
    size_t load_cmds_end = sizeof(struct mach_header_64) + hdr->header.sizeofcmds;
    if (load_cmds_end > builder->code_offset) {
        printf("[!] Load commands overlap with code\n");
        printf("                  Load cmds end: 0x%zx, Code offset: 0x%zx\n",
            load_cmds_end, builder->code_offset);
        return false;
    }
    
    if (hdr->text_segment.fileoff % PAGE_SIZE_64 != 0) {
        printf("[!] __TEXT segment not page-aligned (0x%llx)\n",
            hdr->text_segment.fileoff);
        return false;
    }
    
    if (hdr->linkedit_segment.fileoff % PAGE_SIZE_64 != 0) {
        printf("[!] __LINKEDIT segment not page-aligned (0x%llx)\n",
            hdr->linkedit_segment.fileoff);
        return false;
    }
    
    if (hdr->text_segment.vmaddr < hdr->pagezero_segment.vmaddr + hdr->pagezero_segment.vmsize) {
        printf("[!] __TEXT vmaddr overlaps with __PAGEZERO\n");
        printf("                  PAGEZERO: 0x%llx-0x%llx\n",
            hdr->pagezero_segment.vmaddr,
            hdr->pagezero_segment.vmaddr + hdr->pagezero_segment.vmsize);
        printf("                  TEXT: 0x%llx\n", hdr->text_segment.vmaddr);
        return false;
    }
    
    if (!(hdr->text_segment.initprot & VM_PROT_EXECUTE)) {
        printf("[!] __TEXT segment not executable\n");
        return false;
    }
    
    if (hdr->text_segment.fileoff != 0) {
        printf("[!] __TEXT segment doesn't start at file offset 0\n");
        return false;
    }
    
    if (hdr->text_section.offset < hdr->text_segment.fileoff ||
        hdr->text_section.offset + hdr->text_section.size > 
        hdr->text_segment.fileoff + hdr->text_segment.filesize) {
        printf("[!] __text section outside __TEXT segment\n");
        return false;
    }
    
    if (hdr->entry_cmd.entryoff < hdr->text_segment.fileoff ||
        hdr->entry_cmd.entryoff >= hdr->text_segment.fileoff + hdr->text_segment.filesize) {
        printf("[!] Entry point outside __TEXT segment\n");
        return false;
    }
    printf(" [+] Entry point within __TEXT segment\n");
    
    if (builder->code_size == 0 || builder->code_size > 100 * 1024 * 1024) {
        printf("[!] Code size unreasonable (%zu bytes)\n", builder->code_size);
        return false;
    }
    printf(" [+] Code size reasonable (%zu bytes)\n", builder->code_size);
    
    printf("[+] All Passed\n");
    return true;
}

/**
 * Wrap code in Mach-O 
 */
uint8_t* wrap_macho(const uint8_t *code, size_t code_size, size_t *out_size) {
    if (!code || code_size == 0 || !out_size) {
        printf("Invalid parameters\n");
        return NULL;
    }
    
    if (code_size > 100 * 1024 * 1024) {  // 100MB limit
        printf("Code size too large (%zu bytes)\n", code_size);
        return NULL;
    }
    
    // Initialize builder
    macho_builder_t *builder = builder_init(code_size);
    if (!builder) {
        printf("Failed to initialize builder\n");
        return NULL;
    }
    
    // Build all 
    build_header(builder);
    build_page0(builder);
    build_text(builder);
    build_linkedit(builder);
    build_symtab(builder);
    build_dysymtab(builder);
    build_entry(builder);
    
    // Write code section
    write_code(builder, code, code_size);
    init_symbol(builder);
    
    if (!macho_stuff(builder)) {
        printf("Validation failed\n");
        builder_free(builder);
        return NULL;
    }
    
    size_t final_size = calculate_fsz(builder);
    *out_size = final_size;
    
    uint8_t *result = builder->buffer;
    builder->buffer = NULL;  // can't stand double-free
    
    builder_free(builder);
    
    printf("Mach-O binary (%zu bytes)\n", final_size);
    
    return result;
}

bool V_machO(const uint8_t *data, size_t size) { 
    if (!data || size < sizeof(struct mach_header_64)) {
        return false;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    if (mh->magic != MH_MAGIC_64) {
        return false;
    }
    
#if defined(__x86_64__)
    if (mh->cputype != CPU_TYPE_X86_64) {
        return false;
    }
#elif defined(__aarch64__)
    if (mh->cputype != CPU_TYPE_ARM64) {
        return false;
    }
#endif
    
    // Check file type
    if (mh->filetype != MH_EXECUTE && 
        mh->filetype != MH_DYLIB && 
        mh->filetype != MH_BUNDLE) {
        return false;
    }
    
    // Verify load commands fit in file
    size_t load_cmds_size = sizeof(struct mach_header_64) + mh->sizeofcmds;
    if (load_cmds_size > size) {
        return false;
    }
    
    return true;
}
