#include "wrap.h"
#include <string.h>
#include <stdlib.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/vm_prot.h>

#define PG 0x4000
#define PG_ALIGN(x) (((x) + PG - 1) & ~(PG - 1))

uint8_t *wrap_macho(const uint8_t *code, size_t code_sz, size_t *out_sz) {
    if (!code || !code_sz || !out_sz) return NULL;

    /* compute layout */
    size_t hdr_sz   = sizeof(struct mach_header_64)
                    + sizeof(struct segment_command_64)                          /* __PAGEZERO */
                    + sizeof(struct segment_command_64) + sizeof(struct section_64) /* __TEXT + __text */
                    + sizeof(struct segment_command_64)                          /* __LINKEDIT */
                    + sizeof(struct symtab_command)
                    + sizeof(struct dysymtab_command)
                    + sizeof(struct dyld_info_command);

    size_t code_off  = PG_ALIGN(hdr_sz);
    size_t code_aln  = PG_ALIGN(code_sz);
    size_t link_off  = code_off + code_aln;
    size_t link_sz   = PG;  /* 1 page for symtab+strtab */
    size_t total     = link_off + link_sz;

    uint8_t *buf = calloc(1, total);
    if (!buf) return NULL;

    uint64_t vm_base = PG; /* __TEXT vmaddr (right after __PAGEZERO) */
    uint8_t *p = buf;

    /* mach_header_64 */
    struct mach_header_64 *mh = (void *)p;
    mh->magic      = MH_MAGIC_64;
    mh->cputype    = CPU_TYPE_ARM64;
    mh->cpusubtype = CPU_SUBTYPE_ARM64_ALL;
    mh->filetype   = MH_DYLIB;
    mh->ncmds      = 6;
    mh->sizeofcmds = (uint32_t)(hdr_sz - sizeof(*mh));
    mh->flags      = MH_NOUNDEFS | MH_DYLDLINK | MH_PIE;
    p += sizeof(*mh);

    struct segment_command_64 *pz = (void *)p;
    pz->cmd     = LC_SEGMENT_64;
    pz->cmdsize = sizeof(*pz);
    memcpy(pz->segname, "__PAGEZERO", 10);
    pz->vmaddr  = 0;
    pz->vmsize  = PG;
    p += sizeof(*pz);

    struct segment_command_64 *ts = (void *)p;
    ts->cmd      = LC_SEGMENT_64;
    ts->cmdsize  = sizeof(*ts) + sizeof(struct section_64);
    memcpy(ts->segname, "__TEXT", 6);
    ts->vmaddr   = vm_base;
    ts->vmsize   = code_off + code_aln;
    ts->fileoff  = 0;
    ts->filesize = code_off + code_aln;
    ts->maxprot  = VM_PROT_READ | VM_PROT_EXECUTE;
    ts->initprot = VM_PROT_READ | VM_PROT_EXECUTE;
    ts->nsects   = 1;
    p += sizeof(*ts);

    struct section_64 *sc = (void *)p;
    memcpy(sc->sectname, "__text", 6);
    memcpy(sc->segname, "__TEXT", 6);
    sc->addr   = vm_base + code_off;
    sc->size   = code_sz;
    sc->offset = (uint32_t)code_off;
    sc->align  = 2;
    sc->flags  = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;
    p += sizeof(*sc);

    struct segment_command_64 *le = (void *)p;
    le->cmd      = LC_SEGMENT_64;
    le->cmdsize  = sizeof(*le);
    memcpy(le->segname, "__LINKEDIT", 10);
    le->vmaddr   = vm_base + code_off + code_aln;
    le->vmsize   = PG_ALIGN(link_sz);
    le->fileoff  = link_off;
    le->filesize = link_sz;
    le->maxprot  = VM_PROT_READ;
    le->initprot = VM_PROT_READ;
    p += sizeof(*le);

    /* LC_SYMTAB */
    uint32_t sym_off = (uint32_t)link_off;
    uint32_t str_off = (uint32_t)(link_off + 512);
    struct symtab_command *sy = (void *)p;
    sy->cmd     = LC_SYMTAB;
    sy->cmdsize = sizeof(*sy);
    sy->symoff  = sym_off;
    sy->nsyms   = 0;
    sy->stroff  = str_off;
    sy->strsize = (uint32_t)(link_sz - 512);
    p += sizeof(*sy);

    struct dysymtab_command *dy = (void *)p;
    dy->cmd     = LC_DYSYMTAB;
    dy->cmdsize = sizeof(*dy);
    p += sizeof(*dy);

    struct dyld_info_command *di = (void *)p;
    di->cmd     = LC_DYLD_INFO_ONLY;
    di->cmdsize = sizeof(*di);
    /* all offsets/sizes zero */
    p += sizeof(*di);

    /* write code */
    memcpy(buf + code_off, code, code_sz);

    /* null string table entry */
    buf[str_off] = '\0';

    *out_sz = total;
    return buf;
}
