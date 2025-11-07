#include <aether.h>

/* Relocation engine for position-independent execution 
        Tracks and fixes up code references during mutation and loading */

reloc_table_t* reloc_init(uint64_t original_base) {
    reloc_table_t *table = calloc(1, sizeof(reloc_table_t));
    if (!table) return NULL;
    
    table->capacity = 256; // too much damn magic nm 
    table->entries = calloc(table->capacity, sizeof(reloc_entry_t));
    if (!table->entries) {
        free(table);
        return NULL;
    }
    
    table->count = 0;
    table->original_base = original_base;
    return table;
}

/* Add relocation entry with full instruction context */
bool reloc_add(reloc_table_t *table, size_t offset, size_t inst_start, 
               size_t inst_len, uint8_t type, int64_t addend, 
               uint64_t target, bool is_relative) {
    if (!table) return false;
    
    if (table->count >= table->capacity) {
        size_t new_cap = table->capacity * 2;
        reloc_entry_t *new_entries = realloc(table->entries, 
                                              new_cap * sizeof(reloc_entry_t));
        if (!new_entries) return false;
        
        table->entries = new_entries;
        table->capacity = new_cap;
    }
    
    reloc_entry_t *entry = &table->entries[table->count++];
    entry->offset = offset;
    entry->instruction_start = inst_start;
    entry->type = type;
    entry->addend = addend;
    entry->target = target;
    entry->is_relative = is_relative;
    entry->symbol_name = NULL;  /* Will be filled in later if external */
    entry->instruction_len = inst_len;
    
    return true;
}

/* x86-64 relocation scanner with decoding */
static void scan_x86(uint8_t *code, size_t size,
                                 reloc_table_t *table, uint64_t base_addr)
{
    size_t offset = 0;
    x86_inst_t inst;
    size_t consecutive_failures = 0;
    const size_t max_failures = 16;  /* Allow some corrupted instructions */

    while (offset < size) {
        /* decoding of mutated code */
        if (!decode_x86_withme(code + offset, size - offset, base_addr + offset, &inst, NULL)) {
            consecutive_failures++;
            if (consecutive_failures > max_failures) {
                /* Too many failures, skip this region */
                offset += 16;
                consecutive_failures = 0;
                continue;
            }
            /* Unknown raw? +1 and keep going */
            offset++;
            continue;
        }

        consecutive_failures = 0;  

        if (!inst.valid || inst.len == 0) {
            offset++;
            continue;
        }

        const size_t len = inst.len;

        /* rel32 calls and jumps */
        if (inst.opcode[0] == 0xE8 || inst.opcode[0] == 0xE9) {
            /* direct call/jmp rel32 */
            if (offset + 5 <= size) {
                int32_t rel32 = *(int32_t *)(code + offset + 1);
                uint64_t target = base_addr + offset + len + rel32;
                uint8_t type = (inst.opcode[0] == 0xE8) ? RELOC_CALL : RELOC_JMP;
                /* Store the relocation offset, instruction start, instruction length */
                reloc_add(table, offset + 1, offset, len, type, rel32, target, true);
            }
        }

        /* conditional jumps 0F 8x rel32 */
        else if (inst.raw[0] == 0x0F &&
                 (inst.raw[1] & 0xF0) == 0x80 &&
                 len >= 6) {
            if (offset + 6 <= size) {
                int32_t rel32 = *(int32_t *)(code + offset + 2);
                uint64_t target = base_addr + offset + len + rel32;
                reloc_add(table, offset + 2, offset, len, RELOC_JMP, rel32, target, true);
            }
        }

        /* RIP-relative memory operands */
        if (inst.has_modrm && (offset + len) <= size) {
            uint8_t modrm = inst.modrm;
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm  = modrm & 7;

            /* RIP-relative form is mod==0 && rm==5 */
            if (mod == 0 && rm == 5) {
                /* displacement is the 4 bytes following ModRM */
                size_t disp_off = inst.disp_offset;
                if (!disp_off && inst.modrm_offset > 0)
                    disp_off = (size_t)(inst.modrm_offset + 1); /* fallback */

                if (disp_off > 0 && disp_off + 4 <= len && offset + disp_off + 4 <= size) {
                    int32_t disp32 = *(int32_t *)(code + offset + disp_off);
                    uint64_t target = base_addr + offset + len + disp32;
                    reloc_add(table, offset + disp_off, offset, len, RELOC_LEA, disp32, target, true);
                }
            }
        }

        /* RIP-relative immediates */
        if (inst.has_imm && inst.imm_size == 4 && inst.is_rel_imm && 
            inst.imm_offset > 0 && offset + inst.imm_offset + 4 <= size) {
            int32_t rel32 = *(int32_t *)(code + offset + inst.imm_offset);
            uint64_t target = base_addr + offset + len + rel32;
            reloc_add(table, offset + inst.imm_offset, offset, len, RELOC_LEA, rel32, target, true);
        }
        offset += len ? len : 1;
    }
}

/* Scan ARM64 code for relocatable references */
static void scan_arm64(uint8_t *code, size_t size,
                                    reloc_table_t *table, uint64_t base_addr) {
    size_t i = 0;
    
    while (i < size - 4) {
        uint32_t insn = *(uint32_t*)(code + i);
        
        /* B/BL */
        if ((insn & 0x7C000000) == 0x14000000) {
            int32_t imm26 = (int32_t)(insn & 0x03FFFFFF);
            if (imm26 & 0x02000000) imm26 |= 0xFC000000; 
            
            int64_t offset = imm26 * 4;
            uint64_t target = base_addr + i + offset;
            
            uint8_t type = (insn & 0x80000000) ? RELOC_CALL : RELOC_JMP;
            reloc_add(table, i, i, 4, type, offset, target, true);
        }
        
        /* B.cond */
        else if ((insn & 0xFF000010) == 0x54000000) {
            int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
            if (imm19 & 0x40000) imm19 |= 0xFFF80000; 
            
            int64_t offset = imm19 * 4;
            uint64_t target = base_addr + i + offset;
            reloc_add(table, i, i, 4, RELOC_JMP, offset, target, true);
        }
        
        /* CBZ/CBNZ */
        else if ((insn & 0x7E000000) == 0x34000000) {
            int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
            if (imm19 & 0x40000) imm19 |= 0xFFF80000;
            
            int64_t offset = imm19 * 4;
            uint64_t target = base_addr + i + offset;
            reloc_add(table, i, i, 4, RELOC_JMP, offset, target, true);
        }
        
        /* ADRP */
        else if ((insn & 0x9F000000) == 0x90000000) {
            int64_t immlo = (insn >> 29) & 0x3;
            int64_t immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & 0x100000) imm |= 0xFFFFFFFFFFE00000LL; 
            
            int64_t offset = imm * 4096; /* Page offset */
            uint64_t target = (base_addr + i) & ~0xFFFULL;
            target += offset;
            reloc_add(table, i, i, 4, RELOC_LEA, offset, target, true);
        }
        
        /* ADR */
        else if ((insn & 0x9F000000) == 0x10000000) {
            int64_t immlo = (insn >> 29) & 0x3;
            int64_t immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & 0x100000) imm |= 0xFFFFFFFFFFE00000LL; 
            
            uint64_t target = base_addr + i + imm;
            reloc_add(table, i, i, 4, RELOC_LEA, imm, target, true);
        }
        
        /* load from PC address */
        else if ((insn & 0x3B000000) == 0x18000000) {
            int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
            if (imm19 & 0x40000) imm19 |= 0xFFF80000;
            
            int64_t offset = imm19 * 4;
            uint64_t target = base_addr + i + offset;
            reloc_add(table, i, i, 4, RELOC_LEA, offset, target, true);
        }
        
        i += 4;
    }
}

void reloc_free(reloc_table_t *table) {
    if (!table) return;
    
    if (table->entries) {
        /* Free symbol names */
        for (size_t i = 0; i < table->count; i++) {
            if (table->entries[i].symbol_name) {
                free(table->entries[i].symbol_name);
            }
        }
        free(table->entries);
    }
    
    free(table);
}

/* Scan code and build relocation table */
reloc_table_t* reloc_scan(uint8_t *code, size_t size, uint64_t base_addr, uint8_t arch) {
    reloc_table_t *table = reloc_init(base_addr);
    if (!table) return NULL;
    
    if (arch == ARCH_X86) {
        scan_x86(code, size, table, base_addr);
    }
#if defined(ARCH_ARM)
    else if (arch == ARCH_ARM) {
        scan_arm64(code, size, table, base_addr);
    }
#endif
    
    return table;
}

/* Check if target address is within the code range Exported for use by symbol resolution */
bool iz_internal(uint64_t target, uint64_t base, size_t size) {
    /* If target is more than 1GB away from base, it's definitely external, 
        I could be wrong */
    int64_t distance = (int64_t)target - (int64_t)base;
    if (distance < 0) distance = -distance;
    
    if (distance > 0x40000000) { 
        return false;  
    }
    
    /* Otherwise check if within code range */
    return (target >= base && target < base + size);
}

/* Analyze relocation table to determine if code is self-contained */
bool own_self(reloc_table_t *table, size_t code_size) { 
    if (!table) return true;
    
    size_t external_refs = 0;
    size_t internal_refs = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];
        
        if (iz_internal(rel->target, table->original_base, code_size)) {
            internal_refs++;
        } else {
            external_refs++;
        }
    }
    
    return (external_refs == 0);
}

/* Find instruction start by decoding backwards from relocation offset */
static size_t start_x86(uint8_t *code, size_t size, size_t reloc_offset) {
    /* Work backwards from there */
    size_t search_start = (reloc_offset > 15) ? reloc_offset - 15 : 0;
    x86_inst_t inst;
    
    for (size_t try_offset = search_start; try_offset <= reloc_offset && try_offset + 15 <= size; try_offset++) {
        if (decode_x86_withme(code + try_offset, size - try_offset, 
                             (uintptr_t)(code + try_offset), &inst, NULL)) {
            if (inst.valid && inst.len > 0) {
                size_t rel_in_inst = reloc_offset - try_offset;
                /* Check if relocation offset is within this instruction */
                if (rel_in_inst < inst.len) {
                    return try_offset;
                }
            }
        }
    }
    
    return 0;
}

/* Apply relocations for new base address */
bool reloc_apply(uint8_t *code, size_t size, reloc_table_t *table, 
                 uint64_t new_base, uint8_t arch) {
    if (!code || !table) return false;
    
    int64_t slide = (int64_t)new_base - (int64_t)table->original_base;
    
    /* If no game, no skin */
    if (slide == 0) {
        return true;
    }
    
    size_t fixed = 0;
    size_t skipped_external = 0;
    size_t failed = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];
        
        if (rel->offset >= size) {
            failed++;
            continue;
        }
        
        if (arch == ARCH_X86) {
            if (rel->is_relative) {
                /* Get instruction start and length */
                size_t inst_start = rel->instruction_start;
                size_t inst_len = rel->instruction_len;
                
                /* If not stored, try to find by decoding backwards */
                if (inst_start == 0 || inst_len == 0) {
                    inst_start = start_x86(code, size, rel->offset);
                    if (inst_start == 0) {
                        failed++;
                        continue;
                    }
                }
                
                /* Verify instruction is still valid by decoding */
                x86_inst_t inst;
                if (!decode_x86_withme(code + inst_start, size - inst_start, 
                                      new_base + inst_start, &inst, NULL) || 
                    !inst.valid || inst.len == 0) {
                    failed++;
                    continue;
                }
                
                /* Use actual decoded length, this is dumbasf */
                inst_len = inst.len;
                
                /* Verify relocation offset is within instruction */
                if (rel->offset < inst_start || rel->offset + 4 > inst_start + inst_len) {
                    failed++;
                    continue;
                }
                
                uint64_t new_pc = new_base + inst_start + inst_len;
                
                /* Calculate new target */
                uint64_t old_target = rel->target;
                uint64_t new_target = old_target + slide;  /* Target moved with code */
                int64_t new_offset = (int64_t)new_target - (int64_t)new_pc;
                
                /* if fits in rel32 */
                if (new_offset < INT32_MIN || new_offset > INT32_MAX) {
                    failed++;
                    continue;
                }
                
                /* Apply the fix */
                int32_t *ptr = (int32_t*)(code + rel->offset);
                *ptr = (int32_t)new_offset;
                fixed++;
            }
            /* Absolute 64-bit */
            else if (rel->type == RELOC_ABS64) {
                if (rel->offset + 8 > size) {
                    failed++;
                    continue;
                }
                
                uint64_t *ptr = (uint64_t*)(code + rel->offset);
                *ptr += slide;
                fixed++;
            }
        }
        else if (arch == ARCH_ARM) {
            if (rel->is_relative) {
                /* Get instruction start and length */
                size_t inst_start = rel->instruction_start;
                size_t inst_len = rel->instruction_len;
                
                /* Default to 4 bytes for ARM64 if not stored */
                if (inst_start == 0) inst_start = rel->offset;
                if (inst_len == 0) inst_len = 4;
                
                /* Verify instruction is still valid */
                if (inst_start + 4 > size) {
                    failed++;
                    continue;
                }
                
                arm64_inst_t inst;
                uint64_t new_pc = new_base + inst_start + 4;
                uint64_t old_target = rel->target;
                uint64_t new_target = old_target + slide;
                
                int64_t new_offset = (int64_t)new_target - (int64_t)new_pc;
                uint32_t *insn_ptr = (uint32_t*)(code + inst_start);
                uint32_t insn = *insn_ptr;
                
                if ((insn & 0x7C000000) == 0x14000000) {
                    int64_t max_range = (1LL << 27);
                    if (new_offset < -max_range || new_offset >= max_range || (new_offset & 3) != 0) {
                        failed++;
                        continue;
                    }
                    
                    uint32_t new_insn = (insn & 0xFC000000) | ((new_offset / 4) & 0x3FFFFFF);
                    *insn_ptr = new_insn;
                    fixed++;
                }
                else if ((insn & 0xFF000010) == 0x54000000) {
                    int64_t max_range = (1LL << 20);
                    if (new_offset < -max_range || new_offset >= max_range || (new_offset & 3) != 0) {
                        failed++;
                        continue;
                    }
                    
                    uint32_t new_insn = (insn & 0xFF00001F) | (((new_offset / 4) & 0x7FFFF) << 5);
                    *insn_ptr = new_insn;
                    fixed++;
                }
                else if ((insn & 0x7E000000) == 0x34000000) {
                    int64_t max_range = (1LL << 20);
                    if (new_offset < -max_range || new_offset >= max_range || (new_offset & 3) != 0) {
                        failed++;
                        continue;
                    }
                    
                    uint32_t new_insn = (insn & 0xFF00001F) | (((new_offset / 4) & 0x7FFFF) << 5);
                    *insn_ptr = new_insn;
                    fixed++;
                }
                else if ((insn & 0x9F000000) == 0x90000000) {
                    uint64_t target_page = (new_target & ~0xFFFULL);
                    uint64_t pc_page = (new_pc & ~0xFFFULL);
                    int64_t page_offset = (int64_t)target_page - (int64_t)pc_page;
                    
                    if (page_offset < -(1LL << 32) || page_offset >= (1LL << 32)) {
                        failed++;
                        continue;
                    }
                    
                    int64_t imm = page_offset / 4096;
                    uint32_t immlo = imm & 0x3;
                    uint32_t immhi = (imm >> 2) & 0x7FFFF;
                    uint32_t new_insn = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
                    *insn_ptr = new_insn;
                    fixed++;
                }
                else if ((insn & 0x9F000000) == 0x10000000) {
                    if (new_offset < -(1LL << 20) || new_offset >= (1LL << 20)) {
                        failed++;
                        continue;
                    }
                    
                    uint32_t immlo = new_offset & 0x3;
                    uint32_t immhi = (new_offset >> 2) & 0x7FFFF;
                    uint32_t new_insn = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
                    *insn_ptr = new_insn;
                    fixed++;
                }
                else if ((insn & 0x3B000000) == 0x18000000) {
                    int64_t max_range = (1LL << 20);
                    if (new_offset < -max_range || new_offset >= max_range || (new_offset & 3) != 0) {
                        failed++;
                        continue;
                    }
                    
                    uint32_t new_insn = (insn & 0xFF00001F) | (((new_offset / 4) & 0x7FFFF) << 5);
                    *insn_ptr = new_insn;
                    fixed++;
                }
                else {
                    failed++;
                }
            }
            else if (rel->type == RELOC_ABS64) {
                if (rel->offset + 8 > size) {
                    failed++;
                    continue;
                }
                
                uint64_t *ptr = (uint64_t*)(code + rel->offset);
                *ptr += slide;
                fixed++;
            }
        }
    }
    
    return (failed == 0);
}

/* Export relocation table for later use  */
bool reloc_export(reloc_table_t *table, uint8_t **out_data, size_t *out_size) {
    if (!table || !out_data || !out_size) return false;
    
    /* Calculate */
    size_t data_size = sizeof(uint64_t) + sizeof(size_t);
    
    for (size_t i = 0; i < table->count; i++) {
        data_size += sizeof(reloc_entry_t) - sizeof(char*); /* Entry without pointer */
        data_size += sizeof(uint32_t); /* Symbol name length */
        if (table->entries[i].symbol_name) {
            data_size += strlen(table->entries[i].symbol_name) + 1;
        }
    }
    
    uint8_t *data = malloc(data_size);
    if (!data) return false;
    
    uint8_t *ptr = data;
    
    /* Write header */
    *(uint64_t*)ptr = table->original_base;
    ptr += sizeof(uint64_t);
    
    *(size_t*)ptr = table->count;
    ptr += sizeof(size_t);
    
    /* Write entries */
    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *entry = &table->entries[i];
        
        /* except symbol_name pointer */
        memcpy(ptr, entry, offsetof(reloc_entry_t, symbol_name));
        ptr += offsetof(reloc_entry_t, symbol_name);
        
        /* Write instruction_len */
        *(size_t*)ptr = entry->instruction_len;
        ptr += sizeof(size_t);
        
        /* Write symbol name */
        uint32_t name_len = entry->symbol_name ? (uint32_t)strlen(entry->symbol_name) + 1 : 0;
        *(uint32_t*)ptr = name_len;
        ptr += sizeof(uint32_t);
        
        if (name_len > 0) {
            memcpy(ptr, entry->symbol_name, name_len);
            ptr += name_len;
        }
    }
    
    *out_data = data;
    *out_size = data_size;
    return true;
}

/* Import relocation table */
reloc_table_t* reloc_import(uint8_t *data, size_t size) {
    if (!data || size < sizeof(uint64_t) + sizeof(size_t)) return NULL;
    
    uint8_t *ptr = data;
    uint8_t *end = data + size;
    
    /* Read header */
    if (ptr + sizeof(uint64_t) + sizeof(size_t) > end) return NULL;
    
    uint64_t original_base = *(uint64_t*)ptr;
    ptr += sizeof(uint64_t);
    
    size_t count = *(size_t*)ptr;
    ptr += sizeof(size_t);
    
    reloc_table_t *table = reloc_init(original_base);
    if (!table) return NULL;
    
    /* Allocate space for entries */
    if (count > table->capacity) {
        reloc_entry_t *new_entries = calloc(count, sizeof(reloc_entry_t));
        if (!new_entries) {
            reloc_free(table);
            return NULL;
        }
        free(table->entries);
        table->entries = new_entries;
        table->capacity = count;
    }
    
    /* Read entries */
    for (size_t i = 0; i < count; i++) {
        if (ptr + offsetof(reloc_entry_t, symbol_name) + sizeof(size_t) + sizeof(uint32_t) > end) {
            reloc_free(table);
            return NULL;
        }
        
        reloc_entry_t *entry = &table->entries[i];
        /* Read all fields except symbol_name pointer */
        memcpy(entry, ptr, offsetof(reloc_entry_t, symbol_name));
        ptr += offsetof(reloc_entry_t, symbol_name);
        
        /* Read instruction_len (written separately in export) */
        entry->instruction_len = *(size_t*)ptr;
        ptr += sizeof(size_t);
        
        /* Read symbol name length */
        uint32_t name_len = *(uint32_t*)ptr;
        ptr += sizeof(uint32_t);
        
        if (name_len > 0) {
            if (ptr + name_len > end) {
                reloc_free(table);
                return NULL;
            }
            
            entry->symbol_name = malloc(name_len);
            if (!entry->symbol_name) {
                reloc_free(table);
                return NULL;
            }
            
            memcpy(entry->symbol_name, ptr, name_len);
            entry->symbol_name[name_len - 1] = '\0'; 
            ptr += name_len;
        } else {
            entry->symbol_name = NULL;
        }
        
        table->count++;
    }
    
    return table;
}