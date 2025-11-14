#include <aether.h>

static bool code_addr(uint64_t imm, uint64_t base_addr, size_t size);
static void jump_table(uint8_t *code, size_t size, size_t table_offset,
                           uint64_t base_addr, reloc_table_t *table);

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

/* x86-64 relocation  */
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
                size_t disp_off = inst.disp_offset;
                if (!disp_off && inst.modrm_offset > 0)
                    disp_off = (size_t)(inst.modrm_offset + 1); /* fallback */

                if (disp_off > 0 && disp_off + 4 <= len && offset + disp_off + 4 <= size) {
                    int32_t disp32 = *(int32_t *)(code + offset + disp_off);
                    uint64_t target = base_addr + offset + len + disp32;
                    
                    /* Mark SIMD instructions */
                    uint8_t reloc_type = RELOC_LEA;
                    if (inst.is_simd) {
                        reloc_type = RELOC_LEA;  /* Could add RELOC_SIMD */
                    }
                    
                    reloc_add(table, offset + disp_off, offset, len, reloc_type, disp32, target, true);
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
        
        if ((inst.rep || inst.repne) && 
            (inst.opcode[0] == 0xA4 || inst.opcode[0] == 0xA5 || 
             inst.opcode[0] == 0xAA || inst.opcode[0] == 0xAB || 
             inst.opcode[0] == 0xAC || inst.opcode[0] == 0xAD || 
             inst.opcode[0] == 0xAE || inst.opcode[0] == 0xAF)) {
            /* These are tricky RSI/RDI values are runtime-dependent, Best we can do is mark them as special in the relocation table
                        so they can be protected from mutation */
             DBG("[Reloc] String instruction at 0x%zx (REP %02x)\n", 
                offset, inst.opcode[0]);
        }
        
        /* Absolute addresses */
        if (inst.has_imm && !inst.is_rel_imm && inst.imm_offset > 0) {
            if (inst.imm_size == 8 && offset + inst.imm_offset + 8 <= size) {
                uint64_t imm64 = inst.imm;
                /* Check if this looks like a code address */
                if (code_addr(imm64, base_addr, size)) {
                    reloc_add(table, offset + inst.imm_offset, offset, len, 
                             RELOC_ABS64, 0, imm64, false);
                }
            }
            /* Check for 32-bit immediate that might be an address */
            else if (inst.imm_size == 4 && offset + inst.imm_offset + 4 <= size) {
                uint64_t imm32 = inst.imm & 0xFFFFFFFF;
                
                /* For MOV instructions, check if immediate looks like address */
                if ((inst.opcode[0] >= 0xB8 && inst.opcode[0] <= 0xBF) ||  
                    inst.opcode[0] == 0xC7) { 
                    
                    /* Sign-extend if it looks like a signed offset */
                    if (imm32 & 0x80000000) {
                        imm32 |= 0xFFFFFFFF00000000ULL;
                    }
                    
                    /* Check if within code range using heuristics */
                    if (code_addr(imm32, base_addr, size)) {
                        reloc_add(table, offset + inst.imm_offset, offset, len, 
                                 RELOC_ABS64, 0, imm32, false);
                    }
                }
            }
        }
        
        /* Detect computed jumps */
        if (inst.opcode[0] == 0xFF && inst.has_modrm) {
            uint8_t reg = modrm_reg(inst.modrm);
            uint8_t mod = (inst.modrm >> 6) & 3;
            uint8_t rm = inst.modrm & 7;
            
            if (reg == 4 && mod != 3) {
                if (rm == 4 && inst.has_sib) {
                    if (inst.disp_size == 4 && inst.disp_offset > 0 && 
                        offset + inst.disp_offset + 4 <= size) {
                        int32_t disp32 = inst.disp;
                        uint64_t table_addr = base_addr + offset + len + disp32;
                        
                        /* Mark this as a potential jump table reference */
                        if (iz_internal(table_addr, base_addr, size)) {
                            reloc_add(table, offset + inst.disp_offset, offset, len, 
                                     RELOC_LEA, disp32, table_addr, true);
                            
                            /* Scan the jump table data for address entries */
                            size_t table_file_offset = (size_t)(table_addr - base_addr);
                            if (table_file_offset < size) {
                                jump_table(code, size, table_file_offset, base_addr, table);
                            }
                        }
                    }
                }
                /* RIP-relative jump table access */
                else if (mod == 0 && rm == 5 && inst.disp_size == 4 && 
                         inst.disp_offset > 0 && offset + inst.disp_offset + 4 <= size) {
                    int32_t disp32 = inst.disp;
                    uint64_t table_addr = base_addr + offset + len + disp32;
                    
                    if (iz_internal(table_addr, base_addr, size)) {
                        reloc_add(table, offset + inst.disp_offset, offset, len, 
                                 RELOC_LEA, disp32, table_addr, true);
                        
                        /* Scan the jump table data for address entries */
                        size_t table_file_offset = (size_t)(table_addr - base_addr);
                        if (table_file_offset < size) {
                            jump_table(code, size, table_file_offset, base_addr, table);
                        }
                    }
                }
            }
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
        
        else if ((insn & 0x7E000000) == 0x36000000 || (insn & 0x7E000000) == 0x37000000) {
            int32_t imm14 = (int32_t)((insn >> 5) & 0x3FFF);
            if (imm14 & 0x2000) imm14 |= 0xFFFFC000;
            
            int64_t offset = imm14 * 4;
            uint64_t target = base_addr + i + offset;
            reloc_add(table, i, i, 4, RELOC_JMP, offset, target, true);
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

/* Avoid false positives from constants */
bool iz_internal(uint64_t target, uint64_t base, size_t size) {
    /* must be within actual code range */
    if (target < base || target >= base + size) {
        return false;
    }
    
    /* prefer aligned addresses */
    #if defined(__aarch64__) || defined(_M_ARM64)
        /* ARM64 instructions are 4-byte aligned */
        if ((target & 0x3) != 0) {
            return false;
        }
    #else
        /* we can start anywhere */
    #endif
    
    /* Reject suspiciously round numbers that are likely constants */
    if ((target & 0xFFFFF) == 0 && target != base) {
        /* Addresses like 0x100000, 0x200000 are likely constants, not code */
        return false;
    }
    
    return true;
}

/* Check if an immediate value looks like a code address */
static bool code_addr(uint64_t imm, uint64_t base_addr, size_t size) {    
    /* Skip small values that are likely constants */
    if (imm < 0x1000) return false;
    
    /* Check if it's within or near the code section */
    if (iz_internal(imm, base_addr, size)) {
        /* Prefer aligned addresses */
        if ((imm & 0x1) == 0) return true;
        /* But allow unaligned if very close to base */
        if (imm >= base_addr && imm < base_addr + 0x10000) return true;
    }
    
    return false;
}

/* Jump table scan */
static void jump_table(uint8_t *code, size_t size, size_t table_offset,
                       uint64_t base_addr, reloc_table_t *table) {
    if (!code || !table || table_offset >= size) return;

    const size_t max_entries = 64;
    size_t entries_found_abs = 0;
    size_t entries_found_rel = 0;

    for (size_t i = 0; i < max_entries; i++) {
        size_t entry_offset = table_offset + i*8;
        if (entry_offset + 8 > size) break;

        uint64_t entry_addr = 0;
        memcpy(&entry_addr, code + entry_offset, sizeof(entry_addr));

        if (code_addr(entry_addr, base_addr, size)) {
            reloc_add(table, entry_offset, entry_offset, 8, RELOC_ABS64, 0, entry_addr, false);
            entries_found_abs++;
        } else break;
    }

    if (entries_found_abs == 0) {
        for (size_t i = 0; i < max_entries; i++) {
            size_t entry_offset = table_offset + i*4;
            if (entry_offset + 4 > size) break;

            int32_t rel_offset = 0;
            memcpy(&rel_offset, code + entry_offset, sizeof(rel_offset));
            uint64_t target = base_addr + entry_offset + rel_offset;

            if (rel_offset >= -0x10000 && rel_offset <= 0x10000 && iz_internal(target, base_addr, size)) {
                reloc_add(table, entry_offset, entry_offset, 4, RELOC_REL32, rel_offset, target, true);
                entries_found_rel++;
            } else break;
        }
    }
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
                    /* find instruction start by decoding backwards from relocation offset */
                    size_t search_start = (rel->offset > 15) ? rel->offset - 15 : 0;
                    x86_inst_t search_inst;
                    inst_start = 0;
                    
                    for (size_t try_offset = search_start; try_offset <= rel->offset && try_offset + 15 <= size; try_offset++) {
                        if (decode_x86_withme(code + try_offset, size - try_offset, 
                                             (uintptr_t)(code + try_offset), &search_inst, NULL)) {
                            if (search_inst.valid && search_inst.len > 0) {
                                size_t rel_in_inst = rel->offset - try_offset;
                                /* Check if relocation offset is within this instruction */
                                if (rel_in_inst < search_inst.len) {
                                    inst_start = try_offset;
                                    break;
                                }
                            }
                        }
                    }
                    
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
                
                /* if still valid */
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

/* Relocation update after insertion */
bool reloc_update(reloc_table_t *table,  
                  size_t insertion_offset,
                  size_t bytes_inserted,
                  uint8_t *code, 
                  size_t code_size,
                  uint64_t base_addr,
                  uint8_t arch) {
    if (!table || !code || bytes_inserted == 0) return true;

    size_t up_offst = 0;
    size_t up_disp = 0;
    size_t Oz_errors = 0;

    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];

        size_t inst_start = rel->instruction_start;
        size_t inst_len = rel->instruction_len;

        if (inst_start == SIZE_MAX) {
            inst_start = 0;
        } else if (inst_start >= code_size) {
            DBG("[!] Invalid instruction_start 0x%zx >= code_size 0x%zx for reloc at 0x%zx\n", 
                inst_start, code_size, rel->offset);
            return false;
        }

        if (inst_len == 0 && inst_start < code_size) {
            if (arch == ARCH_X86) {
                x86_inst_t inst;
                if (decode_x86_withme(code + inst_start, code_size - inst_start,
                                     base_addr + inst_start, &inst, NULL) && inst.valid) {
                    inst_len = inst.len;
                    rel->instruction_len = inst_len;
                }
            } else if (arch == ARCH_ARM) {
                inst_len = 4;
                rel->instruction_len = 4;
            }
        }

        if (inst_len > 0 && insertion_offset > inst_start &&
            insertion_offset < inst_start + inst_len) {
            DBG("[!] Insertion at 0x%zx inside instruction at 0x%zx (len=%zu)\n",
                insertion_offset, inst_start, inst_len);
            return false;
        }
    }

    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];

        /* Instruction moves if insertion is at or before its start (>= semantics) */
        bool inst_moved = (rel->instruction_start != SIZE_MAX) ? 
            (rel->instruction_start >= insertion_offset) : 
            (rel->offset >= insertion_offset);
        bool target_moved = (rel->target >= base_addr + insertion_offset);

        if (inst_moved) {
            rel->offset += bytes_inserted;
            if (rel->instruction_start != SIZE_MAX) rel->instruction_start += bytes_inserted;
            up_offst++;
        }

        if (target_moved) rel->target += bytes_inserted;

        if (rel->is_relative && arch == ARCH_X86) {
            /* Skip recalculation if nothing changed */
            if (!inst_moved && !target_moved) continue;
            
            size_t inst_start = rel->instruction_start;
            size_t inst_len = rel->instruction_len;

            if (inst_start == SIZE_MAX && rel->offset > 0) {
                size_t search_start = (rel->offset > 15) ? rel->offset - 15 : 0;
                bool found = false;

                for (size_t try_offset = search_start; try_offset <= rel->offset && try_offset + 15 <= code_size; try_offset++) {
                    x86_inst_t search_inst;
                    if (decode_x86_withme(code + try_offset, code_size - try_offset,
                                          base_addr + try_offset, &search_inst, NULL)) {
                        if (search_inst.valid && search_inst.len > 0) {
                            size_t rel_in_inst = rel->offset - try_offset;
                            if (rel_in_inst + 4 <= search_inst.len) {
                                inst_start = try_offset;
                                inst_len = search_inst.len;
                                rel->instruction_start = inst_start;
                                rel->instruction_len = inst_len;
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if (!found) {
                    DBG("[!] Cannot find instruction for relocation at 0x%zx\n", rel->offset);
                    Oz_errors++;
                    continue;
                }
            }

            if (inst_len == 0 && inst_start < code_size) {
                x86_inst_t inst;
                if (decode_x86_withme(code + inst_start, code_size - inst_start,
                                     base_addr + inst_start, &inst, NULL) && inst.valid) {
                    inst_len = inst.len;
                    rel->instruction_len = inst_len;
                } else {
                    DBG("[!] Failed to decode instruction at 0x%zx for relocation\n", inst_start);
                    Oz_errors++;
                    continue;
                }
            }if (inst_len == 0) {Oz_errors++;continue;}

            if (inst_start >= code_size || rel->offset + 4 > code_size) {
                Oz_errors++;
                continue;
            }

            uint64_t new_pc = base_addr + inst_start + inst_len;
            int64_t new_disp = (int64_t)rel->target - (int64_t)new_pc;
            if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
                DBG("[!] Relocation at 0x%zx: displacement overflow (%lld)\n", rel->offset, new_disp);
                Oz_errors++;
                continue;
            }

            *(int32_t*)(code + rel->offset) = (int32_t)new_disp;
            up_disp++;
        }
        else if (rel->is_relative && arch == ARCH_ARM) {
            /* Skip recalculation if nothing changed */
            if (!inst_moved && !target_moved) continue;
            
            size_t inst_start = rel->instruction_start;
            if (inst_start == SIZE_MAX) inst_start = rel->offset;

            if (inst_start + 4 > code_size) {
                Oz_errors++;
                continue;
            }

            uint32_t *insn_ptr = (uint32_t*)(code + inst_start);
            uint32_t insn = *insn_ptr;
            uint64_t new_pc = base_addr + inst_start;
            uint64_t target_addr = rel->target;
            int64_t new_offset = (int64_t)target_addr - (int64_t)new_pc;

            if ((insn & 0x7C000000) == 0x14000000) { // B/BL
                if (new_offset >= -(1LL<<27) && new_offset < (1LL<<27) && (new_offset & 3) == 0) {
                    *insn_ptr = (insn & 0xFC000000) | ((new_offset/4) & 0x3FFFFFF);
                    up_disp++;
                } else Oz_errors++;
            }
            else if ((insn & 0xFF000010) == 0x54000000 || (insn & 0x7E000000) == 0x34000000) { // B.cond, CBZ/CBNZ
                if (new_offset >= -(1LL<<20) && new_offset < (1LL<<20) && (new_offset & 3) == 0) {
                    /* Both instruction types use same encoding for offset */
                    *insn_ptr = (insn & 0xFF00001F) | (((new_offset/4) & 0x7FFFF) << 5);
                    up_disp++;
                } else Oz_errors++;
            }
            else if ((insn & 0x9F000000) == 0x90000000) { // ADRP
                uint64_t target_page = target_addr & ~0xFFFULL;
                uint64_t pc_page = (new_pc & ~0xFFFULL);
                int64_t page_offset = (int64_t)target_page - (int64_t)pc_page;
                if (page_offset >= -(1LL<<32) && page_offset < (1LL<<32)) {
                    int64_t imm = page_offset / 4096;
                    uint32_t immlo = imm & 0x3;
                    uint32_t immhi = (imm >> 2) & 0x7FFFF;
                    *insn_ptr = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
                    up_disp++;
                } else Oz_errors++;
            }
            else if ((insn & 0x9F000000) == 0x10000000) { // ADR
                if (new_offset >= -(1LL<<20) && new_offset < (1LL<<20)) {
                    uint32_t immlo = new_offset & 0x3;
                    uint32_t immhi = (new_offset >> 2) & 0x7FFFF;
                    *insn_ptr = (insn & 0x9F00001F) | (immlo << 29) | (immhi << 5);
                    up_disp++;
                } else Oz_errors++;
            }
            else if ((insn & 0x3B000000) == 0x18000000) { // LDR literal
                /* LDR literal is PC-relative from instruction start, no adjustment needed */
                if (new_offset >= -(1LL<<20) && new_offset < (1LL<<20) && (new_offset & 3) == 0) {
                    *insn_ptr = (insn & 0xFF00001F) | (((new_offset/4) & 0x7FFFF) << 5);
                    up_disp++;
                } else Oz_errors++;
            }
            else if ((insn & 0x7E000000) == 0x36000000 || (insn & 0x7E000000) == 0x37000000) { // TBZ/TBNZ
                if (new_offset >= -(1LL<<15) && new_offset < (1LL<<15) && (new_offset & 3) == 0) {
                    *insn_ptr = (insn & 0xFFF8001F) | (((new_offset/4) & 0x3FFF) << 5);
                    up_disp++;
                } else Oz_errors++;
            }
        }
    }

    if (Oz_errors > 0) return false;
    return true;
}

/* Validate that all relocations will fit after potential expansion */
bool reloc_expanziv(reloc_table_t *table, size_t current_size,
                               size_t proposed_size, uint64_t base_addr, uint8_t arch) {
    if (!table) return true;
    
    /* Calculate maximum safe displacement based on architecture */
    int64_t max_safe_disp = (arch == ARCH_X86) ? INT32_MAX : (1LL << 27);  /* ARM64 B/BL range */
    
    size_t count_0z = 0;
    size_t checked = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];
        
        if (!rel->is_relative) continue;  /* Only check PC-relative */
        
        checked++;
        
        /* Simulate worst-case: instruction at start, target at end */
        uint64_t worst_pc = base_addr;
        uint64_t worst_target = base_addr + proposed_size; 
        int64_t worst_disp = (int64_t)worst_target - (int64_t)worst_pc;
        
        if (worst_disp < -max_safe_disp || worst_disp > max_safe_disp) {
            count_0z++;
            DBG("[Reloc] at 0x%zx would with size %zu (worst-case disp=%lld)\n",
                   rel->offset, proposed_size, worst_disp);
        }
    }
    
    if (count_0z > 0) { 
        DBG("[Reloc] NAH %zu/%zu size %zu\n",
               count_0z, checked, proposed_size);
        return false;
    }
    
    DBG("[Reloc] AIGHT %zu size %zu\n",
           checked, proposed_size);
    return true;
}

size_t reloc_overz(reloc_table_t *table, uint8_t *code, size_t code_size,
                              uint64_t base_addr, uint8_t arch) {
    if (!table || !code) return 0;
    
    size_t count_0z = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];
        
        if (!rel->is_relative) continue;
        
        size_t inst_start = rel->instruction_start;
        size_t inst_len = rel->instruction_len;
        
        if (inst_start >= code_size) continue;
        
        uint64_t pc = base_addr + inst_start + inst_len;
        uint64_t target = rel->target;
        int64_t disp = (int64_t)target - (int64_t)pc;
        
        if (arch == ARCH_X86) {
            if (disp < INT32_MIN || disp > INT32_MAX) {
                count_0z++;
            }
        } else if (arch == ARCH_ARM) {
            /* Check based on instruction type */
            if (inst_start + 4 <= code_size) {
                uint32_t insn = *(uint32_t*)(code + inst_start);
                
                /* B/BL: ±128MB */
                if ((insn & 0x7C000000) == 0x14000000) {
                    if (disp < -(1LL << 27) || disp >= (1LL << 27) || (disp & 3) != 0) {
                        count_0z++;
                    }
                }
                /* B.cond, CBZ, CBNZ: ±1MB */
                else if ((insn & 0xFF000010) == 0x54000000 || 
                         (insn & 0x7E000000) == 0x34000000) {
                    if (disp < -(1LL << 20) || disp >= (1LL << 20) || (disp & 3) != 0) {
                        count_0z++;
                    }
                }
                /* TBZ/TBNZ: ±32KB */
                else if ((insn & 0x7E000000) == 0x36000000 || 
                         (insn & 0x7E000000) == 0x37000000) {
                    if (disp < -(1LL << 15) || disp >= (1LL << 15) || (disp & 3) != 0) {
                        count_0z++;
                    }
                }
            }
        }
    }
    
    return count_0z;
}

/* I'm an engineer at heart */
void reloc_stats(reloc_table_t *table, size_t code_size) {
    if (!table) {
        DBG("[Reloc] No relocation table\n");
        return;
    }
    
    size_t by_type[8] = {0};
    size_t internal = 0, external = 0;
    size_t simd_relocs = 0;
    size_t jump_table_relocs = 0;
    
    for (size_t i = 0; i < table->count; i++) {
        reloc_entry_t *rel = &table->entries[i];
        
        if (rel->type < 8) by_type[rel->type]++;
        
        if (iz_internal(rel->target, table->original_base, code_size)) {
            internal++;
        } else {
            external++;
        }
        
        /* Detect SIMD relocations by checking instruction bytes */
        if (rel->instruction_start < code_size) {
            /* pass for now */
        }
    }
    
    DBG("[Reloc] Total: %zu entries\n", table->count);
    DBG("[Reloc] Internal: %zu, External: %zu\n", internal, external);
    DBG("[Reloc] By type: CALL=%zu JMP=%zu LEA=%zu ABS64=%zu REL32=%zu\n",
           by_type[RELOC_CALL], by_type[RELOC_JMP], by_type[RELOC_LEA],
           by_type[RELOC_ABS64], by_type[RELOC_REL32]);
}
