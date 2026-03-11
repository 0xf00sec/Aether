#include "arm64.h"
#include "flow.h"
#include "xfrm.h"
#include "ir.h"
#include "map.h"
#include <stdlib.h>
#include <string.h>

static size_t aether_mutate_single(uint8_t *code, size_t size, size_t max_size,
                                  aether_rng_t *rng, unsigned intensity,
                                  uint64_t text_vmaddr, uint64_t text_vmend);

size_t aether_mutate(uint8_t *code, size_t size, size_t max_size,
                   aether_rng_t *rng, unsigned intensity, unsigned passes,
                   uint64_t text_vmaddr, uint64_t text_vmend) {
    if (!code || size < 16 || size % 4 || max_size < size || !rng) return 0;
    if (passes == 0) passes = 1;
    if (passes > 3) passes = 3;
    size_t current_size = size;
    bool can_grow = (max_size > size);
    if (can_grow) passes = 1;
    for (unsigned pass = 0; pass < passes; pass++) {
        size_t new_size = aether_mutate_single(code, current_size, max_size,
                                              rng, intensity, text_vmaddr, text_vmend);
        if (new_size == 0) return current_size;
        current_size = new_size;
        if (current_size >= max_size - 256) break;
    }
    return current_size;
}

static size_t aether_mutate_single(uint8_t *code, size_t size, size_t max_size,
                                  aether_rng_t *rng, unsigned intensity,
                                  uint64_t text_vmaddr, uint64_t text_vmend) {
    if (!code || size < 16 || size % 4 || max_size < size) return 0;
    
    int n = size / 4;
    int max_out = max_size / 4;
    bool can_grow = (max_size > size);
    arm64_inst_t *insns = calloc(n, sizeof(arm64_inst_t));
    inst_live_t *live = calloc(n, sizeof(inst_live_t));
    if (!insns || !live) { free(insns); free(live); return 0; }
    
    
    for (int i = 0; i < n; i++)
        if (!arm64_decode(code + i * 4, &insns[i])) insns[i].valid = 0;
    
    
    liveness_full(insns, n, live);
    
    

    uint32_t *out = calloc(max_size / 4, sizeof(uint32_t));
    int *orig_to_new = calloc(n, sizeof(int));
    if (!out || !orig_to_new) { free(insns); free(live); free(out); free(orig_to_new); return 0; }
    for (int i = 0; i < n; i++) orig_to_new[i] = -1;
    
    int out_n = 0;
    mutate_ctx_t ctx = { .insns = insns, .live = live, .n = n, .rng = rng };
    
    for (int i = 0; i < n; i++) {
        ctx.idx = i;
        
        
        if (!insns[i].valid || insns[i].is_privileged) {
            orig_to_new[i] = out_n;
            out[out_n++] = insns[i].raw;
            continue;
        }
        
        uint32_t r = aether_rand(rng);
        unsigned choice = (r >> 16) % 100;
        
        if ((!can_grow || choice < intensity * 2) && !insns[i].is_control_flow) {
            uint32_t sub[3];
            int ns = equiv_subst(&ctx, sub);
            if (ns > 0 && (can_grow || ns == 1)) {
                orig_to_new[i] = out_n;
                for (int j = 0; j < ns; j++) out[out_n++] = sub[j];
                continue;
            }
        }
        
        if (can_grow && choice >= 20 && choice < 20 + intensity * 1.5) {
            uint32_t junk = gen_junk(&ctx);
            if (junk != 0xD503201F) out[out_n++] = junk;
        }
        
        if (can_grow && choice >= 35 && choice < 35 + intensity) {
            uint32_t junk = gen_live_junk(&ctx);
            if (junk != 0xD503201F) out[out_n++] = junk;
        }
        
        if (can_grow && choice >= 45 && choice < 45 + intensity / 2 && i + 1 < n && !insns[i].is_control_flow) {
            uint32_t opaque[2];
            if (gen_opaque_predicate(&ctx, opaque, false, 8) == 2) {
                out[out_n++] = opaque[0];
                out[out_n++] = opaque[1];
            }
        }
    
        orig_to_new[i] = out_n;
        out[out_n++] = insns[i].raw;
        
        if (can_grow && out_n * 4 >= (int)max_size - 64) break;
    }
    
    /* Resolve all PC-relative branches using position map      
     * Must run BEFORE reordering/permutation those operations invalidate
     * the orig_to_new map by moving instructions to new positions.
     * Reorder/permute only swap independent instructions, so resolved
     * branch offsets remain correct after reordering.
     */
    for (int i = 0; i < out_n; i++) {
        uint32_t w = out[i];
        int orig_idx = -1;
        int new_imm = 0;
        
        for (int j = 0; j < n; j++) {
            if (orig_to_new[j] == i) { orig_idx = j; break; }
        }
        if (orig_idx < 0) continue;
        
        if ((w & 0x7C000000) == 0x14000000) {
            int32_t imm26 = (int32_t)(w & 0x3FFFFFF);
            if (imm26 & 0x2000000) imm26 |= (int32_t)0xFC000000;
            int tgt = orig_idx + imm26;
            new_imm = (tgt >= 0 && tgt < n && orig_to_new[tgt] >= 0)
                      ? orig_to_new[tgt] - i : (orig_idx + imm26) - i;
            out[i] = (w & 0xFC000000) | ((uint32_t)new_imm & 0x3FFFFFF);
            continue;
        }
        if ((w & 0xFF000010) == 0x54000000) {
            int32_t imm19 = (int32_t)((w >> 5) & 0x7FFFF);
            if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000;
            int tgt = orig_idx + imm19;
            new_imm = (tgt >= 0 && tgt < n && orig_to_new[tgt] >= 0)
                      ? orig_to_new[tgt] - i : (orig_idx + imm19) - i;
            out[i] = (w & 0xFF00001F) | (((uint32_t)new_imm & 0x7FFFF) << 5);
            continue;
        }
        if ((w & 0x7E000000) == 0x34000000) {
            int32_t imm19 = (int32_t)((w >> 5) & 0x7FFFF);
            if (imm19 & 0x40000) imm19 |= (int32_t)0xFFF80000;
            int tgt = orig_idx + imm19;
            new_imm = (tgt >= 0 && tgt < n && orig_to_new[tgt] >= 0)
                      ? orig_to_new[tgt] - i : (orig_idx + imm19) - i;
            out[i] = (w & 0xFF00001F) | (((uint32_t)new_imm & 0x7FFFF) << 5);
            continue;
        }
        if ((w & 0x7E000000) == 0x36000000) {
            int32_t imm14 = (int32_t)((w >> 5) & 0x3FFF);
            if (imm14 & 0x2000) imm14 |= (int32_t)0xFFFFC000;
            int tgt = orig_idx + imm14;
            new_imm = (tgt >= 0 && tgt < n && orig_to_new[tgt] >= 0)
                      ? orig_to_new[tgt] - i : (orig_idx + imm14) - i;
            out[i] = (w & 0xFFF8001F) | (((uint32_t)new_imm & 0x3FFF) << 5);
            continue;
        }
    }

    
    {
        ir_inst_t *ir_buf = calloc(out_n, sizeof(ir_inst_t));
        if (ir_buf) {
            for (int i = 0; i < out_n; i++)
                ir_lift((uint8_t *)&out[i], &ir_buf[i]);
            ir_transform(ir_buf, out_n, aether_rand(rng));
            for (int i = 0; i < out_n; i++)
                ir_lower(&ir_buf[i], &out[i]);
            free(ir_buf);
        }
    }

    
    for (int i = 0; i < out_n - 5; i += 3) {
        if (aether_rand(rng) % 10 < 3) {
            arm64_inst_t win_insns[16];
            int win_len = (out_n - i < 8) ? out_n - i : 8;
            for (int j = 0; j < win_len; j++)
                arm64_decode((uint8_t*)&out[i + j], &win_insns[j]);
            
            inst_live_t win_live[16];
            liveness_window(win_insns, win_len, win_live, 0, win_len - 1);
            
            int swaps = reorder_window(win_insns, win_live, 0, win_len, rng);
            if (swaps > 0) {
                for (int j = 0; j < win_len; j++)
                    out[i + j] = win_insns[j].raw;
            }
        }
    }
    
    
    if ((aether_rand(rng) & 0xFF) < intensity && out_n > n) {
        uint32_t *perm = calloc(max_size / 4, sizeof(uint32_t));
        if (perm) {
            arm64_inst_t *out_insns = calloc(out_n, sizeof(arm64_inst_t));
            if (out_insns) {
                for (int i = 0; i < out_n; i++)
                    arm64_decode((uint8_t*)&out[i], &out_insns[i]);
                size_t pn = permute_blocks(out_insns, out_n, perm, max_size / 4, rng);
                if (pn > 0 && pn < max_size / 4) {
                    memcpy(out, perm, pn * 4);
                    out_n = pn;
                }
                free(out_insns);
            }
            free(perm);
        }
    }
    
    
    {
        arm64_inst_t *ra_insns = calloc(out_n, sizeof(arm64_inst_t));
        inst_live_t *ra_live = calloc(out_n, sizeof(inst_live_t));
        if (ra_insns && ra_live) {
            for (int i = 0; i < out_n; i++)
                arm64_decode((uint8_t *)&out[i], &ra_insns[i]);
            liveness_full(ra_insns, out_n, ra_live);
            regalloc_recolor((uint8_t *)out, out_n, ra_insns, ra_live, rng);
        }
        free(ra_insns); free(ra_live);
    }

    size_t new_size = out_n * 4;
    if (!can_grow) {
        
        while (out_n * 4 < (int)size) out[out_n++] = 0xD503201F; 
        new_size = size;
    }
    if (new_size <= max_size) {
        memcpy(code, out, new_size);
        free(insns); free(live); free(out); free(orig_to_new);
        return new_size;
    }
    
    free(insns); free(live); free(out); free(orig_to_new);
    return 0;
}
