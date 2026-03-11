#include "link_x86.h"
#include "x86.h"
#include "flow_x86.h"
#include "xfrm_x86.h"
#include "ir.h"
#include "map_x86.h"
#include <stdlib.h>
#include <string.h>

size_t aether_mutate_x86(uint8_t *code, size_t size, size_t max_size,
                       aether_rng_t *rng, unsigned intensity, unsigned passes) {
    if (!code || size < 2 || max_size < size || !rng) return 0;
    if (passes == 0) passes = 1;
    if (passes > 3) passes = 3;

    size_t cur = size;
    for (unsigned pass = 0; pass < passes; pass++) {
        size_t ns = aether_mutate_x86_single(code, cur, max_size, rng, intensity);
        if (ns == 0) return cur;
        cur = ns;
        if (cur >= max_size - 64) break;
    }
    return cur;
}

size_t aether_mutate_x86_single(uint8_t *code, size_t size, size_t max_size,
                               aether_rng_t *rng, unsigned intensity) {
    if (!code || size < 2 || max_size < size) return 0;

    /* Decode */
    int max_insns = size; /* worst case: 1-byte instructions */
    if (max_insns > 8192) max_insns = 8192;
    x86_inst_t *insns = calloc(max_insns, sizeof(x86_inst_t));
    if (!insns) return 0;

    int n = 0;
    size_t off = 0;
    while (off < size && n < max_insns) {
        if (!x86_decode(code + off, size - off, &insns[n]) || !insns[n].valid) {
            off++; continue; /* skip bad byte */
        }
        off += insns[n].len;
        n++;
    }
    if (n < 4) { free(insns); return 0; }

    /* Liveness */
    x86_inst_live_t *live = calloc(n, sizeof(x86_inst_live_t));
    if (!live) { free(insns); return 0; }
    x86_liveness_full(insns, n, live);

    /* Emit mutated code with junk/equiv/opaques */
    bool can_grow = (max_size > size);
    uint8_t *out = calloc(1, max_size);
    int *orig_to_new = calloc(n, sizeof(int)); /* byte offset map */
    if (!out || !orig_to_new) { free(insns); free(live); free(out); free(orig_to_new); return 0; }

    size_t out_off = 0;
    x86_mutate_ctx_t ctx = { insns, live, n, 0, rng };

    for (int i = 0; i < n; i++) {
        ctx.idx = i;
        orig_to_new[i] = (int)out_off;

        if (!insns[i].valid || insns[i].is_privileged) {
            memcpy(out + out_off, insns[i].raw, insns[i].len);
            out_off += insns[i].len;
            continue;
        }

        uint32_t r = aether_rand(rng);
        unsigned choice = (r >> 16) % 100;

        if (choice < intensity * 2 && !insns[i].is_control_flow) {
            uint8_t sub[15];
            int slen = x86_equiv_subst(&ctx, sub);
            if (slen > 0) {
                memcpy(out + out_off, sub, slen);
                out_off += slen;
                continue;
            }
        }

        if (can_grow && choice >= 20 && choice < 20 + (unsigned)(intensity * 1.5)) {
            uint8_t junk[15];
            int jlen = x86_gen_junk(&ctx, junk);
            if (jlen > 0 && out_off + jlen + insns[i].len < max_size) {
                memcpy(out + out_off, junk, jlen);
                out_off += jlen;
            }
        }

        if (can_grow && choice >= 35 && choice < 35 + intensity) {
            uint8_t junk[15];
            int jlen = x86_gen_live_junk(&ctx, junk);
            if (jlen > 0 && out_off + jlen + insns[i].len < max_size) {
                memcpy(out + out_off, junk, jlen);
                out_off += jlen;
            }
        }

        if (can_grow && choice >= 45 && choice < 45 + intensity / 2 &&
            !insns[i].is_control_flow) {
            uint8_t opaque[32];
            int olen = x86_gen_opaque(&ctx, opaque, (int32_t)insns[i].len);
            if (olen > 0 && out_off + olen + insns[i].len < max_size) {
                memcpy(out + out_off, opaque, olen);
                out_off += olen;
            }
        }

        /* Emit original */
        memcpy(out + out_off, insns[i].raw, insns[i].len);
        out_off += insns[i].len;

        if (can_grow && out_off >= max_size - 32) break;
    }

    /* Resolve relative branches using orig_to_new map */
    /* Re-decode the output to find branches */
    x86_inst_t *out_insns = calloc(max_insns * 2, sizeof(x86_inst_t));
    int out_n = 0;
    off = 0;
    if (out_insns) {
        while (off < out_off && out_n < max_insns * 2) {
            if (!x86_decode(out + off, out_off - off, &out_insns[out_n]) || !out_insns[out_n].valid) {
                off++; continue;
            }
            off += out_insns[out_n].len;
            out_n++;
        }
    }

    /* IR transforms on output */
    if (out_insns && out_n > 0) {
        ir_inst_t *ir_buf = calloc(out_n, sizeof(ir_inst_t));
        if (ir_buf) {
            for (int i = 0; i < out_n; i++)
                ir_lift_x86(&out_insns[i], &ir_buf[i]);
            int transforms = ir_transform(ir_buf, out_n, aether_rand(rng));
            (void)transforms;
            /* Lower back - rebuild output buffer */
            if (transforms > 0) {
                size_t new_off = 0;
                for (int i = 0; i < out_n; i++) {
                    int blen = ir_lower_x86(&ir_buf[i], out + new_off);
                    new_off += blen;
                }
                out_off = new_off;
            }
            free(ir_buf);
        }
    }

    /* Re-decode for reorder + regalloc */
    if (out_insns) {
        out_n = 0; off = 0;
        while (off < out_off && out_n < max_insns * 2) {
            if (!x86_decode(out + off, out_off - off, &out_insns[out_n]) || !out_insns[out_n].valid) {
                off++; continue;
            }
            off += out_insns[out_n].len;
            out_n++;
        }

        x86_inst_live_t *out_live = calloc(out_n, sizeof(x86_inst_live_t));
        if (out_live && out_n >= 4) {
            x86_liveness_full(out_insns, out_n, out_live);

            for (int i = 0; i < out_n - 5; i += 3) {
                if (aether_rand(rng) % 10 < 3) {
                    int wlen = (out_n - i < 8) ? out_n - i : 8;
                    x86_reorder_window(out_insns + i, out_live + i, 0, wlen, rng);
                }
            }

            /* Regalloc recolor */
            x86_regalloc_recolor(out, out_insns, out_n, out_live, rng);

            free(out_live);
        }
    }

    /* Copy result back */
    if (out_off > 0 && out_off <= max_size) {
        memcpy(code, out, out_off);
    } else {
        out_off = 0;
    }

    free(insns); free(live); free(out); free(orig_to_new); free(out_insns);
    return out_off ? out_off : size;
}
