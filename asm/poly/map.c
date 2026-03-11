#include "map.h"
#include <string.h>
#include <stdlib.h>

#define MAX_REG 29

typedef struct {
    int first_def;
    int last_use;
    bool used;
} live_range_t;

static void patch_reg(uint32_t *w, uint8_t old_r, uint8_t new_r,
                      const arm64_inst_t *inst) {
    /* patch Rd[4:0], Rn[9:5], Rm[20:16], Ra[14:10] only if decoder id 'em  */

    /* Rd [4:0] */
    if ((*w & 0x1F) == old_r) {
        for (int j = 0; j < inst->num_regs_written; j++)
            if (inst->regs_written[j] == old_r) { *w = (*w & ~0x1Fu) | new_r; break; }
    }
    if (((*w >> 5) & 0x1F) == old_r) {
        for (int j = 0; j < inst->num_regs_read; j++)
            if (inst->regs_read[j] == old_r) { *w = (*w & ~(0x1Fu << 5)) | ((uint32_t)new_r << 5); break; }
    }

    if (((*w >> 16) & 0x1F) == old_r && inst->num_regs_read >= 2) {
        for (int j = 0; j < inst->num_regs_read; j++)
            if (inst->regs_read[j] == old_r) { *w = (*w & ~(0x1Fu << 16)) | ((uint32_t)new_r << 16); break; }
    }

    if (((*w >> 10) & 0x1F) == old_r && inst->num_regs_read >= 3) {
        for (int j = 0; j < inst->num_regs_read; j++)
            if (inst->regs_read[j] == old_r) { *w = (*w & ~(0x1Fu << 10)) | ((uint32_t)new_r << 10); break; }
    }
}

static int regalloc_recolor_range(uint8_t *code, int total_n,
                                   const arm64_inst_t *insns,
                                   const inst_live_t *live,
                                   aether_rng_t *rng, int start, int end);

int regalloc_recolor(uint8_t *code, int n, const arm64_inst_t *insns,
                     const inst_live_t *live, aether_rng_t *rng) {
    if (n < 2) return 0;

    /* Split at function boundaries (RET/RETAA) and process each independently */
    int total_renamed = 0;
    int func_start = 0;
    for (int i = 0; i <= n; i++) {
        bool is_end = (i == n) ||
                      (insns[i].op == ARM_OP_RET || insns[i].op == ARM_OP_RETAA);
        if (!is_end) continue;
        int func_end = (i < n) ? i + 1 : n; /* include the RET */
        int fn = func_end - func_start;
        if (fn >= 4) {
            total_renamed += regalloc_recolor_range(
                code, n, insns, live, rng, func_start, func_end);
        }
        func_start = func_end;
    }
    return total_renamed;
}

static int regalloc_recolor_range(uint8_t *code, int total_n,
                                   const arm64_inst_t *insns,
                                   const inst_live_t *live,
                                   aether_rng_t *rng, int start, int end) {
    int n = end - start;

    live_range_t ranges[MAX_REG];
    memset(ranges, 0, sizeof(ranges));
    for (int r = 0; r < MAX_REG; r++) { ranges[r].first_def = -1; ranges[r].last_use = -1; }

    for (int ii = 0; ii < n; ii++) {
        int i = start + ii;
        if (!insns[i].valid) continue;
        for (int j = 0; j < insns[i].num_regs_written; j++) {
            uint8_t r = insns[i].regs_written[j];
            if (r >= MAX_REG) continue;
            ranges[r].used = true;
            if (ranges[r].first_def < 0) ranges[r].first_def = ii;
            if (ii > ranges[r].last_use) ranges[r].last_use = ii;
        }
        for (int j = 0; j < insns[i].num_regs_read; j++) {
            uint8_t r = insns[i].regs_read[j];
            if (r >= MAX_REG) continue;
            ranges[r].used = true;
            if (ranges[r].first_def < 0) ranges[r].first_def = 0;
            if (ii > ranges[r].last_use) ranges[r].last_use = ii;
        }
    }

    /* Mark regs live-in at function entry or live-out at function exit */
    for (int r = 0; r < MAX_REG; r++) {
        if (live[start].live_in & (1u << r)) {
            ranges[r].used = true;
            if (ranges[r].first_def < 0) ranges[r].first_def = 0;
        }
        if (live[end-1].live_out & (1u << r)) {
            ranges[r].used = true;
            if (ranges[r].last_use < n - 1) ranges[r].last_use = n - 1;
        }
    }

    /* Mark call-clobbered regs: any BL/BLR makes X0-X18 live across the call */
    for (int ii = 0; ii < n; ii++) {
        int i = start + ii;
        if (insns[i].op == ARM_OP_BL || insns[i].op == ARM_OP_BLR) {
            for (int r = 0; r <= 18; r++) {
                ranges[r].used = true;
                if (ranges[r].first_def < 0) ranges[r].first_def = 0;
                if (ii > ranges[r].last_use) ranges[r].last_use = ii;
            }
        }
    }

    bool interfere[MAX_REG][MAX_REG];
    memset(interfere, 0, sizeof(interfere));
    for (int a = 0; a < MAX_REG; a++) {
        if (!ranges[a].used) continue;
        for (int b = a + 1; b < MAX_REG; b++) {
            if (!ranges[b].used) continue;
            if (ranges[a].first_def <= ranges[b].last_use &&
                ranges[b].first_def <= ranges[a].last_use) {
                interfere[a][b] = interfere[b][a] = true;
            }
        }
    }

    uint8_t color[MAX_REG];
    for (int r = 0; r < MAX_REG; r++) color[r] = r;

    uint8_t order[MAX_REG];
    for (int i = 0; i < MAX_REG; i++) order[i] = i;
    for (int i = MAX_REG - 1; i > 0; i--) {
        int j = aether_rand_n(rng, i + 1);
        uint8_t t = order[i]; order[i] = order[j]; order[j] = t;
    }

    int renamed = 0;
    for (int oi = 0; oi < MAX_REG; oi++) {
        uint8_t r = order[oi];
        if (!ranges[r].used) continue;
        /* Don't rename ABI args if live-in, or return values if live-out */
        if (r <= 8 && (live[start].live_in & (1u << r))) continue;
        if (live[end-1].live_out & (1u << r)) continue;
        /* Don't rename callee-saved regs (X19-X28) - they have ABI obligations */
        if (r >= 19 && r <= 28) continue;

        uint8_t cands[MAX_REG]; int nc = 0;
        for (int c = 0; c < MAX_REG; c++) cands[nc++] = c;
        for (int i = nc - 1; i > 0; i--) {
            int j = aether_rand_n(rng, i + 1);
            uint8_t t = cands[i]; cands[i] = cands[j]; cands[j] = t;
        }

        for (int ci = 0; ci < nc; ci++) {
            uint8_t c = cands[ci];
            if (c == r) continue;
            if (c <= 8 && (live[start].live_in & (1u << c))) continue;
            if (live[end-1].live_out & (1u << c)) continue;
            if (c >= 19 && c <= 28) continue;

            bool conflict = false;
            for (int other = 0; other < MAX_REG && !conflict; other++) {
                if (other == r) continue;
                if (color[other] == c && interfere[r][other]) conflict = true;
                if (color[other] == r && interfere[other][c]) conflict = true;
            }
            if (conflict) continue;

            color[r] = c;
            renamed++;
            break;
        }
    }

    if (renamed == 0) return 0;

    uint32_t *words = (uint32_t *)code;
    for (int ii = 0; ii < n; ii++) {
        int i = start + ii;
        if (!insns[i].valid || insns[i].is_control_flow || insns[i].is_privileged) continue;
        for (int r = 0; r < MAX_REG; r++) {
            if (color[r] == r) continue;
            bool uses = false;
            for (int j = 0; j < insns[i].num_regs_written; j++)
                if (insns[i].regs_written[j] == r) uses = true;
            for (int j = 0; j < insns[i].num_regs_read; j++)
                if (insns[i].regs_read[j] == r) uses = true;
            if (uses) patch_reg(&words[i], r, color[r], &insns[i]);
        }
    }

    return renamed;
}
