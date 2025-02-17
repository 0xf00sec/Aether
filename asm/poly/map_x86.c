#include "map_x86.h"
#include <string.h>
#include <stdlib.h>

#define MAX_REG 16
#define UNSAFE(r) ((r) == X86_REG_RSP || (r) == X86_REG_RBP)
#define CALLEE_SAVED(r) ((r) == X86_REG_RBX || ((r) >= X86_REG_R12 && (r) <= X86_REG_R15))

typedef struct { int first_def, last_use; bool used; } live_range_t;

/* Patch register in a raw x86 instruction */
static bool patch_x86_reg(uint8_t *raw, uint8_t len, const x86_inst_t *inst,
                          uint8_t old_r, uint8_t new_r) {
    if (!inst->has_modrm) return false;
    uint8_t mod = x86_modrm_mod(inst->modrm);
    if (mod != 3) return false; /* only reg-reg */

    /* Find modrm byte offset in instruction */
    int modrm_off = inst->prefix_count + (inst->rex ? 1 : 0) + inst->opcode_len;
    if (modrm_off >= len) return false;

    bool patched = false;
    uint8_t new_modrm = raw[modrm_off];

    /* Patch reg field (bits [5:3]) */
    if (inst->reg == old_r) {
        new_modrm = (new_modrm & 0xC7) | ((new_r & 7) << 3);
        /* Fix REX.R */
        if (inst->rex) {
            int rex_off = modrm_off - inst->opcode_len;
            if (rex_off >= 0) {
                raw[rex_off] = (raw[rex_off] & ~0x04) | ((new_r >= 8) ? 0x04 : 0);
            }
        }
        patched = true;
    }

    /* Patch rm field (bits [2:0]) */
    if (inst->rm == old_r) {
        new_modrm = (new_modrm & 0xF8) | (new_r & 7);
        /* Fix REX.B */
        if (inst->rex) {
            int rex_off = modrm_off - inst->opcode_len;
            if (rex_off >= 0) {
                raw[rex_off] = (raw[rex_off] & ~0x01) | ((new_r >= 8) ? 0x01 : 0);
            }
        }
        patched = true;
    }

    if (patched) raw[modrm_off] = new_modrm;

    /* Verify the patched instruction still decodes correctly */
    if (patched) {
        x86_inst_t check;
        if (!x86_decode(raw, len, &check) || !check.valid || check.len != len)
            return false;
    }
    return patched;
}

int x86_regalloc_recolor(uint8_t *code, const x86_inst_t *insns, int n,
                         const x86_inst_live_t *live, aether_rng_t *rng) {
    if (n < 4) return 0;

    live_range_t ranges[MAX_REG];
    memset(ranges, 0, sizeof(ranges));
    for (int r = 0; r < MAX_REG; r++) { ranges[r].first_def = -1; ranges[r].last_use = -1; }

    for (int i = 0; i < n; i++) {
        if (!insns[i].valid) continue;
        for (int j = 0; j < insns[i].num_regs_written; j++) {
            uint8_t r = insns[i].regs_written[j];
            if (r >= MAX_REG) continue;
            ranges[r].used = true;
            if (ranges[r].first_def < 0) ranges[r].first_def = i;
            if (i > ranges[r].last_use) ranges[r].last_use = i;
        }
        for (int j = 0; j < insns[i].num_regs_read; j++) {
            uint8_t r = insns[i].regs_read[j];
            if (r >= MAX_REG) continue;
            ranges[r].used = true;
            if (ranges[r].first_def < 0) ranges[r].first_def = 0;
            if (i > ranges[r].last_use) ranges[r].last_use = i;
        }
    }

    for (int r = 0; r < MAX_REG; r++) {
        if (live[0].live_in & X86_REG_BIT(r)) {
            ranges[r].used = true;
            if (ranges[r].first_def < 0) ranges[r].first_def = 0;
        }
        if (live[n-1].live_out & X86_REG_BIT(r)) {
            ranges[r].used = true;
            if (ranges[r].last_use < n - 1) ranges[r].last_use = n - 1;
        }
    }

    /* Calls extend volatile reg ranges */
    for (int i = 0; i < n; i++) {
        if (insns[i].op == X86_OP_CALL) {
            const uint8_t vol[] = {0,1,2,6,7,8,9,10,11};
            for (int v = 0; v < 9; v++) {
                uint8_t r = vol[v];
                ranges[r].used = true;
                if (ranges[r].first_def < 0) ranges[r].first_def = 0;
                if (i > ranges[r].last_use) ranges[r].last_use = i;
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
                ranges[b].first_def <= ranges[a].last_use)
                interfere[a][b] = interfere[b][a] = true;
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
        if (!ranges[r].used || UNSAFE(r) || CALLEE_SAVED(r)) continue;
        if (live[0].live_in & X86_REG_BIT(r)) continue;
        if (live[n-1].live_out & X86_REG_BIT(r)) continue;

        for (int ci = 0; ci < MAX_REG; ci++) {
            uint8_t c = order[ci]; /* try in random order */
            if (c == r || UNSAFE(c) || CALLEE_SAVED(c)) continue;
            if (live[0].live_in & X86_REG_BIT(c)) continue;
            if (live[n-1].live_out & X86_REG_BIT(c)) continue;

            bool conflict = false;
            for (int o = 0; o < MAX_REG && !conflict; o++) {
                if (o == r) continue;
                if (color[o] == c && interfere[r][o]) conflict = true;
            }
            if (!conflict) { color[r] = c; renamed++; break; }
        }
    }

    if (renamed == 0) return 0;

    /* Build byte offset table */
    int offsets[4096];
    int off = 0;
    for (int i = 0; i < n && i < 4096; i++) { offsets[i] = off; off += insns[i].len; }

    for (int i = 0; i < n; i++) {
        if (!insns[i].valid || insns[i].is_control_flow || insns[i].is_privileged ||
            insns[i].is_simd) continue;
        for (int r = 0; r < MAX_REG; r++) {
            if (color[r] == r) continue;
            bool uses = false;
            for (int j = 0; j < insns[i].num_regs_written; j++)
                if (insns[i].regs_written[j] == r) uses = true;
            for (int j = 0; j < insns[i].num_regs_read; j++)
                if (insns[i].regs_read[j] == r) uses = true;
            if (uses) patch_x86_reg(code + offsets[i], insns[i].len, &insns[i], r, color[r]);
        }
    }

    return renamed;
}