#ifndef AETHER_LIVENESS_H
#define AETHER_LIVENESS_H

#include "arm64.h"

typedef uint32_t regset_t;

#define REG_BIT(r)    (1u << (r))
#define FLAGS_BIT     (1u << 31)

/* Stack slot tracking */

#define MAX_SLOTS     16   /* max tracked SP-relative slots */

typedef struct {
    int16_t  offset;       
    uint8_t  size;         /* access size in bytes (1/2/4/8) */
} stack_slot_t;

typedef struct {
    stack_slot_t slots[MAX_SLOTS]; 
    uint8_t      num_slots;        /* number of active slots */
    uint16_t     live_in;         
    uint16_t     live_out;         
    uint16_t     def;           
    uint16_t     use;             
} slot_live_t;

/* Per-instruction liveness */
typedef struct {
    regset_t live_in;
    regset_t live_out;
    regset_t def;
    regset_t use;
} inst_live_t;

void liveness_window(const arm64_inst_t *insns, int n,
                     inst_live_t *out, int win_start, int win_end);

int liveness_full(const arm64_inst_t *insns, int n, inst_live_t *out);

/* Query helpers */

/* Is register r dead after instruction idx? */
static inline bool reg_is_dead(const inst_live_t *live, int idx, uint8_t r) {
    return r < 31 && !(live[idx].live_out & REG_BIT(r));
}

/* Are NZCV flags dead after instruction idx? (safe to insert flag-clobbering junk) */
static inline bool flags_are_dead(const inst_live_t *live, int idx) {
    return !(live[idx].live_out & FLAGS_BIT);
}

/* Registers dead after idx, excluding X29(FP)/X30(LR)/SP - safe for junk/rename */
static inline regset_t dead_regs(const inst_live_t *live, int idx) {
    /* X19-X28 are callee-saved (ABI), never treat as dead for junk insertion */
    const regset_t CALLEE_SAVED = 0x1FF80000u; /* bits 19-28 */
    return ~live[idx].live_out & 0x1FFFFFFFu & ~CALLEE_SAVED;
}

int stack_liveness(const arm64_inst_t *insns, int n, slot_live_t *out);

static inline bool slot_is_safe(const slot_live_t *slive, int idx,
                                int16_t offset, uint8_t size) {
    for (int s = 0; s < slive[0].num_slots; s++) {
        if (!(slive[idx].live_out & (1u << s))) continue; /* slot not live, fine */
        int16_t so = slive[0].slots[s].offset;
        uint8_t ss = slive[0].slots[s].size;
        if (offset < so + ss && so < offset + size)
            return false; /* overlaps a live slot */
    }
    return true;
}

typedef struct {
    uint8_t  reg;          /* register number */
    uint16_t def_idx;      
    uint16_t use_idx[8];   /* instruction indices that consume this def */
    uint8_t  num_uses;     
} def_use_t;

int build_def_use(const arm64_inst_t *insns, const inst_live_t *live,
                  int n, uint8_t reg, def_use_t *chains, int max_chains);

int detect_loops(const arm64_inst_t *insns, int n, bool *loop_body);

regset_t loop_live_regs(const arm64_inst_t *insns, const inst_live_t *live,
                        int n, const bool *loop_body, int idx);

#endif /* AETHER_LIVENESS_H */
