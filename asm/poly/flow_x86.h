#ifndef AETHER_LIVENESS_X86_H
#define AETHER_LIVENESS_X86_H

#include "x86.h"

/* bits 0-15 = RAX-R15, bit 31 = RFLAGS */
typedef uint32_t x86_regset_t;

#define X86_REG_BIT(r)   (1u << (r))
#define X86_FLAGS_BIT    (1u << 31)

typedef struct {
    x86_regset_t live_in;
    x86_regset_t live_out;
    x86_regset_t def;
    x86_regset_t use;
} x86_inst_live_t;

void x86_liveness_window(const x86_inst_t *insns, int n,
                         x86_inst_live_t *out, int win_start, int win_end);

int x86_liveness_full(const x86_inst_t *insns, int n, x86_inst_live_t *out);

/* Query helpers */
static inline bool x86_reg_is_dead(const x86_inst_live_t *live, int idx, uint8_t r) {
    return r < 16 && !(live[idx].live_out & X86_REG_BIT(r));
}

static inline bool x86_flags_are_dead(const x86_inst_live_t *live, int idx) {
    return !(live[idx].live_out & X86_FLAGS_BIT);
}

/* Dead volatile regs (safe for junk/rename), excluding RSP/RBP */
static inline x86_regset_t x86_dead_regs(const x86_inst_live_t *live, int idx) {
    const x86_regset_t UNSAFE = X86_REG_BIT(X86_REG_RSP) | X86_REG_BIT(X86_REG_RBP);
    const x86_regset_t CALLEE_SAVED = X86_REG_BIT(X86_REG_RBX) | X86_REG_BIT(X86_REG_R12) |
                                       X86_REG_BIT(X86_REG_R13) | X86_REG_BIT(X86_REG_R14) |
                                       X86_REG_BIT(X86_REG_R15);
    return ~live[idx].live_out & 0xFFFFu & ~UNSAFE & ~CALLEE_SAVED;
}

#endif
