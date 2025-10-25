#include <aether.h>

/* https:/*www.coranac.com/tonc/text/asm.htm */ */

#if defined(ARCH_ARM)

/* Read u32 little-endian */
static inline uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline arm_reg_t rd(const uint32_t insn) { return (arm_reg_t)(insn & 0x1F); }
static inline arm_reg_t rn(const uint32_t insn) { return (arm_reg_t)((insn >> 5) & 0x1F); }
static inline arm_reg_t rm(const uint32_t insn) { return (arm_reg_t)((insn >> 16) & 0x1F); }
static inline arm_reg_t ra(const uint32_t insn) { return (arm_reg_t)((insn >> 10) & 0x1F); }
static inline arm_reg_t rt2(const uint32_t insn) { return (arm_reg_t)((insn >> 10) & 0x1F); }

static inline uint32_t bits(const uint32_t x, int hi, int lo) { 
    return (x >> lo) & ((1u << (hi - lo + 1)) - 1u); 
}

static inline int64_t sxt64(uint64_t v, int nbits) {
    const uint64_t m = 1ULL << (nbits - 1);
    return (int64_t)((v ^ m) - m);
}

/* Track register read (up to 4 per instruction) */
static inline void track_read(arm64_inst_t *out, arm_reg_t reg) {
    if (reg < 32 && out->num_regs_read < 4) {
        out->regs_read[out->num_regs_read++] = reg;
    }
}

/* Track register write (up to 2 per instruction) */
static inline void track_write(arm64_inst_t *out, arm_reg_t reg) {
    if (reg < 32 && out->num_regs_written < 2) {
        out->regs_written[out->num_regs_written++] = reg;
    }
}

/* Does this instruction modify PC? */
static bool is_cfi(uint32_t insn) {
    if ((insn & 0x7C000000u) == 0x14000000u) return true;                   
    if ((insn & 0xFF000010u) == 0x54000000u) return true;                   
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) return true;                   
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return true;                   
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return true;                   
    return false;
}

/* Privileged instruction? (needs EL1+) */
static bool is_priv(uint32_t insn) {
    if ((insn & 0xFFE0001Fu) == 0xD4000001u) return true;                   
    if ((insn & 0xFFC00000u) == 0xD5000000u) return true;                   
    if ((insn & 0xFFF00000u) == 0xD5300000u) return true;                   
    if ((insn & 0xFFF00000u) == 0xD5100000u) return true;                   
    return false;
}

/**
 * Handles 40+ instruction types branches, data processing, load/store,
 * system instructions. Tracks register reads/writes, immediates, targets.
 */
bool decode_arm64(const uint8_t *code, arm64_inst_t *out) {
    memset(out, 0, sizeof(*out));
    const uint32_t insn = rd_u32(code);

    out->raw         = insn;
    out->opcode      = (insn >> 21) & 0x7FF;
    out->opcode_len  = 4;
    out->len         = 4;
    out->valid       = true;
    out->is_signed   = false;
    out->is_privileged = is_priv(insn);
    out->privileged    = out->is_privileged;     
    out->ring0         = out->is_privileged;     
    out->is_control_flow = is_cfi(insn);
    out->modifies_ip     = out->is_control_flow;
    out->type         = ARM_OP_NONE;
    out->is_64bit     = false;
    out->num_regs_read = 0;
    out->num_regs_written = 0;                   
    
    /* B/BL (unconditional branch immediate) */
    if ((insn & 0x7C000000u) == 0x14000000u) {
        const uint32_t imm26 = bits(insn, 25, 0);
        const int64_t off    = sxt64(imm26, 26) << 2;
        const bool link      = (insn >> 31) & 1;

        out->type            = link ? ARM_OP_BRANCH_LINK : ARM_OP_BRANCH;
        out->rd              = ARM_REG_PC;
        out->imm             = off;
        out->target          = off;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        
        if (link) {
            track_write(out, ARM64_REG_X30);  /* LR is written */
        }
        return true;
    }

    /* B.cond (conditional branch) */
    if ((insn & 0xFF000010u) == 0x54000000u) {
        const uint32_t imm19 = bits(insn, 23, 5);
        const int64_t off    = sxt64(imm19, 19) << 2;
        const uint8_t cond   = bits(insn, 3, 0);

        out->type            = ARM_OP_BRANCH_COND;
        out->condition       = (arm_condition_t)cond;
        out->imm             = off;
        out->target          = off;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        return true;
    }
    
    /* CBZ/CBNZ (compare and branch on zero/nonzero) */
    if ((insn & 0x7E000000u) == 0x34000000u) {
        const bool sf        = (insn >> 31) & 1;
        const bool nz        = (insn >> 24) & 1;
        const uint32_t imm19 = bits(insn, 23, 5);
        const int64_t off    = sxt64(imm19, 19) << 2;
        const arm_reg_t rt   = rd(insn);
        
        out->type            = nz ? ARM_OP_CBNZ : ARM_OP_CBZ;
        out->rd              = rt;
        out->imm             = off;
        out->target          = off;
        out->is_64bit        = sf;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        
        track_read(out, rt);
        return true;
    }
    
    /* TBZ/TBNZ (test bit and branch) */
    if ((insn & 0x7E000000u) == 0x36000000u) {
        const bool b5        = (insn >> 31) & 1;
        const bool nz        = (insn >> 24) & 1;
        const uint32_t b40   = bits(insn, 23, 19);
        const uint32_t imm14 = bits(insn, 18, 5);
        const int64_t off    = sxt64(imm14, 14) << 2;
        const arm_reg_t rt   = rd(insn);
        const uint8_t bit    = (b5 << 5) | b40;
        
        out->type            = nz ? ARM_OP_TBNZ : ARM_OP_TBZ;
        out->rd              = rt;
        out->imm             = bit;  /* Bit position */
        out->target          = off;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        
        track_read(out, rt);
        return true;
    }

    /* BR (branch to register) */
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {
        const arm_reg_t reg_n = rn(insn);
        
        out->type            = ARM_OP_BRANCH;
        out->rn              = reg_n;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        
        track_read(out, reg_n);
        return true;
    }
    
    /* BLR (branch with link to register) */
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) {
        const arm_reg_t reg_n = rn(insn);
        
        out->type            = ARM_OP_BRANCH_LINK;
        out->rn              = reg_n;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        
        track_read(out, reg_n);
        track_write(out, ARM64_REG_X30);  /* LR is written */
        return true;
    }

    /* RET (return from subroutine) */
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) {
        const arm_reg_t reg_n = rn(insn);
        
        out->type            = ARM_OP_RET;
        out->rn              = reg_n;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        
        track_read(out, reg_n);
        return true;
    }

    /* Add/Sub (immediate) */
    if ((insn & 0x1F000000u) == 0x11000000u) {
        const bool sf        = (insn >> 31) & 1;
        const bool op        = (insn >> 30) & 1;
        const bool S         = (insn >> 29) & 1;
        const bool sh        = (insn >> 22) & 1;
        const uint32_t imm12 = bits(insn, 21, 10);
        const arm_reg_t reg_d = rd(insn);
        const arm_reg_t reg_n = rn(insn);

        /* CMP/CMN are aliases when rd == XZR */
        if (S && reg_d == 31) {
            out->type = op ? ARM_OP_CMP : ARM_OP_CMN;
            out->rn   = reg_n;
            track_read(out, reg_n);
        } else {
            out->type = op ? ARM_OP_SUB : ARM_OP_ADD;
            out->rd   = reg_d;
            out->rn   = reg_n;
            track_read(out, reg_n);
            track_write(out, reg_d);
        }
        
        out->imm      = (uint64_t)imm12 << (sh ? 12 : 0);
        out->imm_size = sh ? 24 : 12;
        out->is_64bit = sf;
        return true;
    }

    /* Add/Sub (register) */
    if ((insn & 0x1F000000u) == 0x0B000000u) {
        const bool sf        = (insn >> 31) & 1;
        const bool op        = (insn >> 30) & 1;
        const bool S         = (insn >> 29) & 1;
        const arm_reg_t reg_d = rd(insn);
        const arm_reg_t reg_n = rn(insn);
        const arm_reg_t reg_m = rm(insn);
        const uint8_t shift   = bits(insn, 23, 22);
        const uint8_t amount  = bits(insn, 15, 10);

        /* CMP/CMN are aliases when rd == XZR */
        if (S && reg_d == 31) {
            out->type = op ? ARM_OP_CMP : ARM_OP_CMN;
            out->rn   = reg_n;
            out->rm   = reg_m;
            track_read(out, reg_n);
            track_read(out, reg_m);
        } else {
            out->type = op ? ARM_OP_SUB : ARM_OP_ADD;
            out->rd   = reg_d;
            out->rn   = reg_n;
            out->rm   = reg_m;
            track_read(out, reg_n);
            track_read(out, reg_m);
            track_write(out, reg_d);
        }
        
        out->shift_type   = shift;
        out->shift_amount = amount;
        out->is_64bit     = sf;
        return true;
    }
    
    /* Logical (shifted register) + MOV alias */
    if ((insn & 0x1F000000u) == 0x0A000000u) {
        const bool sf        = (insn >> 31) & 1;
        const uint32_t opc   = bits(insn, 30, 29);
        const uint32_t shift = bits(insn, 23, 22);
        const uint32_t imm6  = bits(insn, 15, 10);
        const arm_reg_t reg_d = rd(insn);
        const arm_reg_t reg_n = rn(insn);
        const arm_reg_t reg_m = rm(insn);

        /* MOV (register) is an alias of ORR with rn == XZR */
        if (opc == 1 && reg_n == 31 && shift == 0 && imm6 == 0) {
            out->type     = ARM_OP_MOV;
            out->rd       = reg_d;
            out->rm       = reg_m;
            out->is_64bit = sf;
            track_read(out, reg_m);
            track_write(out, reg_d);
            return true;
        }

        /* TST is an alias of ANDS with rd == XZR */
        if (opc == 3 && reg_d == 31) {
            out->type = ARM_OP_TST;
            out->rn   = reg_n;
            out->rm   = reg_m;
            track_read(out, reg_n);
            track_read(out, reg_m);
        } else {
            switch (opc) {
                case 0: out->type = ARM_OP_AND; break;
                case 1: out->type = ARM_OP_ORR; break;
                case 2: out->type = ARM_OP_EOR; break;
                case 3: out->type = ARM_OP_AND; break;  /* ANDS */
            }
            out->rd = reg_d;
            out->rn = reg_n;
            out->rm = reg_m;
            track_read(out, reg_n);
            track_read(out, reg_m);
            track_write(out, reg_d);
        }
        
        out->shift_type   = shift;
        out->shift_amount = imm6;
        out->is_64bit     = sf;
        return true;
    }
    
    /* Data-processing (3 source): MADD, MSUB, SMULL, UMULL, etc. */
    if ((insn & 0x1F000000u) == 0x1B000000u) {
        const bool sf        = (insn >> 31) & 1;
        const uint32_t op54  = bits(insn, 23, 21);
        const bool o0        = (insn >> 15) & 1;
        const arm_reg_t reg_d = rd(insn);
        const arm_reg_t reg_n = rn(insn);
        const arm_reg_t reg_m = rm(insn);
        const arm_reg_t reg_a = ra(insn);
        
        if (op54 == 0) {
            if (reg_a == 31) {
                /* MUL is an alias of MADD with ra == XZR */
                out->type = ARM_OP_MUL;
                out->rd   = reg_d;
                out->rn   = reg_n;
                out->rm   = reg_m;
                track_read(out, reg_n);
                track_read(out, reg_m);
                track_write(out, reg_d);
            } else {
                out->type = o0 ? ARM_OP_MSUB : ARM_OP_MADD;
                out->rd   = reg_d;
                out->rn   = reg_n;
                out->rm   = reg_m;
                out->ra   = reg_a;
                track_read(out, reg_n);
                track_read(out, reg_m);
                track_read(out, reg_a);
                track_write(out, reg_d);
            }
            out->is_64bit = sf;
            return true;
        }
    }
    
    /* Data-processing (2 source): UDIV, SDIV, LSLV, LSRV, ASRV, RORV */
    if ((insn & 0x1FE00000u) == 0x1AC00000u) {
        const bool sf        = (insn >> 31) & 1;
        const uint32_t opcode = bits(insn, 15, 10);
        const arm_reg_t reg_d = rd(insn);
        const arm_reg_t reg_n = rn(insn);
        const arm_reg_t reg_m = rm(insn);
        
        switch (opcode) {
            case 0x02: out->type = ARM_OP_UDIV; break;
            case 0x03: out->type = ARM_OP_SDIV; break;
            case 0x08: out->type = ARM_OP_LSL; break;
            case 0x09: out->type = ARM_OP_LSR; break;
            case 0x0A: out->type = ARM_OP_ASR; break;
            case 0x0B: out->type = ARM_OP_ROR; break;
            default:
                out->valid = false;
                return false;
        }
        
        out->rd       = reg_d;
        out->rn       = reg_n;
        out->rm       = reg_m;
        out->is_64bit = sf;
        
        track_read(out, reg_n);
        track_read(out, reg_m);
        track_write(out, reg_d);
        return true;
    }

    /* Move wide (immediate): MOVN/MOVZ/MOVK */
    if ((insn & 0x1F800000u) == 0x12800000u) {
        const bool sf        = (insn >> 31) & 1;
        const uint32_t opc   = bits(insn, 30, 29);
        const uint32_t hw    = bits(insn, 22, 21);
        const uint64_t imm16 = bits(insn, 20, 5);
        const uint64_t shift = (uint64_t)hw * 16;
        const arm_reg_t reg_d = rd(insn);

        out->type     = ARM_OP_MOV;
        out->rd       = reg_d;
        out->is_64bit = sf;
        
        track_write(out, reg_d);

        if (opc == 2) {  /* MOVZ */
            out->imm      = imm16 << shift;
            out->imm_size = sf ? 64 : 32;
            return true;
        } else if (opc == 0) {  /* MOVN */
            const uint64_t width_mask = sf ? 0xFFFFFFFFFFFFFFFFULL : 0x00000000FFFFFFFFULL;
            const uint64_t v = (imm16 << shift);
            out->imm      = (~v) & width_mask;
            out->imm_size = sf ? 64 : 32;
            return true;
        } else if (opc == 3) {  /* MOVK */
            /* MOVK keeps existing bits, only modifies 16-bit field */
            out->imm      = imm16 | (shift << 32);
            out->imm_size = 16;
            track_read(out, reg_d);  /* Also reads destination */
            return true;
        }
    }
    
    /* ADRP (form PC-relative address to 4KB page) */
    if ((insn & 0x9F000000u) == 0x90000000u) {
        const uint32_t immlo = bits(insn, 30, 29);
        const uint32_t immhi = bits(insn, 23, 5);
        const int64_t imm    = sxt64(((uint64_t)immhi << 2) | immlo, 21) << 12;
        const arm_reg_t reg_d = rd(insn);
        
        out->type     = ARM_OP_ADRP;
        out->rd       = reg_d;
        out->imm      = imm;
        out->is_64bit = true;
        
        track_write(out, reg_d);
        return true;
    }
    
    /* ADR (form PC-relative address) */
    if ((insn & 0x9F000000u) == 0x10000000u) {
        const uint32_t immlo = bits(insn, 30, 29);
        const uint32_t immhi = bits(insn, 23, 5);
        const int64_t imm    = sxt64(((uint64_t)immhi << 2) | immlo, 21);
        const arm_reg_t reg_d = rd(insn);
        
        out->type     = ARM_OP_ADR;
        out->rd       = reg_d;
        out->imm      = imm;
        out->is_64bit = true;
        
        track_write(out, reg_d);
        return true;
    }
    
    /* Load/Store (unsigned immediate) */
    if ((insn & 0x3B000000u) == 0x39000000u) {
        const uint32_t size  = bits(insn, 31, 30);
        const uint32_t opc   = bits(insn, 23, 22);
        const uint32_t imm12 = bits(insn, 21, 10);
        const arm_reg_t reg_t = rd(insn);
        const arm_reg_t reg_n = rn(insn);

        const uint64_t scale = size;
        const uint64_t off   = ((uint64_t)imm12) << scale;

        if (opc == 0) {
            out->type = ARM_OP_STR;
            track_read(out, reg_t);   /* STR reads from rt */
            track_read(out, reg_n);   /* Base register */
        } else if (opc == 1) {
            out->type = ARM_OP_LDR;
            track_write(out, reg_t);  /* LDR writes to rt */
            track_read(out, reg_n);   /* Base register */
        } else {
            out->valid = false;
            return false;
        }

        out->rn       = reg_n;
        out->rd       = reg_t;
        out->imm      = off;
        out->imm_size = 12 + (int)scale;
        out->is_64bit = (size == 3);
        return true;
    }
    
    /* Load/Store pair (signed offset) */
    if ((insn & 0x3A000000u) == 0x28000000u) {
        const uint32_t opc   = bits(insn, 31, 30);
        const bool L         = (insn >> 22) & 1;
        const int32_t imm7   = (int32_t)sxt64(bits(insn, 21, 15), 7);
        const arm_reg_t reg_t = rd(insn);
        const arm_reg_t reg_t2 = rt2(insn);
        const arm_reg_t reg_n = rn(insn);
        
        const uint32_t scale = (opc == 0) ? 2 : 3;  /* 32-bit or 64-bit */
        const int64_t offset = imm7 << scale;
        
        if (L) {
            out->type = ARM_OP_LDP;
            track_write(out, reg_t);
            track_write(out, reg_t2);
            track_read(out, reg_n);
        } else {
            out->type = ARM_OP_STP;
            track_read(out, reg_t);
            track_read(out, reg_t2);
            track_read(out, reg_n);
        }
        
        out->rd       = reg_t;
        out->rm       = reg_t2;  /* Reuse rm for second register */
        out->rn       = reg_n;
        out->imm      = offset;
        out->is_64bit = (opc == 2);
        return true;
    }
    
    /* NOP and hint instructions */
    if ((insn & 0xFFFFFFFFu) == 0xD503201Fu) {
        out->type  = ARM_OP_NOP;
        out->valid = true;
        return true;
    }

    /* SVC (supervisor call) */
    if ((insn & 0xFFE0001Fu) == 0xD4000001u) {
        out->type          = ARM_OP_SVC;
        out->imm           = bits(insn, 20, 5);
        out->is_privileged = true;
        out->privileged    = true;
        out->ring0         = true;
        return true;
    }

    /* MRS (move system register to general-purpose register) */
    if ((insn & 0xFFF00000u) == 0xD5300000u) {
        const arm_reg_t reg_t = rd(insn);
        
        out->type          = ARM_OP_MRS;
        out->rd            = reg_t;
        out->is_privileged = true;
        out->privileged    = true;
        out->ring0         = true;
        
        track_write(out, reg_t);
        return true;
    }

    /* MSR (move general-purpose register to system register) */
    if ((insn & 0xFFF00000u) == 0xD5100000u) {
        const arm_reg_t reg_t = rd(insn);
        
        out->type          = ARM_OP_MSR;
        out->rd            = reg_t;
        out->is_privileged = true;
        out->privileged    = true;
        out->ring0         = true;
        
        track_read(out, reg_t);
        return true;
    }

    /* SYS (system instruction) */
    if ((insn & 0xFFC00000u) == 0xD5000000u) {
        out->type          = ARM_OP_SYS;
        out->imm           = bits(insn, 20, 5);
        out->is_privileged = true;
        out->privileged    = true;
        out->ring0         = true;
        return true;
    }

    /* If we reach here, instruction is not recognized */
    out->valid = false;
    return false;
}

#endif  /* ARCH_ARM    */
