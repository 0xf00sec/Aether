#include <wisp.h>

/*-------------------------------------------
   AArch64 decoder
-------------------------------------------*/

#if defined(ARCH_ARM)

static inline uint32_t rd_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline arm_reg_t rd(const uint32_t insn) { return (arm_reg_t)(insn & 0x1F); }
static inline arm_reg_t rn(const uint32_t insn) { return (arm_reg_t)((insn >> 5) & 0x1F); }
static inline arm_reg_t rm(const uint32_t insn) { return (arm_reg_t)((insn >> 16) & 0x1F); }

static inline uint32_t bits(const uint32_t x, int hi, int lo) { return (x >> lo) & ((1u << (hi - lo + 1)) - 1u); }
static inline int64_t  sxt64(uint64_t v, int nbits) {
    const uint64_t m = 1ULL << (nbits - 1);
    return (int64_t)((v ^ m) - m);
}

  
static bool is_cfi(uint32_t insn) {
    if ((insn & 0x7C000000u) == 0x14000000u) return true;                   
    if ((insn & 0xFF000010u) == 0x54000000u) return true;                   
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) return true;                   
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) return true;                   
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) return true;                   
    return false;
}

static bool is_priv(uint32_t insn) {
    if ((insn & 0xFFE0001Fu) == 0xD4000001u) return true;                   
    if ((insn & 0xFFC00000u) == 0xD5000000u) return true;                   
    if ((insn & 0xFFF00000u) == 0xD5300000u) return true;                   
    if ((insn & 0xFFF00000u) == 0xD5100000u) return true;                   
    return false;
}

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
        return true;
    }

      
    if ((insn & 0xFF000010u) == 0x54000000u) {
        const uint32_t imm19 = bits(insn, 23, 5);
        const int64_t off    = sxt64(imm19, 19) << 2;

        out->type            = ARM_OP_BRANCH_COND;
        out->imm             = off;
        out->target          = off;
        out->is_control_flow = true;
        out->modifies_ip     = true;
        return true;
    }

      
    if ((insn & 0xFFFFFC1Fu) == 0xD61F0000u) {   
        out->type            = ARM_OP_BRANCH;
        out->rn              = rn(insn);
        out->is_control_flow = true;
        out->modifies_ip     = true;
        return true;
    }
    if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) {   
        out->type            = ARM_OP_BRANCH_LINK;
        out->rn              = rn(insn);
        out->is_control_flow = true;
        out->modifies_ip     = true;
        return true;
    }

      
    if ((insn & 0xFFFFFC1Fu) == 0xD65F0000u) {
        out->type            = ARM_OP_RET;
        out->rn              = rn(insn);         
        out->is_control_flow = true;
        out->modifies_ip     = true;
        return true;
    }

    /*  Add/Sub (immediate) */
    if ((insn & 0x1F000000u) == 0x11000000u) {
        const bool sf  = (insn >> 31) & 1;
        const bool op  = (insn >> 30) & 1;       
        const bool sh  = (insn >> 22) & 1;       
        const uint32_t imm12 = bits(insn, 21, 10);

        out->type     = op ? ARM_OP_SUB : ARM_OP_ADD;
        out->rd       = rd(insn);
        out->rn       = rn(insn);
        out->imm      = (uint64_t)imm12 << (sh ? 12 : 0);
        out->imm_size = sh ? 24 : 12;
        out->is_64bit = sf;
        return true;
    }

    /*  Add/Sub (register)  */
    if ((insn & 0x1F000000u) == 0x0B000000u) {
        const bool sf = (insn >> 31) & 1;
        const bool op = (insn >> 30) & 1;

        out->type     = op ? ARM_OP_SUB : ARM_OP_ADD;
        out->rd       = rd(insn);
        out->rn       = rn(insn);
        out->rm       = rm(insn);
        out->is_64bit = sf;
        return true;
    }

    /*  (shifted register) + MOV alias  */
    if ((insn & 0x1F000000u) == 0x0A000000u) {
        const bool sf   = (insn >> 31) & 1;
        const uint32_t opc = bits(insn, 30, 29);
        const uint32_t imm6 = bits(insn, 15, 10);
        const uint32_t sh   = bits(insn, 23, 22);
        const arm_reg_t rrn = rn(insn);

          
        if (opc == 1 && rrn == (arm_reg_t)31 && sh == 0 && imm6 == 0) {
            out->type     = ARM_OP_MOV;
            out->rd       = rd(insn);
            out->rm       = rm(insn);
            out->is_64bit = sf;
            return true;
        }

        switch (opc) {
            case 0: out->type = ARM_OP_AND; break;
            case 1: out->type = ARM_OP_ORR; break;
            case 2: out->type = ARM_OP_EOR; break;
            default: out->type = ARM_OP_AND; break;   
        }
        out->rd       = rd(insn);
        out->rn       = rrn;
        out->rm       = rm(insn);
        out->is_64bit = sf;
        return true;
    }

    /*  MOVN/MOVZ/MOVK  */
    if ((insn & 0x1F800000u) == 0x12800000u) {
        const bool sf    = (insn >> 31) & 1;
        const uint32_t opc = bits(insn, 30, 29);     
        const uint32_t hw  = bits(insn, 22, 21);
        const uint64_t imm16 = bits(insn, 20, 5);
        const uint64_t shift = (uint64_t)hw * 16;

        out->type     = ARM_OP_MOV;
        out->rd       = rd(insn);
        out->is_64bit = sf;

        if (opc == 2) {                    
            out->imm      = imm16 << shift;
            out->imm_size = sf ? 64 : 32;
            return true;
        } else if (opc == 0) {             
            const uint64_t width_mask = sf ? 0xFFFFFFFFFFFFFFFFULL : 0x00000000FFFFFFFFULL;
            const uint64_t v = (imm16 << shift);
            out->imm      = (~v) & width_mask;
            out->imm_size = sf ? 64 : 32;
            return true;
        } else if (opc == 3) {             
              
            out->imm      = imm16 | (shift << 32);   
            out->imm_size = 16;
            return true;
        }
          
    }

    if ((insn & 0x3B000000u) == 0x39000000u) {
        const uint32_t size  = bits(insn, 31, 30);      
        const uint32_t opc   = bits(insn, 23, 22);      
        const uint32_t imm12 = bits(insn, 21, 10);

        const uint64_t scale = size;                    
        const uint64_t off   = ((uint64_t)imm12) << scale;

        if (opc == 0) {
            out->type = ARM_OP_STR;
        } else if (opc == 1) {
            out->type = ARM_OP_LDR;
        } else {
              
            out->valid = false;
            return false;
        }

        out->rn       = rn(insn);
        out->rd       = rd(insn);
        out->imm      = off;
        out->imm_size = 12 + (int)scale;    
        out->is_64bit = (size == 3);
        return true;
    }

      

      
    if ((insn & 0xFFE0001Fu) == 0xD4000001u) {   
        out->type          = ARM_OP_SVC;
        out->imm           = bits(insn, 20, 5);
        out->is_privileged = true;
        out->privileged    = true;
        return true;
    }

    if ((insn & 0xFFF00000u) == 0xD5300000u) {   
        out->type          = ARM_OP_MRS;
        out->rd            = rd(insn);
        out->is_privileged = true;
        out->privileged    = true;
        return true;
    }

    if ((insn & 0xFFF00000u) == 0xD5100000u) {   
        out->type          = ARM_OP_MSR;
        out->rd            = rd(insn);   
        out->is_privileged = true;
        out->privileged    = true;
        return true;
    }

    if ((insn & 0xFFC00000u) == 0xD5000000u) {   
        out->type          = ARM_OP_SYS;
        out->imm           = bits(insn, 20, 5);
        out->is_privileged = true;
        out->privileged    = true;
        return true;
    }

    out->valid = false;
    return false;
}

#endif   
