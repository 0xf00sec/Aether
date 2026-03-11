#include "x86.h"

static inline void add_read(x86_inst_t *i, uint8_t r) {
    if (r < 16 && i->num_regs_read < 6) i->regs_read[i->num_regs_read++] = r;
}
static inline void add_write(x86_inst_t *i, uint8_t r) {
    if (r < 16 && i->num_regs_written < 4) i->regs_written[i->num_regs_written++] = r;
}

/* Add memory operand registers (base + index) as reads */
static void add_mem_reads(x86_inst_t *i) {
    if (i->addr_mode == X86_ADDR_MEM || i->addr_mode == X86_ADDR_RIP) {
        if (i->rm < 16) add_read(i, i->rm);
        if (i->index < 16) add_read(i, i->index);
    }
}

void x86_classify(x86_inst_t *inst, uint8_t op0, uint8_t op1, bool rex_w) {
    (void)rex_w;
    uint8_t mod = inst->has_modrm ? x86_modrm_mod(inst->modrm) : 0;
    uint8_t ext = inst->has_modrm ? x86_modrm_reg(inst->modrm) : 0; /* /r extension */

    inst->sets_flags = false;
    inst->reads_flags = false;

    /* One-byte opcodes */

    /* NOP */
    if (op0 == 0x90 && !inst->has_modrm) {
        inst->op = X86_OP_NOP; return;
    }
    /* Multi-byte NOP: 0F 1F /0 */
    if (op0 == 0x0F && op1 == 0x1F) {
        inst->op = X86_OP_NOP; return;
    }

    /* RET */
    if (op0 == 0xC3 || op0 == 0xCB) {
        inst->op = X86_OP_RET; inst->is_control_flow = true;
        add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP);
        return;
    }
    if (op0 == 0xC2 || op0 == 0xCA) {
        inst->op = X86_OP_RET; inst->is_control_flow = true;
        add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP);
        return;
    }

    /* PUSH r64 */
    if (op0 >= 0x50 && op0 <= 0x57) {
        inst->op = X86_OP_PUSH;
        uint8_t r = (op0 - 0x50) | (inst->rex & 1 ? 8 : 0);
        add_read(inst, r); add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP);
        return;
    }
    /* POP r64 */
    if (op0 >= 0x58 && op0 <= 0x5F) {
        inst->op = X86_OP_POP;
        uint8_t r = (op0 - 0x58) | (inst->rex & 1 ? 8 : 0);
        add_write(inst, r); add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP);
        return;
    }
    /* PUSH imm */
    if (op0 == 0x68 || op0 == 0x6A) {
        inst->op = X86_OP_PUSH;
        add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP);
        return;
    }

    /* CALL rel32 */
    if (op0 == 0xE8) {
        inst->op = X86_OP_CALL; inst->is_control_flow = true;
        inst->target = inst->imm; /* relative */
        add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP);
        return;
    }
    /* JMP rel32/rel8 */
    if (op0 == 0xE9 || op0 == 0xEB) {
        inst->op = X86_OP_JMP; inst->is_control_flow = true;
        inst->target = inst->imm;
        return;
    }
    /* Jcc rel8 */
    if (op0 >= 0x70 && op0 <= 0x7F) {
        inst->op = X86_OP_JCC; inst->is_control_flow = true;
        inst->cc = (x86_cc_t)(op0 - 0x70);
        inst->target = inst->imm;
        inst->reads_flags = true;
        return;
    }
    /* LOOP/LOOPcc */
    if (op0 >= 0xE0 && op0 <= 0xE2) {
        inst->op = X86_OP_LOOP; inst->is_control_flow = true;
        inst->target = inst->imm;
        add_read(inst, X86_REG_RCX); add_write(inst, X86_REG_RCX);
        if (op0 != 0xE2) inst->reads_flags = true;
        return;
    }

    /* MOV r, imm (B8+r) */
    if (op0 >= 0xB8 && op0 <= 0xBF) {
        inst->op = X86_OP_MOV;
        uint8_t r = (op0 - 0xB8) | (inst->rex & 1 ? 8 : 0);
        add_write(inst, r);
        return;
    }
    /* MOV r8, imm8 (B0+r) */
    if (op0 >= 0xB0 && op0 <= 0xB7) {
        inst->op = X86_OP_MOV;
        uint8_t r = (op0 - 0xB0) | (inst->rex & 1 ? 8 : 0);
        add_write(inst, r);
        return;
    }

    /* LEA */
    if (op0 == 0x8D) {
        inst->op = X86_OP_LEA;
        add_write(inst, inst->reg);
        add_mem_reads(inst); /* reads base/index for address calc, not memory */
        return;
    }

    /* MOV r/m, r  (88/89) */
    if (op0 == 0x88 || op0 == 0x89) {
        inst->op = X86_OP_MOV;
        add_read(inst, inst->reg);
        if (mod == 3) add_write(inst, inst->rm);
        else { add_mem_reads(inst); }
        return;
    }
    /* MOV r, r/m  (8A/8B) */
    if (op0 == 0x8A || op0 == 0x8B) {
        inst->op = X86_OP_MOV;
        add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* MOV r/m, imm (C6/C7) */
    if (op0 == 0xC6 || op0 == 0xC7) {
        inst->op = X86_OP_MOV;
        if (mod == 3) add_write(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }

    if ((op0 & 0xC6) == 0x00 && (op0 & 1) <= 1 && op0 < 0x40) {
        uint8_t grp = (op0 >> 3) & 7;
        static const x86_op_t alu_ops[] = {
            X86_OP_ADD, X86_OP_OR, X86_OP_ADC, X86_OP_SBB,
            X86_OP_AND, X86_OP_SUB, X86_OP_XOR, X86_OP_CMP
        };
        inst->op = alu_ops[grp];
        inst->sets_flags = true;
        if (grp == 2 || grp == 3) inst->reads_flags = true; /* ADC/SBB */
        add_read(inst, inst->reg);
        if (mod == 3) {
            add_read(inst, inst->rm);
            if (grp != 7) add_write(inst, inst->rm); /* CMP doesn't write */
        } else add_mem_reads(inst);
        return;
    }
    if ((op0 & 0xC6) == 0x02 && op0 < 0x40) {
        uint8_t grp = (op0 >> 3) & 7;
        static const x86_op_t alu_ops[] = {
            X86_OP_ADD, X86_OP_OR, X86_OP_ADC, X86_OP_SBB,
            X86_OP_AND, X86_OP_SUB, X86_OP_XOR, X86_OP_CMP
        };
        inst->op = alu_ops[grp];
        inst->sets_flags = true;
        if (grp == 2 || grp == 3) inst->reads_flags = true;
        add_read(inst, inst->reg);
        if (grp != 7) add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    if ((op0 & 0xC7) == 0x04 || (op0 & 0xC7) == 0x05) {
        uint8_t grp = (op0 >> 3) & 7;
        static const x86_op_t alu_ops[] = {
            X86_OP_ADD, X86_OP_OR, X86_OP_ADC, X86_OP_SBB,
            X86_OP_AND, X86_OP_SUB, X86_OP_XOR, X86_OP_CMP
        };
        inst->op = alu_ops[grp];
        inst->sets_flags = true;
        if (grp == 2 || grp == 3) inst->reads_flags = true;
        add_read(inst, X86_REG_RAX);
        if (grp != 7) add_write(inst, X86_REG_RAX);
        return;
    }

    if (op0 == 0x80 || op0 == 0x81 || op0 == 0x83) {
        static const x86_op_t g1[] = {
            X86_OP_ADD, X86_OP_OR, X86_OP_ADC, X86_OP_SBB,
            X86_OP_AND, X86_OP_SUB, X86_OP_XOR, X86_OP_CMP
        };
        inst->op = g1[ext];
        inst->sets_flags = true;
        if (ext == 2 || ext == 3) inst->reads_flags = true;
        if (mod == 3) {
            add_read(inst, inst->rm);
            if (ext != 7) add_write(inst, inst->rm);
        } else add_mem_reads(inst);
        return;
    }

    if (op0 == 0x84 || op0 == 0x85) {
        inst->op = X86_OP_TEST; inst->sets_flags = true;
        add_read(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* TEST rAX, imm (A8/A9) */
    if (op0 == 0xA8 || op0 == 0xA9) {
        inst->op = X86_OP_TEST; inst->sets_flags = true;
        add_read(inst, X86_REG_RAX);
        return;
    }

    /* XCHG (87) */
    if (op0 == 0x87) {
        inst->op = X86_OP_XCHG;
        if (mod == 3) {
            add_read(inst, inst->reg); add_read(inst, inst->rm);
            add_write(inst, inst->reg); add_write(inst, inst->rm);
        } else {
            add_read(inst, inst->reg); add_write(inst, inst->reg);
            add_mem_reads(inst);
        }
        return;
    }

    if (op0 == 0xC0 || op0 == 0xC1 || op0 == 0xD0 || op0 == 0xD1 ||
        op0 == 0xD2 || op0 == 0xD3) {
        static const x86_op_t sh[] = {
            X86_OP_ROL, X86_OP_ROR, X86_OP_SHL/*RCL*/, X86_OP_SHR/*RCR*/,
            X86_OP_SHL, X86_OP_SHR, X86_OP_SHL, X86_OP_SAR
        };
        inst->op = sh[ext]; inst->sets_flags = true;
        if (mod == 3) { add_read(inst, inst->rm); add_write(inst, inst->rm); }
        else add_mem_reads(inst);
        if (op0 == 0xD2 || op0 == 0xD3) add_read(inst, X86_REG_RCX);
        return;
    }

    if (op0 == 0xF6 || op0 == 0xF7) {
        inst->sets_flags = true;
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        switch (ext) {
        case 0: inst->op = X86_OP_TEST; break;
        case 2: inst->op = X86_OP_NOT; inst->sets_flags = false;
                if (mod == 3) add_write(inst, inst->rm); break;
        case 3: inst->op = X86_OP_NEG;
                if (mod == 3) add_write(inst, inst->rm); break;
        case 4: inst->op = X86_OP_MUL;
                add_read(inst, X86_REG_RAX); add_write(inst, X86_REG_RAX); add_write(inst, X86_REG_RDX); break;
        case 5: inst->op = X86_OP_IMUL;
                add_read(inst, X86_REG_RAX); add_write(inst, X86_REG_RAX); add_write(inst, X86_REG_RDX); break;
        case 6: inst->op = X86_OP_DIV;
                add_read(inst, X86_REG_RAX); add_read(inst, X86_REG_RDX);
                add_write(inst, X86_REG_RAX); add_write(inst, X86_REG_RDX); break;
        case 7: inst->op = X86_OP_IDIV;
                add_read(inst, X86_REG_RAX); add_read(inst, X86_REG_RDX);
                add_write(inst, X86_REG_RAX); add_write(inst, X86_REG_RDX); break;
        default: break;
        }
        return;
    }

    if (op0 == 0xFF) {
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        switch (ext) {
        case 0: inst->op = X86_OP_INC; inst->sets_flags = true;
                if (mod == 3) add_write(inst, inst->rm); break;
        case 1: inst->op = X86_OP_DEC; inst->sets_flags = true;
                if (mod == 3) add_write(inst, inst->rm); break;
        case 2: inst->op = X86_OP_CALL; inst->is_control_flow = true;
                add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP); break;
        case 4: inst->op = X86_OP_JMP; inst->is_control_flow = true; break;
        case 6: inst->op = X86_OP_PUSH;
                add_read(inst, X86_REG_RSP); add_write(inst, X86_REG_RSP); break;
        default: break;
        }
        return;
    }
    if (op0 == 0xFE) {
        inst->sets_flags = true;
        if (mod == 3) { add_read(inst, inst->rm); add_write(inst, inst->rm); }
        else add_mem_reads(inst);
        inst->op = (ext == 0) ? X86_OP_INC : X86_OP_DEC;
        return;
    }

    /* IMUL r, r/m (0F AF) */
    if (op0 == 0x0F && op1 == 0xAF) {
        inst->op = X86_OP_IMUL; inst->sets_flags = true;
        add_read(inst, inst->reg); add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);return;
    }
    /* IMUL r, r/m, imm (69/6B) */
    if (op0 == 0x69 || op0 == 0x6B) {
        inst->op = X86_OP_IMUL; inst->sets_flags = true;
        add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }

    if (op0 == 0x0F && op1 == 0x05) {
        inst->op = X86_OP_SYSCALL; inst->is_privileged = true; inst->is_control_flow = true;
        return;
    }
    /* UD2 */
    if (op0 == 0x0F && op1 == 0x0B) {
        inst->op = X86_OP_UD2; inst->is_control_flow = true; return;
    }
    /* INT */
    if (op0 == 0xCD) {
        inst->op = X86_OP_INT; inst->is_privileged = true; return;
    }
    /* HLT */
    if (op0 == 0xF4) {
        inst->op = X86_OP_HLT; inst->is_privileged = true; return;
    }
    /* CQO/CDQ/CWD */
    if (op0 == 0x99) {
        inst->op = X86_OP_CQO;
        add_read(inst, X86_REG_RAX); add_write(inst, X86_REG_RDX);
        return;
    }

    /* Two-byte opcodes (0F xx) */
    if (op0 == 0x0F && op1 >= 0x80 && op1 <= 0x8F) {
        inst->op = X86_OP_JCC; inst->is_control_flow = true;
        inst->cc = (x86_cc_t)(op1 - 0x80);
        inst->target = inst->imm;
        inst->reads_flags = true;
        return;
    }
    /* SETcc */
    if (op0 == 0x0F && op1 >= 0x90 && op1 <= 0x9F) {
        inst->op = X86_OP_SETcc;
        inst->cc = (x86_cc_t)(op1 - 0x90);
        inst->reads_flags = true;
        if (mod == 3) add_write(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* CMOVcc */
    if (op0 == 0x0F && op1 >= 0x40 && op1 <= 0x4F) {
        inst->op = X86_OP_CMOV;
        inst->cc = (x86_cc_t)(op1 - 0x40);
        inst->reads_flags = true;
        add_read(inst, inst->reg); add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* MOVZX */
    if (op0 == 0x0F && (op1 == 0xB6 || op1 == 0xB7)) {
        inst->op = X86_OP_MOVZX;
        add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* MOVSX */
    if (op0 == 0x0F && (op1 == 0xBE || op1 == 0xBF)) {
        inst->op = X86_OP_MOVSX;
        add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* BSF/BSR */
    if (op0 == 0x0F && (op1 == 0xBC || op1 == 0xBD)) {
        inst->op = (op1 == 0xBC) ? X86_OP_BSF : X86_OP_BSR;
        inst->sets_flags = true;
        add_write(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* BT/BTS/BTR/BTC */
    if (op0 == 0x0F && (op1 == 0xA3 || op1 == 0xAB || op1 == 0xB3 || op1 == 0xBB)) {
        inst->op = X86_OP_BT; inst->sets_flags = true;
        add_read(inst, inst->reg);
        if (mod == 3) add_read(inst, inst->rm);
        else add_mem_reads(inst);
        return;
    }
    /* SHLD/SHRD */
    if (op0 == 0x0F && (op1 == 0xA4 || op1 == 0xA5 || op1 == 0xAC || op1 == 0xAD)) {
        inst->op = X86_OP_SHL; inst->sets_flags = true;
        add_read(inst, inst->reg);
        if (mod == 3) { add_read(inst, inst->rm); add_write(inst, inst->rm); }
        else add_mem_reads(inst);
        if (op1 == 0xA5 || op1 == 0xAD) add_read(inst, X86_REG_RCX);
        return;
    }

    /* SIMD catch-all for 0F prefix */
    if (op0 == 0x0F) {
        inst->op = X86_OP_SIMD; inst->is_simd = true;
        return;
    }

    /* Unknown f00 */
    inst->op = X86_OP_NONE;
}
