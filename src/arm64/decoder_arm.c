/*
+ * File:        decoder_arm.c
+ *   ARM64 instruction decoder, Reads raw 32-bit opcodes
+ *   and identifies branches, indirect calls/returns, and privileged
+ *   system instructions.
+ *
+ * Capabilities:
+ *   – Raw 32-bit fetch (read_u32)
+ *   – Branch decoding: B, BL, B.cond, CBZ, CBNZ, TBZ, TBNZ
+ *   – Indirect control-flow: BR, BLR, RET
+ *   – Supervisor/system ops: SVC, ISB, DSB, PSB (flagged privileged)
+ *
+ * Dependencies:
+ *   <decoder.h> – arm64_inst_t, ARM_OP_* enums, target/type fields
+ *
+ * Usage:
+ *   Call `decode_arm64(code, &inst)` to populate `inst` (raw, valid,
+ *   target, type, privileged). Always processes exactly one 4-byte
+ *   instruction.
+ *
+ * Notes:
+ *   – Returns true even for non-control-flow opcodes (valid == true).
+ *   – Privileged instructions are marked for higher-level handling.
+ */
    #include "decoder.h"

#if defined(ARCH_ARM)
// THIS IS THE DUMBEST SHIT I'VE WRITTEN SO FAR.
static uint32_t read_u32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

bool decode_arm64(const uint8_t *code, arm64_inst_t *out) {
    if (!code || !out)
        return false;

    uint32_t insn = read_u32(code);
    *out = (arm64_inst_t){ .raw = insn, .valid = true, .target = -1, .type = ARM_OP_NONE };

    uint32_t opc = (insn >> 26) & 0x3F;
    uint32_t op1 = (insn >> 24) & 0xFF;
    uint32_t op2 = (insn >> 16) & 0xFF;
    uint32_t op3 = (insn >> 10) & 0x3F;

    if (opc == 0b000101 || opc == 0b100101) { // B, BL
        int32_t imm26 = (int32_t)(insn << 6) >> 6;
        out->target = (uintptr_t)code + 4 + ((int64_t)imm26 << 2);
        out->type = (opc & 0b100000) ? ARM_OP_BRANCH_LINK : ARM_OP_BRANCH;
        return true;
    }

    if ((insn & 0xFE000000) == 0x54000000) { // B.cond
        int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
        imm19 = (imm19 << 13) >> 13;
        out->target = (uintptr_t)code + 4 + ((int64_t)imm19 << 2);
        out->type = ARM_OP_BRANCH_COND;
        return true;
    }

    // CBZ, CBNZ
    if ((insn & 0x7E000000) == 0x34000000) {
        int32_t imm19 = (int32_t)((insn >> 5) & 0x7FFFF);
        imm19 = (imm19 << 13) >> 13;
        out->target = (uintptr_t)code + 4 + ((int64_t)imm19 << 2);
        out->type = ARM_OP_BRANCH_COND;
        return true;
    }

    // TBZ, TBNZ
    if ((insn & 0x7E000000) == 0x36000000) {
        int32_t imm14 = (int32_t)((insn >> 5) & 0x3FFF);
        imm14 = (imm14 << 18) >> 18;
        out->target = (uintptr_t)code + 4 + ((int64_t)imm14 << 2);
        out->type = ARM_OP_BRANCH_COND;
        return true;
    }

    if (op1 == 0x6B && (op3 & 0x3C) == 0x08) {
        if (op2 == 0x08) { // BR
            out->type = ARM_OP_BRANCH_INDIRECT;
            return true;
        }
        if (op2 == 0x09) { // BLR
            out->type = ARM_OP_BRANCH_LINK;
            return true;
        }
        if (op2 == 0x0A) { // RET
            out->type = ARM_OP_RET;
            return true;
        }
    }

    // S call
    if ((insn & 0xFF000000) == 0xD4000000) { // SVC
        out->privileged = true;
        out->type = ARM_OP_SVC;
        return true;
    }

    if ((insn & 0xFFFFF000) == 0xD5033000) { // ISB
        out->privileged = true;
        out->type = ARM_OP_SYS;
        return true;
    }
    if ((insn & 0xFFFFF000) == 0xD50330A0) { // DSB
        out->privileged = true;
        out->type = ARM_OP_SYS;
        return true;
    }
    if ((insn & 0xFFFFF000) == 0xD503309F) { // PSB
        out->privileged = true;
        out->type = ARM_OP_SYS;
        return true;
    }

    return true;
}

#endif // ARCH_ARM
