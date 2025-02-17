#include "wisp.h"

#ifdef ARCH_X86
//===================================================================
/// TRASH & OPAQUE (for mutation)
//===================================================================

__attribute__((always_inline)) static inline void trash(uint8_t *buf, size_t sz, ChaChaRNG *rng) {
    uint32_t choice = chacha20_random(rng) % 4;
    switch (choice) {
        case 0: {
            if (sz < 8) return;
            uint8_t seq[8] = { 0x48, 0x83, 0xC0, 0x01, 0x48, 0x83, 0xE8, 0x01 };
            memcpy(buf, seq, 8);
        } break;
        case 1: {
            if (sz < 2) return;
            uint8_t seq[2] = { 0x50, 0x58 };
            memcpy(buf, seq, 2);
        } break;
        case 2: {
            if (sz < 10) return;
            uint32_t imm = chacha20_random(rng);
            uint8_t seq[10];
            seq[0] = 0xB8;
            memcpy(seq + 1, &imm, 4);
            seq[5] = 0x35;
            memcpy(seq + 6, &imm, 4);
            memcpy(buf, seq, 10);
        } break;
        case 3: {
            if (sz < 3) return;
            uint8_t seq[3] = { 0x48, 0x31, 0xC0 };
            memcpy(buf, seq, 3);
        } break;
        default: break;
    }
}

__attribute__((always_inline)) static inline void opaque(uint8_t *code, size_t sz, ChaChaRNG *rng) {
    if (sz < 12) return;
    uint32_t imm = chacha20_random(rng);
    uint8_t seq[12];
    seq[0]  = 0xB8;
    memcpy(seq + 1, &imm, 4);
    seq[5]  = 0x3D;
    memcpy(seq + 6, &imm, 4);
    seq[10] = 0x74;
    seq[11] = 0x00;
    size_t pos = chacha20_random(rng) % (sz - 12);
    memcpy(code + pos, seq, 12);
}
#endif

//===================================================================
/// VALIDATION & DISASSEMBLY
//===================================================================

__attribute__((always_inline)) static inline bool validate_instruction(csh handle, const cs_insn *i) {
    if (!i) return false;
#ifdef ARCH_X86
    cs_detail *d = i->detail;
    if (!d) return false;
    for (size_t j = 0; j < d->groups_count; j++) {
        if (d->groups[j] == CS_GRP_PRIVILEGE)
            return false;
    }
#endif
    return true;
}

static bool disassemble_and_validate(csh handle, const uint8_t *code, size_t len) {
    cs_insn *insn = NULL;
    bool valid = true;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    size_t cnt = cs_disasm(handle, code, len, 0, 1, &insn);
    if (cnt != 1) {
        for (size_t k = 0; k < len; k++)
            fprintf(stderr, " %02x", code[k]);
        valid = false;
        goto cleanup;
    }
    if (!validate_instruction(handle, insn))
        valid = false;
cleanup:
    if (insn)
        cs_free(insn, 1);
    return valid;
}

//===================================================================
/// MUTATION
//===================================================================

void mutate(uint8_t *code, size_t sz, ChaChaRNG *rng) {
    MutC ctx = {0};
    ctx.original = code;
    ctx.size = sz;
    ctx.rng = *rng;
    uintptr_t base = (uintptr_t)code;

#ifdef ARCH_X86
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &ctx.handle) != CS_ERR_OK)
        return;
#elif defined(ARCH_ARM)
    if (cs_open(CS_ARCH_ARM64, 0, &ctx.handle) != CS_ERR_OK)
        return;
#endif

    ctx.count = cs_disasm(ctx.handle, code, sz, base, 0, &ctx.insns);
    if (!ctx.count) {
        cs_close(&ctx.handle);
        return;
    }

    uint8_t *backup = malloc(sz);
    if (!backup) {
        cs_free(ctx.insns, ctx.count);
        cs_close(&ctx.handle);
        return;
    }
    memcpy(backup, code, sz);
    size_t original_count = ctx.count;

    for (int pass = 0; pass < 3; pass++) {
        uint32_t action = chacha20_random(&ctx.rng) % 4;
        switch (action) {
            case 0: {
                size_t i = chacha20_random(&ctx.rng) % ctx.count;
                size_t j = chacha20_random(&ctx.rng) % ctx.count;
                if (i == j || ctx.insns[i].size != ctx.insns[j].size)
                    break;
                size_t off_i = ctx.insns[i].address - base;
                size_t off_j = ctx.insns[j].address - base;
                size_t insz = ctx.insns[i].size;
                if (off_i + insz > sz || off_j + insz > sz)
                    break;
                uint8_t temp_i[32], temp_j[32];
                memcpy(temp_i, code + off_i, insz);
                memcpy(temp_j, code + off_j, insz);
                memcpy(code + off_i, temp_j, insz);
                memcpy(code + off_j, temp_i, insz);
                if (!disassemble_and_validate(ctx.handle, code + off_i, insz) ||
                    !disassemble_and_validate(ctx.handle, code + off_j, insz)) {
                    memcpy(code + off_i, temp_i, insz);
                    memcpy(code + off_j, temp_j, insz);
                }
            } break;

#ifdef ARCH_X86
            case 1: {
                if (sz >= JU) {
                    size_t pos = chacha20_random(&ctx.rng) % (sz - JU);
                    trash(code + pos, JU, &ctx.rng);
                }
            } break;
            case 2: {
                opaque(code, sz, &ctx.rng);
            } break;
            case 3: {
                size_t i = chacha20_random(&ctx.rng) % ctx.count;
                size_t off = ctx.insns[i].address - base;
                size_t insz = ctx.insns[i].size;
                if (off + insz > sz)
                    break;
                uint8_t bak[32];
                memcpy(bak, code + off, insz);
                if (insz >= 1 && insz <= 10) {
                    static const uint8_t nop_sequences[][10] = {
                        {0x90},
                        {0x66, 0x90},
                        {0x0F, 0x1F, 0x00},
                        {0x0F, 0x1F, 0x40, 0x00},
                        {0x0F, 0x1F, 0x44, 0x00, 0x00},
                        {0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00},
                        {0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00},
                        {0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
                        {0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},
                        {0x0F, 0x1F, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
                    };
                    memcpy(code + off, nop_sequences[insz - 1], insz);
                } else {
                    memset(code + off, 0x90, insz);
                }
                if (!disassemble_and_validate(ctx.handle, code + off, insz))
                    memcpy(code + off, bak, insz);
            } break;
#endif
            default: break;
        }
    }

    cs_insn *final = NULL;
    size_t final_count = cs_disasm(ctx.handle, code, sz, base, 0, &final);
    if (final_count < (original_count * 0.9))
        memcpy(code, backup, sz);

    free(backup);
    if (ctx.insns)
        cs_free(ctx.insns, ctx.count);
    if (final)
        cs_free(final, final_count);
    cs_close(&ctx.handle);
    *rng = ctx.rng;
}

void mutate_p(uint8_t *code, size_t sz, ChaChaRNG *rng) {
    if (sz <= SZ)
        return;
    uint8_t *target = code + SZ;
    size_t target_size = sz - SZ;
#ifdef MU
    mutate(target, target_size, rng);
#endif
}
