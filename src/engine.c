#include <wisp.h>

__attribute__((always_inline)) inline bool it_op(const uint8_t *code) {
#if defined(ARCH_X86)
    x86_inst_t inst;
    if (!decode_x86(code, 0, &inst, NULL)) return false;
    return !inst.privileged && inst.valid;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (!decode_arm64(code, &inst)) return false;
    return !inst.privileged && inst.valid;
#else
    return false;
#endif
}

__attribute__((always_inline)) inline bool it_chunk(const uint8_t *code, size_t max_len) {
    size_t offset = 0;
    while (offset < max_len) {
        size_t len = snap_instr_len(code + offset);
        if (!len || offset + len > max_len || !it_op(code + offset)) return false;
        offset += len;
    }
    return offset == max_len;
}

__attribute__((always_inline)) inline size_t snap_instr_len(const uint8_t *code) {
#if defined(ARCH_X86)
    x86_inst_t inst;
    return decode_x86(code, 0, &inst, NULL) ? inst.len : 0;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    return decode_arm64(code, &inst) ? 4 : 0;
#else
    return 0;
#endif
}

__attribute__((always_inline)) inline void swap(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size < 16) return;
    uint8_t backup[size];
    memcpy(backup, code, size);

    for (int i = 0; i < 5; i++) {
        size_t a = chacha20_random(rng) % size;
        size_t b = chacha20_random(rng) % size;
        if (a == b) continue;

        size_t la = snap_instr_len(code + a);
        size_t lb = snap_instr_len(code + b);
        if (la && lb && la == lb && a + la <= size && b + lb <= size) {
            uint8_t tmp[16];
            memcpy(tmp, code + a, la);
            memcpy(code + a, code + b, la);
            memcpy(code + b, tmp, la);

            if (it_chunk(code + a, la) && it_chunk(code + b, lb)) return;
            memcpy(code, backup, size);
        }
    }
}

#if defined(ARCH_X86)
const uint8_t x86_junk[][16] = {
    {0x48, 0x89, 0xC0},
    {0x48, 0x83, 0xE0, 0x00},
    {0x48, 0x83, 0xC8, 0xFF},
    {0x48, 0x31, 0xC0},
    {0x90, 0x90, 0x90, 0x90},
    {0x48, 0x87, 0xC9, 0x48, 0x87, 0xD2}
};
#elif defined(ARCH_ARM)
const uint8_t arm_junk[][8] = {
    {0x1F, 0x20, 0x03, 0xD5},
    {0xE0, 0x03, 0x00, 0xAA},
    {0xFF, 0x03, 0x00, 0xD1},
    {0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5}
};
#endif

__attribute__((always_inline)) inline void insert_junk(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size < 16) return;
    size_t pos = chacha20_random(rng) % (size - 16);
    uint8_t original[16];
    memcpy(original, code + pos, 16);

#if defined(ARCH_X86)
    uint8_t junk[16];
    size_t len = 3 + (chacha20_random(rng) % 10);
    memcpy(junk, x86_junk[chacha20_random(rng) % 6], len);
#elif defined(ARCH_ARM)
    uint8_t junk[8];
    size_t len = 4 + (chacha20_random(rng) % 4);
    memcpy(junk, arm_junk[chacha20_random(rng) % 4], len);
#endif

    memcpy(code + pos, junk, len);
    if (!it_chunk(code + pos, len)) memcpy(code + pos, original, 16);
}

__attribute__((always_inline)) inline void Opaque(uint8_t *buf, size_t *len, uint32_t value) {
#if defined(ARCH_X86)
    buf[0] = 0x48; buf[1] = 0x31; buf[2] = 0xC0;
    buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0;
    buf[6] = 0x0F; buf[7] = 0x84;
    *(uint32_t*)(buf + 8) = 0;
    *len = 12;
#elif defined(ARCH_ARM)
    *(uint32_t*)buf = 0xD2800000;
    *(uint32_t*)(buf + 4) = 0xB4000000 | ((4 << 5) & 0x00FFFFE0);
    *len = 8;
#endif
}

__attribute__((always_inline)) inline void _mut8(uint8_t *code, size_t size, chacha_state_t *rng) {
    uint8_t original[size];
    memcpy(original, code, size);
    size_t passes = 3 + (chacha20_random(rng) % 3);

    for (size_t i = 0; i < passes; i++) {
        switch (chacha20_random(rng) % 5) {
            case 0:
                swap(code, size, rng);
                break;
            case 1:
                insert_junk(code, size, rng);
                break;
            case 2: {
                uint8_t opaque[16], backup[16];
                size_t olen;
                Opaque(opaque, &olen, chacha20_random(rng));
                if (olen > size) break;
                size_t pos = chacha20_random(rng) % (size - olen);
                memcpy(backup, code + pos, olen);
                memcpy(code + pos, opaque, olen);
                if (!it_chunk(code + pos, olen)) memcpy(code + pos, backup, olen);
                break;
            }
            case 3: {
                size_t pos = chacha20_random(rng) % size;
                size_t ilen = snap_instr_len(code + pos);
                if (!ilen || pos + ilen > size) break;
                uint8_t backup[16];
                memcpy(backup, code + pos, ilen);
#if defined(ARCH_X86)
                memset(code + pos, 0x90, ilen);
#elif defined(ARCH_ARM)
                *(uint32_t*)(code + pos) = 0xD503201F;
#endif
                if (!it_chunk(code + pos, ilen)) memcpy(code + pos, backup, ilen);
                break;
            }
            case 4:
#if defined(ARCH_X86)
                if (size < 8) break;
                size_t pos = chacha20_random(rng) % (size - 8);
                x86_inst_t inst;
                if (decode_x86(code + pos, 0, &inst, NULL) && inst.len >= 2) {
                    uint8_t orig = code[pos + 1];
                    uint8_t modrm = (orig & 0xC0) |
                                    ((chacha20_random(rng) % 8) << 3) |
                                    (chacha20_random(rng) % 8);
                    code[pos + 1] = modrm;
                    if (!it_chunk(code + pos, inst.len)) code[pos + 1] = orig;
                }
#endif
                break;
        }
    }

    if (!it_chunk(code, size)) memcpy(code, original, size);
}

void mutate(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size <= STUB_SIZE) return;
#ifdef MUTATE
    _mut8(code + STUB_SIZE, size - STUB_SIZE, rng);
#endif
}