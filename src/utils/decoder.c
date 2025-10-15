#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include "aether.h"


typedef struct {const uint8_t *buf;size_t size;uintptr_t base;} mem_ctx_t;
mem_ctx_t ctx;

bool decode_x86_withme(const uint8_t *code, size_t size, uintptr_t ip, x86_inst_t *inst, memread_fn mem_read);
bool mem_read(void *dest, uintptr_t addr, size_t size, mem_ctx_t *ctx) {
    if (addr < ctx->base || addr + size > ctx->base + ctx->size) return false;
    size_t off = addr - ctx->base;
    memcpy(dest, ctx->buf + off, size);
    return true;
}
bool wrapper_mem_read(void *dest, uintptr_t addr, size_t size) {
    extern mem_ctx_t ctx;
    return mem_read(dest, addr, size, &ctx);}

// Register name tables
static const char* const REG8[8]  = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
static const char* const REG16[8] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
static const char* const REG32[8] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
static const char* const REG64[16] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", 
                                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};

static inline uint8_t get_reg_code(uint8_t modrm) {
    return (modrm >> 3) & 0x07;}
static inline const char* get_reg_name(uint8_t code, bool rex_w, uint8_t width) {
    if (rex_w) {
        return REG64[code & 0x0F];
    }
    
    switch (width) {
        case 8:  return REG8[code & 0x07];
        case 16: return REG16[code & 0x07];
        case 32: return REG32[code & 0x07];
        default: return REG32[code & 0x07]; 
    }
}

const char* guess_mnemonic(const x86_inst_t *inst) {
    if (!inst || inst->opcode_len == 0) return "invalid";

    uint8_t op0 = inst->opcode[0];
    uint8_t op1 = inst->opcode_len > 1 ? inst->opcode[1] : 0;
    uint8_t op2 = inst->opcode_len > 2 ? inst->opcode[2] : 0;

    // Single-byte opcodes
    switch (op0) {
        // Control flow
        case 0xC3: return "ret";
        case 0xC2: return "ret imm16";
        case 0xE8: return "call rel32";
        case 0xE9: return "jmp rel32";
        case 0xEB: return "jmp rel8";
        case 0xFF:
            if (inst->has_modrm) {
                uint8_t reg = modrm_reg(inst->modrm);
                switch (reg) {
                    case 2: return "call r/m";
                    case 4: return "jmp r/m";
                    case 5: return "jmp far";
                }
            }
            break;

        // Conditional jumps (short)
        case 0x70: return "jo rel8";   case 0x71: return "jno rel8";
        case 0x72: return "jb rel8";   case 0x73: return "jnb rel8";
        case 0x74: return "jz rel8";   case 0x75: return "jnz rel8";
        case 0x76: return "jbe rel8";  case 0x77: return "ja rel8";
        case 0x78: return "js rel8";   case 0x79: return "jns rel8";
        case 0x7A: return "jp rel8";   case 0x7B: return "jnp rel8";
        case 0x7C: return "jl rel8";   case 0x7D: return "jnl rel8";
        case 0x7E: return "jle rel8";  case 0x7F: return "jg rel8";

        // Loops
        case 0xE0: return "loopne rel8";
        case 0xE1: return "loope rel8";
        case 0xE2: return "loop rel8";
        case 0xE3: return "jcxz rel8";

        // Stack ops
        case 0x50 ... 0x57: return "push reg";
        case 0x58 ... 0x5F: return "pop reg";
        case 0x68: return "push imm32";
        case 0x6A: return "push imm8";

        // MOV instructions
        case 0x88: return "mov r/m8, r8";
        case 0x89: return "mov r/m, r";
        case 0x8A: return "mov r8, r/m8";
        case 0x8B: return "mov r, r/m";
        case 0x8C: return "mov r/m, sreg";
        case 0xA0: return "mov al, moffs8";
        case 0xA1: return "mov eax, moffs32";
        case 0xA2: return "mov moffs8, al";
        case 0xA3: return "mov moffs32, eax";
        case 0xB0 ... 0xB7: return "mov reg8, imm8";
        case 0xB8 ... 0xBF: return inst->rex_w ? "mov reg64, imm64" : "mov reg, imm";

        // Arithmetic
        case 0x00: return "add r/m8, r8";
        case 0x01: return "add r/m, r";
        case 0x02: return "add r8, r/m8";
        case 0x03: return "add r, r/m";
        case 0x04: return "add al, imm8";
        case 0x05: return "add eax, imm32";
        case 0x28: return "sub r/m8, r8";
        case 0x29: return "sub r/m, r";
        case 0x2A: return "sub r8, r/m8";
        case 0x2B: return "sub r, r/m";
        case 0x2C: return "sub al, imm8";
        case 0x2D: return "sub eax, imm32";
        case 0x30: return "xor r/m8, r8";
        case 0x31: return "xor r/m, r";
        case 0x32: return "xor r8, r/m8";
        case 0x33: return "xor r, r/m";
        case 0x34: return "xor al, imm8";
        case 0x35: return "xor eax, imm32";
        case 0x38: return "cmp r/m8, r8";
        case 0x39: return "cmp r/m, r";
        case 0x3A: return "cmp r8, r/m8";
        case 0x3B: return "cmp r, r/m";
        case 0x3C: return "cmp al, imm8";
        case 0x3D: return "cmp eax, imm32";

        // 80/83 group instructions
        case 0x80:
            if (inst->has_modrm) {
                static const char* ops[] = {"add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"};
                uint8_t reg = modrm_reg(inst->modrm);
                if (reg < 8) return ops[reg];
            }
            break;
        case 0x83:
            if (inst->has_modrm) {
                uint8_t reg = modrm_reg(inst->modrm);
                switch (reg) {
                    case 0: return "add r/m, imm8"; case 1: return "or r/m, imm8";
                    case 2: return "adc r/m, imm8"; case 3: return "sbb r/m, imm8";
                    case 4: return "and r/m, imm8"; case 5: return "sub r/m, imm8";
                    case 6: return "xor r/m, imm8"; case 7: return "cmp r/m, imm8";
                }
            }
            break;

        case 0x8D: return "lea r, m";

        // NOP and prefixes
        case 0x90: return "nop";
        case 0xF3: return "rep";
        case 0xF2: return "repne";
        case 0xF0: return "lock";
    }

    // Two-byte opcodes (0F prefix)
    if (op0 == 0x0F) {
        switch (op1) {
            case 0x1F: return "nop";
            case 0x20: return "mov r, cr";
            case 0x22: return "mov cr, r";
            case 0x31: return "rdtsc";
            case 0xA2: return "cpuid";

            // Extended conditional jumps
            case 0x80 ... 0x8F: return "jcc rel32";

            // Bit ops
            case 0xA3: return "bt r/m, r"; case 0xAB: return "bts r/m, r";
            case 0xB3: return "btr r/m, r"; case 0xBB: return "btc r/m, r";

            // SSE/ SIMD
            case 0x10: return "movups xmm, xmm/m128";
            case 0x11: return "movups xmm/m128, xmm";
            case 0x28: return "movaps xmm, xmm/m128";
            case 0x29: return "movaps xmm/m128, xmm";
        }
    }

    // Three-byte opcodes (0F 38)
    if (op0 == 0x0F && op1 == 0x38) {
        switch (op2) {
            case 0xF0: return "crc32 r, r/m8";
            case 0xF1: return "crc32 r, r/m";
        }
    }

    return "db";
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }

    fseek(f, 0, SEEK_END);
    size_t filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *filebuf = malloc(filesize);
    if (!filebuf) { perror("malloc"); fclose(f); return 1; }
    fread(filebuf, 1, filesize, f);
    fclose(f);

    struct mach_header_64 *mh = (struct mach_header_64 *)filebuf;
    if (mh->magic != MH_MAGIC_64) {
        fprintf(stderr, "Not a 64-bit Mach-O\n");
        free(filebuf);
        return 1;
    }

    struct load_command *lc = (struct load_command *)(filebuf + sizeof(struct mach_header_64));
    uint8_t *text_section = NULL;
    size_t text_size = 0;
    uintptr_t text_addr = 0;

    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            struct section_64 *sec = (struct section_64 *)((uint8_t *)seg + sizeof(struct segment_command_64));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (strcmp(sec[j].sectname, "__text") == 0 && strcmp(sec[j].segname, "__TEXT") == 0) {
                    text_section = filebuf + sec[j].offset;
                    text_size = (size_t)sec[j].size;
                    text_addr = (uintptr_t)sec[j].addr;
                    break;
                }
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    if (!text_section) {
        fprintf(stderr, "__text section not found\n");
        free(filebuf);
        return 1;
    }

    // Set global context
    ctx.buf = text_section;
    ctx.size = text_size;
    ctx.base = text_addr;

    uintptr_t ip = text_addr;
    size_t offset = 0;

    while (offset < text_size) {
        x86_inst_t inst;
        bool ok = decode_x86_withme(text_section + offset, text_size - offset, ip + offset, &inst, wrapper_mem_read);
        if (!ok) break;

        printf("0x%08zx: ", offset);
        for (int i = 0; i < inst.len; i++) printf("%02X ", inst.raw[i]);
        printf(" | %-15s", guess_mnemonic(&inst));

        if (inst.is_control_flow) {
            printf(" -> 0x%llx", (unsigned long long)inst.target);
        }
        printf("\n");
        offset += inst.len;
    }

    free(filebuf);
    return 0;
}
