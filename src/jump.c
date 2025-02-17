#include "wisp.h"

//===================================================================
//      JUMP TABLE FUNCTIONS
//===================================================================


/**
 * Invoked by the jump table.
 */
void pickme(void) {
    printf("Alive!");
    // sendprofile(); 
    // Reset...
}

void cani(void) {
    request();
}

void nah(void) {
    // Later, still need some matches.
    destruct_mode();
}

void later(void) {
    // Faux
    for (int i = 0; i < 10; i++) {
        // TODO: Add later.
    }
}

#if defined(__x86_64__)
const uint8_t ramp[] = {
    0x48, 0xB8,             // mov rax, imm64
    0, 0, 0, 0, 0, 0, 0, 0,  
    0x8B, 0x08,             // mov ecx, dword ptr [rax]
    0x48, 0xBA,             // mov rdx, imm64
    0, 0, 0, 0, 0, 0, 0, 0, 
    0x48, 0x8B, 0x04, 0xCA, // mov rax, [rdx+rcx*8]
    0xFF, 0xE0              // jmp rax
};
const size_t te_len = sizeof(ramp);
#elif defined(__arm64__)
const uint8_t ramp[] = { 0x00 };
const size_t te_len = 1;
#endif


volatile uint32_t dex = 0;
// some branching
volatile void (*tramp_[])(void) = { pickme, nah };
uint32_t weight(ChaChaRNG *rng) {
    if (De()) { 
        return 1;
    }
    uint32_t r = chacha20_random(rng) % 100;
    uint32_t t = ((r ^ 0xA5A5A5A5UL) + (r >> 3)) % 100;
    return (t < 50) ? 0 : 1; // you think you funny? Fifty/5ifty = 1 
}
