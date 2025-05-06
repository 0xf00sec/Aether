/*
 * + Author: 0x00s
 * + Notes:
 * - macOS Gatekeeper may flag it based on static heuristics, 
 * - XProtect consistently fails to detect it due to runtime mutation.
 * - Originally developed from internal research and shared publicly to demonstrate core techniques.
 *   – Fully extensible for new techniques.
 *   – Basic macOS Gatekeeper/XProtect evasion is integrated, but
 *     this is meant to be a research sample, not a production release.
 *     Some modifications are needed to fix certain issues and update a few functions for proper execution.
 *     For now, you can test the mutation and execution with the simple function below and run `./testme.sh` for more verbose output.
 *     Operational code can still be performed if you know what you're doing.
 *     More details will be covered in the next part of the series (III).
 *
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
