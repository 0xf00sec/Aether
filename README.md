Aether is a metamorphic implant (x86/ARM) that rewrites its own executable at runtime through liveness-aware instruction mutation and reflective loading. It mutates instruction by instruction, preserving behavior while evading static analysis. The engine uses in-memory encryption, 
native APIs, and Mach-O tricks, with a dead-drop C2 for communication, Anti-analysis features include ptrace blocking, debugger detection, self-destruct, and memory-only execution.

> Just a PoC no funny shit! it's detectable during behavioral analysis. However, if you know what you're doing, everything is modular you can extend modules
for custom evasion, alternative C2s, stealth, or persistence. Each payload generation looks completely different from the last but behaves identically.

**RESEARCH USE ONLY.**
