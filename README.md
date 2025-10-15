# Aether

Aether is a minimalist macOS piece (x86/ARM) designed for runtime mutation and metamorphism through instruction-level. It rewrites its own executable code at runtime to evade static analysis while preserving semantics. In-memory encryption and a dead-drop C2 are used, and it operates entirely via native APIs and Mach-O manipulation.

> This is just a PoC. No funny shit! it’s detectable during behavioral analysis. However, if you know what you’re doing, you can extend each module for custom techniques, dynamic C2, stealth, alternative persistence methods, or simply extract the engine and use it standalone or build it how you like.

#### RESEARCH USE ONLY.