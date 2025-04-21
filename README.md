# Aether

Aether, self-modifying implant designed for macOS, demonstrating runtime code mutation, and C2 communication. written with stealth in mind, it leverages Mach-O internals, encryption, anti-analysis and persistence.

----

```                        
+-------------------------------+
|  Where You At?                |
|       (~/Downloads?)          |
+---------------+---------------+
                │
      ┌─────────┴─────────┐
      │                   │
      ▼                   ▼
+--------------+   +----------------------------+
| Copy self to |   |         Self-destruct      |
|  /tmp & exec |   | (if already inside ~/else) |
+--------------+   +----------------------------+
       │
       ▼
+-------------------------------+
|  Continue ...                 |
+-------------------------------+
```

---

## Structure

- **src/entry.c** –  Entry point that decrypts, mutates, re‑encrypts, and executes the payload.
- **src/mutation.c** – Mutation routines using the Capstone disassembly engine.
- **src/chacha.c** – ChaCha20-based randomness and key stream generation.
- **src/crypto.c** – AES-based encryption and decryption.
- **src/overnout.c** – Deals with data packaging, compression, encryption, and network exfiltration.
- **src/parasite.c & criteria.c** – Self-Explanatory
- **src/autodestruction.c** – Wipes the binary when conditions aren't met, triggering `auto-destruction`.
---

**RESEARCH USE ONLY**. *No funny shit!*
