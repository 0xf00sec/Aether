# Aether

Aether is a piece that demonstrates self-modifying^techniques on macOS by combining code mutation, layered cryptography, anti-debugging measures, and persistence.

Blog Post : https://0x00sec.org/t/macos-malware-volume-ii/

---

- **Self‑Modifying Code & Mutation**  
- **Re‑Encryption and Checks**  
- **Anti‑Debug/Anti‑Analysis**  
- **System Profiling & File Collection**  
- **Persistence, Self‑Relocation & Auto‑Destruction**  
---

## What You Need

- **Platform:** macOS (Mach‑O binaries)
- **Compiler:** clang
- **Dependencies:**  
  - [Capstone](https://www.capstone-engine.org/)  
  - [OpenSSL](https://www.openssl.org/)  
  - [CommonCrypto](https://developer.apple.com/documentation/security/common_crypto) (macOS Framework)  
  - [libcurl](https://curl.se/libcurl/)  
  - [zlib](https://www.zlib.net/)

Ensure you have all of this installed before building.

---

To compile, simply run:

```bash
make
```

To clean build artifacts, run:

```bash
make clean
```

---

```bash
./aether
```

Upon execution, the binary will:    
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

---

Author: 
- [@0x0000000000000000](https://github.com/0xf00s/)
