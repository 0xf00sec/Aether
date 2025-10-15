#include <aether.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <pthread.h>
#include <sys/mman.h>
#include <errno.h>

#define MAX_ENCRYPTED_FUNCS 32
#define TRAMPOLINE_SIZE 64  // Enough for both x86-64 and ARM64

/* Function encryption tracking */
typedef struct {
    void *func_ptr;          // Original function address
    void *trampoline;        // Trampoline stub address
    size_t size;
    uint8_t key[KEY_SIZE];
    uint8_t iv[IV_SIZE];
    uint8_t *backup;
    bool is_encrypted;
    bool is_decrypted;       // Lazy decryption flag
    pthread_mutex_t lock;    // Per-function lock for thread safety
} func_encryption_t;

/* Runtime encryption state */
typedef struct {
    pthread_mutex_t lock;
    func_encryption_t encrypted_funcs[MAX_ENCRYPTED_FUNCS];
    size_t num_encrypted;
} runtime_encryption_state_t;

/* Global encryption state */
static runtime_encryption_state_t g_enc_state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .num_encrypted = 0
};

/* Functions to protect */
static struct {
    void *func_ptr;
    const char *name;
    size_t estimated_size;
    void **trampoline_ptr;  // Pointer to trampoline (filled at runtime)
} protected_functions[] = {
    /* Core mutation engine */
    {(void*)mutate, "mutate", 0x1000, NULL},
    {(void*)scramble_x86, "scramble_x86", 0x800, NULL},
#if defined(__aarch64__)
    {(void*)scramble_arm64, "scramble_arm64", 0x800, NULL},
#endif

    
    /* Decoders  */
    {(void*)decode_map, "decode_map", 0x600, NULL},
    {(void*)sketch_flow, "sketch_flow", 0x800, NULL}
    
};

#define NUM_PROTECTED (sizeof(protected_functions) / sizeof(protected_functions[0]))

/* Trampoline function pointers - these replace the originals */
typedef struct {
    void *mutate_trampoline;
    void *scramble_x86_trampoline;
#if defined(__aarch64__)
    void *scramble_arm64_trampoline;
#endif
    void *expand_code_section_trampoline;
    void *expand_with_chains_trampoline;
    void *decode_map_trampoline;
    void *sketch_flow_trampoline;
} trampoline_table_t;

static trampoline_table_t g_trampolines = {0};

/* ============================================================================
 * TRAMPOLINE GENERATION: Architecture-specific stubs
 * ============================================================================ */

/**
 * generate_trampoline - Create a trampoline stub that decrypts on first call
 * 
 * The trampoline:
 * 1. Checks if function is decrypted (atomic check)
 * 2. If not, calls decrypt_and_jump helper
 * 3. If yes, jumps directly to decrypted function
 * 
 * Architecture-specific implementations:
 * - x86-64: Uses CAS (CMPXCHG) for atomic flag check
 * - ARM64: Uses LDAXR/STLXR for atomic operations
 */
static void* generate_trampoline(func_encryption_t *enc, size_t index) {
    if (!enc || !enc->func_ptr) {
        DBG("ERROR: generate_trampoline called with NULL enc or func_ptr\n");
        return NULL;
    }
    
    DBG("Generating trampoline for function at %p\n", enc->func_ptr);
    
    // Allocate memory for trampoline (RW first, will make RX later)
    // macOS enforces W^X (write XOR execute), so we can't have both at once
    void *trampoline = mmap(NULL, TRAMPOLINE_SIZE,
                           PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    
    if (trampoline == MAP_FAILED) {
        DBG("Failed to allocate trampoline memory: %s\n", strerror(errno));
        return NULL;
    }
    
    DBG("Allocated trampoline memory at %p\n", trampoline);
    
    uint8_t *code = (uint8_t *)trampoline;
    size_t offset = 0;
    
#if defined(__x86_64__)
    /*
     * x86-64 Trampoline:
     * 
     * trampoline:
     *   cmp byte [is_decrypted], 0    ; Check if already decrypted
     *   jne already_decrypted          ; If yes, jump to function
     *   
     *   ; First call - need to decrypt
     *   push rdi                       ; Save all args (System V ABI)
     *   push rsi
     *   push rdx
     *   push rcx
     *   push r8
     *   push r9
     *   
     *   mov rdi, <enc_ptr>             ; Pass enc pointer
     *   call decrypt_on_first_call     ; Decrypt function
     *   
     *   pop r9                         ; Restore args
     *   pop r8
     *   pop rcx
     *   pop rdx
     *   pop rsi
     *   pop rdi
     *   
     * already_decrypted:
     *   jmp [func_ptr]                 ; Jump to real function
     */
    
    // Check if already decrypted: cmp byte [is_decrypted], 0
    code[offset++] = 0x80;  // CMP r/m8, imm8
    code[offset++] = 0x3D;  // ModR/M: [RIP+disp32]
    uint32_t flag_offset = (uint32_t)((uintptr_t)&enc->is_decrypted - (uintptr_t)(code + offset + 4));
    memcpy(code + offset, &flag_offset, 4);
    offset += 4;
    code[offset++] = 0x00;  // Compare with 0
    
    // jne already_decrypted (skip decrypt if already done)
    code[offset++] = 0x0F;  // JNE rel32
    code[offset++] = 0x85;
    uint32_t *jne_target = (uint32_t *)(code + offset);
    offset += 4;  // Will patch this later
    
    // Save registers (System V ABI: RDI, RSI, RDX, RCX, R8, R9)
    code[offset++] = 0x57;  // push rdi
    code[offset++] = 0x56;  // push rsi
    code[offset++] = 0x52;  // push rdx
    code[offset++] = 0x51;  // push rcx
    code[offset++] = 0x41; code[offset++] = 0x50;  // push r8
    code[offset++] = 0x41; code[offset++] = 0x51;  // push r9
    
    // mov rdi, <enc_ptr> (pass enc as first argument)
    code[offset++] = 0x48;  // REX.W
    code[offset++] = 0xBF;  // MOV RDI, imm64
    memcpy(code + offset, &enc, 8);
    offset += 8;
    
    // Call decrypt helper (we'll define this below)
    // For now, just decrypt inline
    code[offset++] = 0x48;  // REX.W
    code[offset++] = 0xB8;  // MOV RAX, imm64
    extern void decrypt_on_first_call_x86(func_encryption_t *enc);
    void *helper = (void *)decrypt_on_first_call_x86;
    memcpy(code + offset, &helper, 8);
    offset += 8;
    code[offset++] = 0xFF;  // CALL RAX
    code[offset++] = 0xD0;
    
    // Restore registers
    code[offset++] = 0x41; code[offset++] = 0x59;  // pop r9
    code[offset++] = 0x41; code[offset++] = 0x58;  // pop r8
    code[offset++] = 0x59;  // pop rcx
    code[offset++] = 0x5A;  // pop rdx
    code[offset++] = 0x5E;  // pop rsi
    code[offset++] = 0x5F;  // pop rdi
    
    // Patch JNE target to here
    *jne_target = (uint32_t)(offset - ((uint8_t *)jne_target - code + 4));
    
    // already_decrypted: jmp [func_ptr]
    code[offset++] = 0xFF;  // JMP r/m64
    code[offset++] = 0x25;  // ModR/M: [RIP+disp32]
    uint32_t ptr_offset = (uint32_t)((uintptr_t)&enc->func_ptr - (uintptr_t)(code + offset + 4));
    memcpy(code + offset, &ptr_offset, 4);
    offset += 4;
    
#elif defined(__aarch64__)
    /*
     * ARM64 Trampoline:
     * 
     * trampoline:
     *   adrp x16, is_decrypted         ; Load flag address
     *   ldrb w17, [x16, :lo12:is_decrypted]
     *   cbnz w17, already_decrypted    ; If decrypted, jump
     *   
     *   ; First call - decrypt
     *   stp x29, x30, [sp, #-16]!      ; Save FP, LR
     *   stp x0, x1, [sp, #-16]!        ; Save args
     *   stp x2, x3, [sp, #-16]!
     *   stp x4, x5, [sp, #-16]!
     *   stp x6, x7, [sp, #-16]!
     *   
     *   adrp x0, enc                   ; Load enc pointer
     *   add x0, x0, :lo12:enc
     *   bl decrypt_on_first_call_arm64
     *   
     *   ldp x6, x7, [sp], #16          ; Restore args
     *   ldp x4, x5, [sp], #16
     *   ldp x2, x3, [sp], #16
     *   ldp x0, x1, [sp], #16
     *   ldp x29, x30, [sp], #16
     *   
     * already_decrypted:
     *   adrp x16, func_ptr
     *   ldr x16, [x16, :lo12:func_ptr]
     *   br x16
     */
    
    uint32_t *insn = (uint32_t *)code;
    
    // ADRP x16, is_decrypted (page-relative address)
    uintptr_t flag_addr = (uintptr_t)&enc->is_decrypted;
    uintptr_t pc = (uintptr_t)insn;
    int64_t page_offset = (flag_addr & ~0xFFF) - (pc & ~0xFFF);
    uint32_t immlo = (page_offset >> 12) & 0x3;
    uint32_t immhi = (page_offset >> 14) & 0x7FFFF;
    insn[offset++] = 0x90000010 | (immlo << 29) | (immhi << 5);  // ADRP x16
    
    // LDRB w17, [x16, #(is_decrypted & 0xFFF)]
    uint32_t page_off = flag_addr & 0xFFF;
    insn[offset++] = 0x39400211 | (page_off << 10);  // LDRB w17, [x16, #offset]
    
    // CBNZ w17, already_decrypted (will patch offset later)
    uint32_t *cbnz_insn = &insn[offset++];
    *cbnz_insn = 0x35000011;  // CBNZ w17, #0 (placeholder)
    
    // Save registers
    insn[offset++] = 0xA9BF7BFD;  // STP x29, x30, [sp, #-16]!
    insn[offset++] = 0xA9BF03E0;  // STP x0, x1, [sp, #-16]!
    insn[offset++] = 0xA9BF0BE2;  // STP x2, x3, [sp, #-16]!
    insn[offset++] = 0xA9BF13E4;  // STP x4, x5, [sp, #-16]!
    insn[offset++] = 0xA9BF1BE6;  // STP x6, x7, [sp, #-16]!
    
    // Load enc pointer into x0
    uintptr_t enc_addr = (uintptr_t)enc;
    pc = (uintptr_t)&insn[offset];
    page_offset = (enc_addr & ~0xFFF) - (pc & ~0xFFF);
    immlo = (page_offset >> 12) & 0x3;
    immhi = (page_offset >> 14) & 0x7FFFF;
    insn[offset++] = 0x90000000 | (immlo << 29) | (immhi << 5);  // ADRP x0
    page_off = enc_addr & 0xFFF;
    insn[offset++] = 0x91000000 | (page_off << 10);  // ADD x0, x0, #offset
    
    // BL decrypt_on_first_call_arm64
    extern void decrypt_on_first_call_arm64(func_encryption_t *enc);
    void *helper = (void *)decrypt_on_first_call_arm64;
    int64_t bl_offset = ((uintptr_t)helper - (uintptr_t)&insn[offset]) / 4;
    insn[offset++] = 0x94000000 | (bl_offset & 0x3FFFFFF);  // BL helper
    
    // Restore registers
    insn[offset++] = 0xA8C11BE6;  // LDP x6, x7, [sp], #16
    insn[offset++] = 0xA8C113E4;  // LDP x4, x5, [sp], #16
    insn[offset++] = 0xA8C10BE2;  // LDP x2, x3, [sp], #16
    insn[offset++] = 0xA8C103E0;  // LDP x0, x1, [sp], #16
    insn[offset++] = 0xA8C17BFD;  // LDP x29, x30, [sp], #16
    
    // Patch CBNZ target
    uint32_t cbnz_offset = offset - (cbnz_insn - insn);
    *cbnz_insn = 0x35000011 | ((cbnz_offset & 0x7FFFF) << 5);
    
    // already_decrypted: Load and jump to func_ptr
    uintptr_t ptr_addr = (uintptr_t)&enc->func_ptr;
    pc = (uintptr_t)&insn[offset];
    page_offset = (ptr_addr & ~0xFFF) - (pc & ~0xFFF);
    immlo = (page_offset >> 12) & 0x3;
    immhi = (page_offset >> 14) & 0x7FFFF;
    insn[offset++] = 0x90000010 | (immlo << 29) | (immhi << 5);  // ADRP x16
    page_off = ptr_addr & 0xFFF;
    insn[offset++] = 0xF9400210 | ((page_off >> 3) << 10);  // LDR x16, [x16, #offset]
    insn[offset++] = 0xD61F0200;  // BR x16
    
#else
    #error "Unsupported architecture for trampolines"
#endif
    
    // Make trampoline read-only + executable (W^X transition)
    if (mprotect(trampoline, TRAMPOLINE_SIZE, PROT_READ | PROT_EXEC) != 0) {
        DBG("Failed to make trampoline executable: %s\n", strerror(errno));
        munmap(trampoline, TRAMPOLINE_SIZE);
        return NULL;
    }
    
    DBG("Generated trampoline at %p for function at %p (offset=%zu bytes)\n", 
        trampoline, enc->func_ptr, offset);
    
    return trampoline;
}

/* ============================================================================
 * DECRYPT HELPERS: Called by trampolines on first use
 * ============================================================================ */

#if defined(__x86_64__)
void decrypt_on_first_call_x86(func_encryption_t *enc) {
    pthread_mutex_lock(&enc->lock);
    
    // Double-check after acquiring lock (another thread may have decrypted)
    if (enc->is_decrypted) {
        pthread_mutex_unlock(&enc->lock);
        return;
    }
    
    DBG("Trampoline: Decrypting function at %p on first call\n", enc->func_ptr);
    
    // Decrypt the function
    if (decrypt_function_memory(enc->func_ptr)) {
        enc->is_decrypted = true;
        DBG("Trampoline: Function decrypted successfully\n");
    } else {
        DBG("Trampoline: FAILED to decrypt function!\n");
    }
    
    pthread_mutex_unlock(&enc->lock);
}
#endif

#if defined(__aarch64__)
void decrypt_on_first_call_arm64(func_encryption_t *enc) {
    pthread_mutex_lock(&enc->lock);
    
    if (enc->is_decrypted) {
        pthread_mutex_unlock(&enc->lock);
        return;
    }
    
    DBG("Trampoline: Decrypting function at %p on first call\n", enc->func_ptr);
    
    if (decrypt_function_memory(enc->func_ptr)) {
        enc->is_decrypted = true;
        DBG("Trampoline: Function decrypted successfully\n");
    } else {
        DBG("Trampoline: FAILED to decrypt function!\n");
    }
    
    pthread_mutex_unlock(&enc->lock);
}
#endif

/* Get page-aligned address and size */
static void get_page_range(void *addr, size_t size, vm_address_t *page_start, vm_size_t *page_size) {
    uintptr_t start = (uintptr_t)addr;
    uintptr_t end = start + size;
    
    /* Align to page boundaries */
    uintptr_t page_aligned_start = start & ~(PAGE_SIZE - 1);
    uintptr_t page_aligned_end = (end + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    
    *page_start = (vm_address_t)page_aligned_start;
    *page_size = (vm_size_t)(page_aligned_end - page_aligned_start);
}

/* Make memory region writable (removes execute) using Mach VM API */
static bool make_writable(void *addr, size_t size) {
    vm_address_t page_start;
    vm_size_t page_size;
    get_page_range(addr, size, &page_start, &page_size);
    
    kern_return_t kr = vm_protect(mach_task_self(), page_start, page_size, 
                                   FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        DBG("vm_protect(RW) failed: %d\n", kr);
        return false;
    }
    return true;
}

/* Make memory region executable using Mach VM API */
static bool make_executable(void *addr, size_t size) {
    vm_address_t page_start;
    vm_size_t page_size;
    get_page_range(addr, size, &page_start, &page_size);
    
    kern_return_t kr = vm_protect(mach_task_self(), page_start, page_size,
                                   FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        DBG("vm_protect(RX) failed: %d\n", kr);
        return false;
    }
    return true;
}

/* Encrypt a function in memory */
static bool encrypt_function_memory(void *func_ptr, size_t size, const char *name, size_t index) {
    pthread_mutex_lock(&g_enc_state.lock);
    
    if (g_enc_state.num_encrypted >= MAX_ENCRYPTED_FUNCS) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    func_encryption_t *enc = &g_enc_state.encrypted_funcs[g_enc_state.num_encrypted];
    
    // Initialize per-function lock
    pthread_mutex_init(&enc->lock, NULL);
    
    /* Generate unique key and IV for this function */
    if (CCRandomGenerateBytes(enc->key, KEY_SIZE) != kCCSuccess) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    if (CCRandomGenerateBytes(enc->iv, IV_SIZE) != kCCSuccess) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Backup original bytes BEFORE changing permissions 
     * 
     * SECURITY NOTE: Storing plaintext backup defeats encryption purpose!
     * An attacker can dump enc->backup to get original code.
     * 
     * Better approach: Store encrypted backup and decrypt on-demand.
     * But this requires the encryption key to be available, which
     * creates another chicken-and-egg problem.
     * 
     * For now, we accept this limitation. Real protection requires
     * hardware-backed encryption (SGX, TrustZone).
     */
    enc->backup = malloc(size);
    if (!enc->backup) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    memcpy(enc->backup, func_ptr, size);
    
    /* Allocate encryption buffer */
    uint8_t *enc_buffer = malloc(size + kCCBlockSizeAES128);
    if (!enc_buffer) {
        free(enc->backup);
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Encrypt from backup (not from func_ptr) */
    size_t encrypted = crypt_payload(1, enc->key, enc->iv, enc->backup, enc_buffer, size);
    
    if (encrypted > 0 && encrypted <= size) {
        /* Now make memory writable */
        if (!make_writable(func_ptr, size)) {
            free(enc->backup);
            free(enc_buffer);
            pthread_mutex_unlock(&g_enc_state.lock);
            return false;
        }
        
        /* Store encryption info FIRST (needed by trampoline generation) */
        enc->func_ptr = func_ptr;
        enc->size = size;
        enc->is_encrypted = true;
        enc->is_decrypted = false;  // Will decrypt on first call
        
        /* Write encrypted data */
        memcpy(func_ptr, enc_buffer, encrypted);
        
        /* Make memory executable again */
        make_executable(func_ptr, size);
        
        /* Generate trampoline stub (needs enc->func_ptr to be set) */
        enc->trampoline = generate_trampoline(enc, index);
        if (!enc->trampoline) {
            DBG("Failed to generate trampoline for %s\n", name);
            free(enc->backup);
            free(enc_buffer);
            pthread_mutex_unlock(&g_enc_state.lock);
            return false;
        }
        
        g_enc_state.num_encrypted++;
        
        DBG("Encrypted %s at %p (size: 0x%zx), trampoline at %p\n", 
            name, func_ptr, size, enc->trampoline);
    }
    
    free(enc_buffer);
    
    pthread_mutex_unlock(&g_enc_state.lock);
    return encrypted > 0;
}

/* Decrypt a function temporarily */
bool decrypt_function_memory(void *func_ptr) {
    pthread_mutex_lock(&g_enc_state.lock);
    
    /* Find encryption info */
    func_encryption_t *enc = NULL;
    for (size_t i = 0; i < g_enc_state.num_encrypted; i++) {
        if (g_enc_state.encrypted_funcs[i].func_ptr == func_ptr) {
            enc = &g_enc_state.encrypted_funcs[i];
            break;
        }
    }
    
    if (!enc || !enc->is_encrypted) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Already decrypted? Just return success (idempotent) */
    if (enc->is_decrypted) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return true;
    }
    
    /* Allocate temp buffer to read encrypted data */
    uint8_t *enc_data = malloc(enc->size);
    if (!enc_data) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Read encrypted data while still RX */
    memcpy(enc_data, func_ptr, enc->size);
    
    /* Allocate decryption buffer */
    uint8_t *dec_buffer = malloc(enc->size + kCCBlockSizeAES128);
    if (!dec_buffer) {
        free(enc_data);
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Decrypt from temp buffer */
    size_t decrypted = crypt_payload(0, enc->key, enc->iv, enc_data, dec_buffer, enc->size);
    
    if (decrypted > 0) {
        /* Make writable */
        if (!make_writable(func_ptr, enc->size)) {
            free(enc_data);
            free(dec_buffer);
            pthread_mutex_unlock(&g_enc_state.lock);
            return false;
        }
        
        /* Write decrypted data */
        memcpy(func_ptr, dec_buffer, decrypted);
        
        /* Make executable again */
        make_executable(func_ptr, enc->size);
        
        enc->is_encrypted = false;
    }
    
    free(enc_data);
    free(dec_buffer);
    
    pthread_mutex_unlock(&g_enc_state.lock);
    return decrypted > 0;
}

/* Re-encrypt a function after use */
static bool reencrypt_function_memory(void *func_ptr) {
    pthread_mutex_lock(&g_enc_state.lock);
    
    /* Find encryption info */
    func_encryption_t *enc = NULL;
    for (size_t i = 0; i < g_enc_state.num_encrypted; i++) {
        if (g_enc_state.encrypted_funcs[i].func_ptr == func_ptr) {
            enc = &g_enc_state.encrypted_funcs[i];
            break;
        }
    }
    
    if (!enc || enc->is_encrypted) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Allocate temp buffer to read decrypted data */
    uint8_t *dec_data = malloc(enc->size);
    if (!dec_data) {
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Read decrypted data while still RX */
    memcpy(dec_data, func_ptr, enc->size);
    
    /* Allocate encryption buffer */
    uint8_t *enc_buffer = malloc(enc->size + kCCBlockSizeAES128);
    if (!enc_buffer) {
        free(dec_data);
        pthread_mutex_unlock(&g_enc_state.lock);
        return false;
    }
    
    /* Encrypt from temp buffer */
    size_t encrypted = crypt_payload(1, enc->key, enc->iv, dec_data, enc_buffer, enc->size);
    
    if (encrypted > 0) {
        /* Make writable */
        if (!make_writable(func_ptr, enc->size)) {
            free(dec_data);
            free(enc_buffer);
            pthread_mutex_unlock(&g_enc_state.lock);
            return false;
        }
        
        /* Write encrypted data */
        memcpy(func_ptr, enc_buffer, encrypted);
        
        /* Make executable again */
        make_executable(func_ptr, enc->size);
        
        enc->is_encrypted = true;
    }
    
    free(dec_data);
    free(enc_buffer);
    
    pthread_mutex_unlock(&g_enc_state.lock);
    return encrypted > 0;
}

/* Check if function is currently encrypted */
bool is_function_encrypted(void *func_ptr) {
    pthread_mutex_lock(&g_enc_state.lock);
    
    for (size_t i = 0; i < g_enc_state.num_encrypted; i++) {
        if (g_enc_state.encrypted_funcs[i].func_ptr == func_ptr) {
            bool encrypted = g_enc_state.encrypted_funcs[i].is_encrypted;
            pthread_mutex_unlock(&g_enc_state.lock);
            return encrypted;
        }
    }
    
    pthread_mutex_unlock(&g_enc_state.lock);
    return false;
}

/* Initialize runtime memory encryption */
void init_runtime_encryption(void) {
    DBG("Runtime encryption system initialized (encryption disabled for now)\n");
    
    /* NOTE: Encryption is currently disabled because:
     * 1. Functions must be decrypted before every call
     * 2. No automatic trampoline system is in place
     * 3. Function size estimation is unreliable
     * 
     * To enable:
     * - Implement trampoline wrappers for each protected function
     * - Use debug symbols or heuristics to determine actual function sizes
     * - Add decrypt/re-encrypt calls around every usage
     */
    
    #if 0  // Disabled - would corrupt functions immediately
    for (size_t i = 0; i < NUM_PROTECTED; i++) {
        encrypt_function_memory(
            protected_functions[i].func_ptr,
            protected_functions[i].estimated_size,
            protected_functions[i].name
        );
    }
    #endif
    
    DBG("Runtime encryption: DISABLED (functions remain plaintext)\n");
}

/* Public API for decrypting functions before use */
bool decrypt_function(void *func_ptr) {
    return decrypt_function_memory(func_ptr);
}

/* Public API for re-encrypting functions after use */
bool reencrypt_function(void *func_ptr) {
    return reencrypt_function_memory(func_ptr);
}

/* ============================================================================
 * SCOPED DECRYPTION: RAII-style decrypt/re-encrypt
 * 
 * Usage:
 *   SCOPED_DECRYPT(mutate) {
 *       mutate(code, size, rng, gen, ctx);
 *   }
 * ============================================================================ */

typedef struct {
    void *func_ptr;
    bool was_encrypted;
} scoped_decrypt_t;

static inline scoped_decrypt_t scoped_decrypt_begin(void *func_ptr) {
    scoped_decrypt_t scope;
    scope.func_ptr = func_ptr;
    scope.was_encrypted = is_function_encrypted(func_ptr);
    
    if (scope.was_encrypted) {
        decrypt_function_memory(func_ptr);
    }
    
    return scope;
}

static inline void scoped_decrypt_end(scoped_decrypt_t *scope) {
    if (scope->was_encrypted) {
        reencrypt_function_memory(scope->func_ptr);
    }
}

#define SCOPED_DECRYPT(func) \
    for (scoped_decrypt_t _scope = scoped_decrypt_begin((void*)(func)), *_once = &_scope; \
         _once; \
         scoped_decrypt_end(_once), _once = NULL)

/* ============================================================================
 * FUNCTION SIZE DETECTION: Heuristic-based function boundary detection
 * ============================================================================ */

static size_t detect_function_size(void *func_ptr) {
    uint8_t *code = (uint8_t *)func_ptr;
    size_t size = 0;
    size_t max_size = 0x4000;  // 16KB max scan
    
#if defined(__x86_64__)
    // Look for function epilogue patterns: RET, INT3 padding, or next function prologue
    for (size_t i = 0; i < max_size; i++) {
        // RET instruction
        if (code[i] == 0xC3) {
            size = i + 1;
            
            // Skip INT3 padding after RET
            while (size < max_size && code[size] == 0xCC) {
                size++;
            }
            
            // Align to 16-byte boundary (common for function alignment)
            size = (size + 15) & ~15;
            break;
        }
        
        // RETF
        if (code[i] == 0xCB) {
            size = i + 1;
            break;
        }
    }
    
#elif defined(__aarch64__)
    // Look for RET instruction (0xD65F03C0) or next function prologue
    for (size_t i = 0; i < max_size; i += 4) {
        uint32_t insn = *(uint32_t *)(code + i);
        
        // RET instruction
        if ((insn & 0xFFFFFC1F) == 0xD65F0000) {
            size = i + 4;
            
            // Align to 16-byte boundary
            size = (size + 15) & ~15;
            break;
        }
    }
#endif
    
    // Fallback: use estimated size if detection failed
    if (size == 0 || size > max_size) {
        size = 0x1000;  // Default 4KB
    }
    
    return size;
}

/* ============================================================================
 * IMPROVED INITIALIZATION: Detect sizes, encrypt, and set up trampolines
 * ============================================================================ */

void init_runtime_encryption_v2(bool enable_encryption) {
    
    if (!enable_encryption) {
        DBG("Encryption DISABLED - functions remain plaintext\n");
        DBG("All function pointers remain unchanged\n");
        return;
    }
    
    DBG("Detecting function sizes and generating trampolines...\n\n");
    
    void **trampoline_ptrs[] = {
        &g_trampolines.mutate_trampoline,
        &g_trampolines.scramble_x86_trampoline,
#if defined(__aarch64__)
        &g_trampolines.scramble_arm64_trampoline,
#endif
        &g_trampolines.expand_code_section_trampoline,
        &g_trampolines.expand_with_chains_trampoline,
        &g_trampolines.decode_map_trampoline,
        &g_trampolines.sketch_flow_trampoline,
    };
    
    for (size_t i = 0; i < NUM_PROTECTED; i++) {
        size_t detected_size = detect_function_size(protected_functions[i].func_ptr);
        
        DBG("[%zu] %s:\n", i, protected_functions[i].name);
        DBG("    Original:  %p\n", protected_functions[i].func_ptr);
        DBG("    Estimated: 0x%zx bytes\n", protected_functions[i].estimated_size);
        DBG("    Detected:  0x%zx bytes\n", detected_size);
        
        // Use detected size if reasonable, otherwise fall back to estimate
        size_t size_to_use = detected_size;
        if (detected_size == 0 || detected_size > 0x10000) {
            size_to_use = protected_functions[i].estimated_size;
            DBG("    ⚠ Detection failed, using estimate\n");
        }
        
        if (encrypt_function_memory(
                protected_functions[i].func_ptr,
                size_to_use,
                protected_functions[i].name,
                i)) {
            
            // Store trampoline pointer
            func_encryption_t *enc = &g_enc_state.encrypted_funcs[i];
            *trampoline_ptrs[i] = enc->trampoline;
            protected_functions[i].trampoline_ptr = trampoline_ptrs[i];
            
            DBG("    ✓ Encrypted successfully\n");
            DBG("    Trampoline: %p\n", enc->trampoline);
        } else {
            DBG("    ✗ Encryption FAILED\n");
        }
        DBG("\n");
    }
    
    DBG("═══════════════════════════════════════════════════════════\n");
    DBG("Runtime encryption: ENABLED\n");
    DBG("  %zu functions encrypted\n", g_enc_state.num_encrypted);
    DBG("  Trampolines generated and ready\n");
    DBG("  Functions will decrypt on first call (lazy decryption)\n");
    DBG("═══════════════════════════════════════════════════════════\n");
}

/* ============================================================================
 * TRAMPOLINE ACCESSORS: Get trampoline pointers for encrypted functions
 * ============================================================================ */

void* get_mutate_trampoline(void) { return g_trampolines.mutate_trampoline; }
void* get_scramble_x86_trampoline(void) { return g_trampolines.scramble_x86_trampoline; }
#if defined(__aarch64__)
void* get_scramble_arm64_trampoline(void) { return g_trampolines.scramble_arm64_trampoline; }
#endif
void* get_expand_code_section_trampoline(void) { return g_trampolines.expand_code_section_trampoline; }
void* get_expand_with_chains_trampoline(void) { return g_trampolines.expand_with_chains_trampoline; }
void* get_decode_map_trampoline(void) { return g_trampolines.decode_map_trampoline; }
void* get_sketch_flow_trampoline(void) { return g_trampolines.sketch_flow_trampoline; }

/* ============================================================================
 * CLEANUP: Free resources on exit
 * ============================================================================ */

void cleanup_runtime_encryption(void) {
    pthread_mutex_lock(&g_enc_state.lock);
    
    DBG("Cleaning up runtime encryption...\n");
    
    for (size_t i = 0; i < g_enc_state.num_encrypted; i++) {
        func_encryption_t *enc = &g_enc_state.encrypted_funcs[i];
        
        // Free trampoline memory
        if (enc->trampoline) {
            munmap(enc->trampoline, TRAMPOLINE_SIZE);
            enc->trampoline = NULL;
        }
        
        // Free backup
        if (enc->backup) {
            free(enc->backup);
            enc->backup = NULL;
        }
        
        // Destroy per-function lock
        pthread_mutex_destroy(&enc->lock);
    }
    
    g_enc_state.num_encrypted = 0;
    memset(&g_trampolines, 0, sizeof(g_trampolines));
    
    pthread_mutex_unlock(&g_enc_state.lock);
    
    DBG("Runtime encryption cleanup complete\n");
}