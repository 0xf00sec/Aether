/*
+ * File:        anti_debug.c
+ *   Anti-debugging module that detects when the process is being traced
+ *   and immediately triggers panic().
+ *
+ * Key:
+ *   – Obfuscated symbol resolution for sysctl via dlsym/RTLD_DEFAULT
+ *   – Runtime detection of P_TRACED flag in struct kinfo_proc
+ *   – Constructor invocation at load time
+ *
+ * Sections:
+ *   • Helpers         – symbol_i(), gctl()
+ *   • Sysctl wrapper  – getsys(), Psys()
+ *   • Detection logic – Se()
+ *   • Constructor     – De()
+ *
+ * Dependencies:
+ *   <wisp.h>         – panic(), logging macros
+ *   <dlfcn.h>        – dlsym(), RTLD_DEFAULT
+ *   <sys/sysctl.h>   – CTL_KERN, KERN_PROC, struct kinfo_proc
+ *
+ * Usage:
+ *   The constructor De()
+ *   runs before main(), and if a debugger is detected, panic() is called.
+ *
+ * Notes:
+ *   – Symbol names are generated randomly each run for evasion.
+ *   – On detection failure, module silently continues.
+ *   – Intended as PoC—extend with custom faux logic.
+ */
    #include <wisp.h>
    #include <wisp.h>

/*-------------------------------------------
  DEBUGGER? 
-------------------------------------------*/
/**
 * Seed the random number generator once.
 */
__attribute__((always_inline)) static inline void _once(void) {
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned int)(time(NULL) ^ getpid()));
        seeded = true;
    }
}

/**
 * 7-character symbol string.
 */
__attribute__((always_inline)) static inline char *symbol_i(void) {
    _once();

    char *de = malloc(7);
    if (!de)
        exit(EXIT_FAILURE);

    int method = rand() % 2;
    unsigned char k = (unsigned char)((getpid() ^ time(NULL)) & 0xFF);
    unsigned char f[6] = {0};

    if (method == 0) {
        f[0] = ((230 / 2) ^ k);
        f[1] = ((242 / 2) ^ k);
        f[2] = ((230 / 2) ^ k);
        f[3] = ((198 / 2) ^ k);
        f[4] = ((232 / 2) ^ k);
        f[5] = ((216 / 2) ^ k);
        for (int i = 0; i < 6; i++)
            de[i] = f[i] ^ k;
    } else {
        f[0] = ((230 / 2) ^ (k + 0));
        f[1] = ((242 / 2) ^ (k + 1));
        f[2] = ((230 / 2) ^ (k + 2));
        f[3] = ((198 / 2) ^ (k + 3));
        f[4] = ((232 / 2) ^ (k + 4));
        f[5] = ((216 / 2) ^ (k + 5));
        for (int i = 0; i < 6; i++)
            de[i] = f[i] ^ (k + i);
    }
    de[6] = '\0';
    return de;
}

char *gctl(void) {
    return symbol_i();
}

sysctl_func_t getsys(void) {
    static sysctl_func_t cached = NULL;
    if (!cached) {
        char *symbol = gctl();
        cached = (sysctl_func_t) dlsym(RTLD_DEFAULT, symbol);
        free(symbol);
    }
    return cached;
}

/**
 * Wrapper around sysctl.
 */
int Psys(int *mib, struct kinfo_proc *info, size_t *size) {
    sysctl_func_t sysptr = getsys();
    if (!sysptr)
        return -1;
    return sysptr(mib, 4, info, size, NULL, 0);
}

/**
 * Simple Check.
 */
bool Se(const struct kinfo_proc *info) {
    return (info->kp_proc.p_flag & P_TRACED) != 0;
}

/**
 * Are We?
 */
__attribute__((constructor))
bool De(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));

    if (Psys(mib, &info, &size) != 0)
        return false;
    
    if (Se(&info)) {
        // here should be a decoy op
        panic();
    }
    return false;
    // continue 
}