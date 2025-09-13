#include <wisp.h>

__attribute__((always_inline)) static inline void _once(void) {
    static bool seeded = false;
    if (!seeded) {
        srand((unsigned int)(time(NULL) ^ getpid()));
        seeded = true;
    }
}

__attribute__((always_inline)) static inline char *symbol_i(void) {
    _once();

    char *de = malloc(7);
    if (!de)
        exit(EXIT_FAILURE); // FANCY 

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

sysctl_fn getsys(void) {
    static sysctl_fn cached = NULL;
    if (!cached) {
        char *symbol = gctl();
        cached = (sysctl_fn) dlsym(RTLD_DEFAULT, symbol);
        free(symbol);
    }
    return cached;
}

int Psys(int *mib, struct kinfo_proc *info, size_t *size) {
    sysctl_fn sysptr = getsys();
    if (!sysptr)
        return -1;
    return sysptr(mib, 4, info, size, NULL, 0);
}

bool Se(const struct kinfo_proc *info) {
    return (info->kp_proc.p_flag & P_TRACED) != 0;
}

__attribute__((constructor)) bool De(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t size = sizeof(info);
    memset(&info, 0, sizeof(info));

    if (Psys(mib, &info, &size) != 0)
        return false;
    
    if (Se(&info)) {
        // faux or just:
        panic();
    }
    return false;
}
