#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

static uint32_t hash_str(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        c = tolower(c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s [...]\n", argv[0]);
        return 1;
    }
    
    printf("// Generated hashes:\n");
    for (int i = 1; i < argc; i++) {
        char lower[256];
        size_t j;
        
        // Convert to lowercase and strip .app
        for (j = 0; j < sizeof(lower) - 1 && argv[i][j]; j++) {
            lower[j] = tolower(argv[i][j]);
        }
        lower[j] = '\0';
        
        char *dot = strstr(lower, ".app");
        if (dot) *dot = '\0';
        
        uint32_t hash = hash_str(lower);
        printf("0x%08x,  // %s\n", hash, lower);
    }
    
    return 0;
}
