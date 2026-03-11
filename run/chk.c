#include "chk.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dlfcn.h>
#include <stdio.h>
#include <mach-o/dyld.h>

static int call_sysctl(int *mib, u_int cnt, void *old, size_t *oldsz) {
    typedef int (*sysctl_fn)(int *, u_int, void *, size_t *, void *, size_t);
    char sym[] = {0x73^0x20, 0x79^0x20, 0x73^0x20, 0x63^0x20,
                  0x74^0x20, 0x6C^0x20, 0};
    for (int i = 0; sym[i]; i++) sym[i] ^= 0x20;
    sysctl_fn fn = (sysctl_fn)dlsym(RTLD_DEFAULT, sym);
    if (!fn) return -1;
    return fn(mib, cnt, old, oldsz, NULL, 0);
}

bool is_debugged(void) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};
    struct kinfo_proc info;
    size_t sz = sizeof(info);
    memset(&info, 0, sz);
    if (call_sysctl(mib, 4, &info, &sz) != 0) return false;
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

void deny_attach(void) {
    typedef int (*ptrace_fn)(int, pid_t, caddr_t, int);
    char sym[] = {0x70^0x11, 0x74^0x11, 0x72^0x11, 0x61^0x11,
                  0x63^0x11, 0x65^0x11, 0};
    for (int i = 0; sym[i]; i++) sym[i] ^= 0x11;
    ptrace_fn fn = (ptrace_fn)dlsym(RTLD_DEFAULT, sym);
    if (fn) fn(31, 0, 0, 0);
}

static void wipe_file(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) { unlink(path); return; }
    int fd = open(path, O_RDWR);
    if (fd < 0) { unlink(path); return; }
    uint8_t buf[4096];
    for (size_t off = 0; off < (size_t)st.st_size; off += sizeof(buf)) {
        size_t chunk = ((size_t)st.st_size - off > sizeof(buf)) ? sizeof(buf) : (size_t)st.st_size - off;
        arc4random_buf(buf, chunk);
        pwrite(fd, buf, chunk, off);
    }
    /* corrupt mach-o header */
    arc4random_buf(buf, sizeof(buf));
    pwrite(fd, buf, sizeof(buf), 0);
    fsync(fd);
    close(fd);
    unlink(path);
}

void self_destruct(void) {
    char path[1024];
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) != 0) return;

    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid == 0) {
        usleep(500000);
        if (kill(parent, 0) != 0) {
            wipe_file(path);
            /* remove parent dir */
            char rpath[1024];
            if (realpath(path, rpath)) {
                char *sl = strrchr(rpath, '/');
                if (sl) { *sl = '\0'; rmdir(rpath); }
            }
        }
        _exit(0);
    }
}


bool harden_check(void) {
    deny_attach();
    if (is_debugged()) return false;
    return true;
}
