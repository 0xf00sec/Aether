#include "bind.h"
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/dyld.h>
#include <string.h>

static void xdec(char *buf, const uint8_t *enc, size_t n) {
    for (size_t i = 0; i < n; i++) buf[i] = enc[i] ^ 0x2B; // key 
    buf[n] = '\0';
}

static CFStringRef get_ioplatform_key(const uint8_t *enc_key, size_t klen) {
    /* "IOPlatformExpertDevice" */
    static const uint8_t dev_enc[] = {0x62,0x64,0x7b,0x47,0x4a,0x5f,0x4d,0x44,0x59,0x46,0x6e,0x53,0x5b,0x4e,0x59,0x5f,0x6f,0x4e,0x5d,0x42,0x48,0x4e};
    char dev[23]; xdec(dev, dev_enc, 22);

#if defined(__MAC_12_0) && __MAC_OS_X_VERSION_MIN_REQUIRED >= __MAC_12_0
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault,
                                                       IOServiceMatching(dev));
#else
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                       IOServiceMatching(dev));
#endif
    memset(dev, 0, sizeof(dev));
    if (!service) return NULL;

    char key[32]; xdec(key, enc_key, klen);
    CFStringRef cfkey = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    memset(key, 0, sizeof(key));
    CFStringRef value = IORegistryEntryCreateCFProperty(service, cfkey, kCFAllocatorDefault, 0);
    CFRelease(cfkey);
    IOObjectRelease(service);
    return value;
}

void derive_env_key(uint8_t key[16], uint8_t iv[16]) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    /* "IOPlatformUUID" */
    static const uint8_t uuid_enc[] = {0x62,0x64,0x7b,0x47,0x4a,0x5f,0x4d,0x44,0x59,0x46,0x7e,0x7e,0x62,0x6f};
    CFStringRef uuid = get_ioplatform_key(uuid_enc, 14);
    if (uuid) {
        char buf[64];
        CFStringGetCString(uuid, buf, sizeof(buf), kCFStringEncodingUTF8);
        CC_SHA256_Update(&ctx, buf, strlen(buf));
        CFRelease(uuid);
    }

    /* "IOPlatformSerialNumber" */
    static const uint8_t ser_enc[] = {0x62,0x64,0x7b,0x47,0x4a,0x5f,0x4d,0x44,0x59,0x46,0x78,0x4e,0x59,0x42,0x4a,0x47,0x65,0x5e,0x46,0x49,0x4e,0x59};
    CFStringRef serial = get_ioplatform_key(ser_enc, 22);
    if (serial) {
        char buf[64];
        CFStringGetCString(serial, buf, sizeof(buf), kCFStringEncodingUTF8);
        CC_SHA256_Update(&ctx, buf, strlen(buf));
        CFRelease(serial);
    }

    uint8_t hash[32];
    CC_SHA256_Final(hash, &ctx);
    memcpy(key, hash, 16);
    memcpy(iv, hash + 16, 16);
}
