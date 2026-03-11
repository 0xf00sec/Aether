#ifndef __CUSTOM_DLFCN__
#define __CUSTOM_DLFCN__

#include <dlfcn.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int custom_dlclose(void* __handle);
extern char* custom_dlerror(void);
extern void* custom_dlopen(const char* __path, int __mode);
extern void* custom_dlsym(void* __handle, const char* __symbol);
extern void* custom_dlopen_from_memory(void* mh, int len);

#ifdef __cplusplus
}
#endif

#endif // __CUSTOM_DLFCN__
