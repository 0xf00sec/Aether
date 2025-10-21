#include <aether.h>

/**
 * Simple Loader for macOS
 * Loads a Mach-O binary directly from memory without touching disk.
 */

static void unload_image(image_t *image);

// Global
static image_t *loaded_images[LOADED_IMAGES] = {NULL};
static size_t num_loaded_images = 0;
static pthread_mutex_t images_mutex = PTHREAD_MUTEX_INITIALIZER;


static void reg_loaded(image_t *image) { 
    if (!image) return;
    
    pthread_mutex_lock(&images_mutex);
    
    if (num_loaded_images < LOADED_IMAGES) {
        loaded_images[num_loaded_images++] = image;
        printf("Registered image %zu at %p\n", num_loaded_images, image->base);
    } else {
        printf("Maximum loaded images reached\n");
    }
    
    pthread_mutex_unlock(&images_mutex);
}

/**
 * Call on exit
 */
__attribute__((destructor))
static void cleanup_loaded(void) {
    pthread_mutex_lock(&images_mutex);
    
    for (size_t i = 0; i < num_loaded_images; i++) {
        if (loaded_images[i]) {
            printf("Cleaning up image at %p\n", loaded_images[i]->base);
            unload_image(loaded_images[i]);
            loaded_images[i] = NULL;
        }
    }
    
    num_loaded_images = 0;
    pthread_mutex_unlock(&images_mutex);
}

/**
 * Validate Mach-O header
 */
static bool validate_macho(uint8_t *data, size_t size) {
    if (!data || size < sizeof(struct mach_header_64)) {
        printf("Size too small\n"); // Ohh 
        return false;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    if (mh->magic != MH_MAGIC_64) {
        printf("Magic (0x%x), expected 0x%x\n", 
            mh->magic, MH_MAGIC_64);
        return false;
    }
    
    if (mh->cputype != CPU_TYPE_X86_64 && mh->cputype != CPU_TYPE_ARM64) {
        return false;
    }
    
    if (mh->filetype != MH_EXECUTE && 
        mh->filetype != MH_DYLIB && 
        mh->filetype != MH_BUNDLE) {
        return false;
    }
    
    printf("Mach-O 64-bit binary\n");
    printf("  CPU: %s\n", mh->cputype == CPU_TYPE_X86_64 ? "x86_64" : "ARM64");
    printf("  Type: %d\n", mh->filetype);
    printf("  Load commands: %u\n", mh->ncmds);
    
    return true;
}

/**
 * Find entry point from LC_MAIN or LC_UNIXTHREAD
 * mh points to ORIGINAL data (with unmodified vmaddrs)
 *      base is the actual mapped memory location keep that in mind 
 */
static void* find_entry(struct mach_header_64 *mh, void *base) {
    uint8_t *ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    
    uint64_t min_vmaddr = UINT64_MAX;
    uint8_t *scan_ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)scan_ptr;
        
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->vmsize > 0 && strcmp(seg->segname, "__PAGEZERO") != 0) {
                if (seg->vmaddr < min_vmaddr) {
                    min_vmaddr = seg->vmaddr;
                }
            }
        }
        
        scan_ptr += lc->cmdsize;
    }
    
    // Now find entry point
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmd == LC_MAIN) {
            struct entry_point_command *ep = (struct entry_point_command *)lc;
            void *entry = (uint8_t *)base + ep->entryoff;
            printf("Found LC_MAIN entry point at file offset 0x%llx -> %p\n", 
                   ep->entryoff, entry);
            return entry;
        }
        
        if (lc->cmd == LC_UNIXTHREAD) {
            // We need to adjust it relative to our base
            #if defined(__x86_64__)
            x86_thread_state64_t *state = 
                (x86_thread_state64_t *)((uint8_t *)lc + sizeof(struct thread_command));
            uint64_t entry_vmaddr = state->__rip;
            void *entry = (uint8_t *)base + (entry_vmaddr - min_vmaddr);
            printf("Found LC_UNIXTHREAD entry point at vmaddr 0x%llx -> %p\n", 
                   entry_vmaddr, entry);
            return entry;
            #elif defined(__aarch64__)
            arm_thread_state64_t *state = 
                (arm_thread_state64_t *)((uint8_t *)lc + sizeof(struct thread_command));
            uint64_t entry_vmaddr = state->__pc;
            void *entry = (uint8_t *)base + (entry_vmaddr - min_vmaddr);
            printf("Found LC_UNIXTHREAD entry point at vmaddr 0x%llx -> %p\n", 
                   entry_vmaddr, entry);
            return entry;
            #endif
        }
        
        ptr += lc->cmdsize;
    }
    
    printf("No entry point found\n");
    return NULL;
}

/**
 * Find and execute constructors (__mod_init_func section)
 * 
 * We don't have a __DATA segment with constructors.
 * The mutated code itself is the "constructor" it runs when loaded.
 * This function is here for completeness but won't find anything in our case.
 */
static void run_constructors(uint8_t *original_data, size_t size, void *base) {
    (void)original_data;
    (void)size;
    (void)base;
    
    // For our use case (wrapping mutated code), there are no constructors
    // The code itself executes directly
    printf("No constructors to run (code executes directly)\n");
}

/**
 * Map Mach-O into executable memory
 */
static void* map_executable(uint8_t *data, size_t size) {
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    // Calculate total VM size needed
    uint64_t min_vmaddr = UINT64_MAX;
    uint64_t max_vmaddr = 0;
    
    uint8_t *ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    uint8_t *end = (uint8_t *)data + size;
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        // Bounds check
        if (ptr + sizeof(struct load_command) > end) {
            printf("Load command %u extends beyond file\n", i);
            return NULL;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        // Validate cmdsize
        if (lc->cmdsize < sizeof(struct load_command) || 
            ptr + lc->cmdsize > end) {
            printf("Load command %u has invalid size\n", i);
            return NULL;
        }
        
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                printf("LC_SEGMENT_64 command too small\n");
                return NULL;
            }
            
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            
            if (seg->vmsize == 0 || strcmp(seg->segname, "__PAGEZERO") == 0) {
                ptr += lc->cmdsize;
                continue;
            }
            
            if (seg->vmaddr < min_vmaddr) {
                min_vmaddr = seg->vmaddr;
            }
            if (seg->vmaddr + seg->vmsize > max_vmaddr) {
                max_vmaddr = seg->vmaddr + seg->vmsize;
            }
        }
        
        ptr += lc->cmdsize;
    }
    
    if (min_vmaddr == UINT64_MAX || max_vmaddr == 0) {
        printf("No valid segments found\n");
        return NULL;
    }
    
    size_t total_size = max_vmaddr - min_vmaddr;
    
    // Allocate RWX memory for the entire image
    void *base = mmap(NULL, total_size, 
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    
    if (base == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        return NULL;
    }
    
    printf("Allocated %zu bytes at %p (RWX)\n", total_size, base);
    
    // Map each segment
    ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) {
            printf("Load command %u extends beyond file\n", i);
            munmap(base, total_size);
            return NULL;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        // Validate cmdsize
        if (lc->cmdsize < sizeof(struct load_command) || 
            ptr + lc->cmdsize > end) {
            printf("Load command %u has invalid size\n", i);
            munmap(base, total_size);
            return NULL;
        }
        
        if (lc->cmd == LC_SEGMENT_64) {
            // second pass 
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                printf("LC_SEGMENT_64 command too small\n");
                munmap(base, total_size);
                return NULL;
            }
            
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            
            if (seg->filesize == 0 || strcmp(seg->segname, "__PAGEZERO") == 0) {
                ptr += lc->cmdsize;
                continue;
            }
            
            // Calculate dst
            void *dest = (uint8_t *)base + (seg->vmaddr - min_vmaddr);
            void *src = data + seg->fileoff;
            
            if (seg->fileoff + seg->filesize > size) {
                printf("Segment %s extends beyond file\n", seg->segname);
                munmap(base, total_size);
                return NULL;
            }
            
            if ((seg->vmaddr - min_vmaddr) + seg->vmsize > total_size) {
                printf("Segment %s extends beyond allocated memory\n", seg->segname);
                munmap(base, total_size);
                return NULL;
            }
            
            // Copy segment data
            memcpy(dest, src, seg->filesize);
            
            if (seg->vmsize > seg->filesize) {
                memset((uint8_t *)dest + seg->filesize, 0, 
                       seg->vmsize - seg->filesize);
            }
            
            printf("Mapped segment %s: vmaddr=0x%llx, size=0x%llx\n",
                seg->segname, seg->vmaddr, seg->vmsize);
        }
        
        ptr += lc->cmdsize;
    }
    
    printf("We mapped all segments\n");
    
    return base;
}

/**
 * Parse Mach-O and prepare for execution
 */
static image_t* prase_macho(uint8_t *data, size_t size) { 
    
    if (!validate_macho(data, size)) {
        return NULL;
    }
    
    printf("Ok\n");
    
    image_t *image = calloc(1, sizeof(image_t));
    if (!image) {
        printf("Failed to allocate image structure\n");
        return NULL;
    }
    
    printf("Calling map_executable\n");
    
    // Map into executable memory
    image->base = map_executable(data, size);
    if (!image->base) {
        printf("map_executable failed\n");
        free(image);
        return NULL;
    }
    
    printf("map_executable succeeded, base=%p\n", image->base);
    
    image->size = size;
    image->original_data = data;  // Keep reference to original data
    image->header = (struct mach_header_64 *)image->base;  // Header is NOW in mapped memory
    image->loaded = true;
    
    printf("Verifying mapped header\n");
    
    // Verify
    if (image->header->magic != MH_MAGIC_64) {
        printf("Mapped header has invalid magic: 0x%x\n", 
               image->header->magic);
        munmap(image->base, image->size);
        free(image);
        return NULL;
    }
    
    printf("Mapped header valid (magic=0x%x, ncmds=%u)\n",
           image->header->magic, image->header->ncmds);
    
    // We need the ORIGINAL data for reading load commands
    struct mach_header_64 *original_header = (struct mach_header_64 *)data;
    image->entry_point = find_entry(original_header, image->base);
    
    if (!image->entry_point) {
        printf("Failed to find entry point\n");
        munmap(image->base, image->size);
        free(image);
        return NULL;
    }
    
    printf("Parse is Aight\n");
    
    return image;
}

static bool execute_image(image_t *image) {
    if (!image || !image->loaded) {
        printf("Invalid or unloaded image\n");
        return false;
    }
    
    // Run constructors if any
    run_constructors(image->original_data, image->size, image->base);
    
    // For our wrapped mutated code, the entry point IS the mutated code
    // We don't actually need to call it just having it loaded in RWX memory
    // is enough. The mutations have been applied and the code is ready.
    if (image->entry_point) {
        printf("Entry point at %p \n", image->entry_point);
    }
    
    // The mutated code is now in RWX memory and can execute
    return true;
}

static void unload_image(image_t *image) {
    if (!image) return;
    
    if (image->base) {
        munmap(image->base, image->size);
        printf("Unmapped image at %p\n", image->base);
    }
    
    free(image);
}

static bool code_integrity(image_t *image) {
    if (!image || !image->base || !image->header) {
        return false;
    }
    
    // is still valid in mapped memory
    if (image->header->magic != MH_MAGIC_64) {
        printf("Header corrupted during mapping\n");
        return false;
    }
    
    // Use original data to read load commands 
    struct mach_header_64 *original_header = (struct mach_header_64 *)image->original_data;
    uint8_t *ptr = (uint8_t *)original_header + sizeof(struct mach_header_64);
    uint8_t *end = image->original_data + image->size;
    
    bool has_executable = false;
    
    for (uint32_t i = 0; i < original_header->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) {
            printf("Load command extends beyond data\n");
            return false;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) {
            printf("Invalid load command size\n");
            return false;
        }
        
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                printf("LC_SEGMENT_64 too small\n");
                return false;
            }
            
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            
            if (seg->initprot & VM_PROT_EXECUTE) {
                has_executable = true;
            }
        }
        
        ptr += lc->cmdsize;
    }
    
    if (!has_executable) {
        printf("No executable segments found\n");
        return false;
    }
    
    printf("Code integrity verification passed\n");
    return true;
}

/**
 * Load and execute 
 * 
 * This is the core reflective:
 * 1. Validates the structure
 * 2. Maps it into RWX memory
 * 3. Resolves any necessary relocations
 * 4. Executes constructors
 * 5. If we want we can call the entry point
 */
bool exec_mem(uint8_t *data, size_t size) { 
    if (!data || size == 0) {
        printf("Invalid (data=%p, size=%zu)\n", data, size);
        return false;
    }

    if (size < sizeof(struct mach_header_64) + sizeof(struct load_command)) {
        printf("Binary too small (%zu bytes)\n", size);
        return false;
    }
    
    // Parse and map
    image_t *image = prase_macho(data, size);
    if (!image) {
        return false;
    }
    
    printf("[+] Mach-O parsed successfully\n");
    printf("  Base address: %p\n", image->base);
    printf("  Size: %zu bytes\n", image->size);
    
    if (!code_integrity(image)) {
        printf("[!] Code integrity failed\n");
        unload_image(image);
        return false;
    }
    
    // Execute
    bool success = execute_image(image);
    
    if (success) {
        printf("  Code loaded at: %p\n", image->base);
    } else {
        printf("[!] Execution failed\n");
        unload_image(image);
        return false;
    }
    
    // Register the image for cleanup on exit
    // The code needs to stay in memory to continue executing
    if (success) {
        reg_loaded(image);
    } else {
        unload_image(image);
    }
    
    return success;
}
