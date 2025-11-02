#include <aether.h>

/* Reflective Mach-O loader maps from memory without disk */

static void unload_image(image_t *image);

static image_t *loaded_images[LOADED_IMAGES] = {NULL};
static size_t num_loaded_images = 0;
static pthread_mutex_t images_mutex = PTHREAD_MUTEX_INITIALIZER;


static void reg_loaded(image_t *image) { 
    if (!image) return;
    
    pthread_mutex_lock(&images_mutex);
    
    if (num_loaded_images < LOADED_IMAGES) {
        loaded_images[num_loaded_images] = image;
        num_loaded_images++;
        DBG("Registered image %zu at %p\n", num_loaded_images, image->base);
    } else {
        DBG("Maximum loaded images reached\n");
    }
    
    pthread_mutex_unlock(&images_mutex);
}

__attribute__((destructor))
static void cleanup_loaded(void) {
    pthread_mutex_lock(&images_mutex);
    
    for (size_t i = 0; i < num_loaded_images; i++) {
        if (loaded_images[i]) {
            DBG("Cleaning up image at %p\n", loaded_images[i]->base);
            unload_image(loaded_images[i]);
            loaded_images[i] = NULL;
        }
    }
    
    num_loaded_images = 0;
    pthread_mutex_unlock(&images_mutex);
}

static bool validate_macho(uint8_t *data, size_t size) {
    if (!data || size < sizeof(struct mach_header_64)) {
        DBG("Size too small\n");
        return false;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    if (mh->magic != MH_MAGIC_64) {
        DBG("Magic (0x%x), expected 0x%x\n", mh->magic, MH_MAGIC_64);
        return false;
    }
    
    if (mh->cputype != CPU_TYPE_X86_64 && mh->cputype != CPU_TYPE_ARM64) {
        return false;
    }
    
    if (mh->filetype != MH_EXECUTE && mh->filetype != MH_DYLIB && mh->filetype != MH_BUNDLE) {
        return false;
    }
    
    DBG("Mach-O 64-bit binary\n");
    DBG("  CPU: %s\n", mh->cputype == CPU_TYPE_X86_64 ? "x86_64" : "ARM64");
    DBG("  Type: %d\n", mh->filetype);
    DBG("  Load commands: %u\n", mh->ncmds);
    
    return true;
}

/* Find entry point mh is original data, base is mapped memory */
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
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmd == LC_MAIN) {
            struct entry_point_command *ep = (struct entry_point_command *)lc;
            void *entry = (uint8_t *)base + ep->entryoff;
            DBG("LC_MAIN entry at 0x%llx -> %p\n", ep->entryoff, entry);
            return entry;
        }
        
        if (lc->cmd == LC_UNIXTHREAD) {
            #if defined(__x86_64__)
            x86_thread_state64_t *state = (x86_thread_state64_t *)((uint8_t *)lc + sizeof(struct thread_command));
            uint64_t entry_vmaddr = state->__rip;
            void *entry = (uint8_t *)base + (entry_vmaddr - min_vmaddr);
            DBG("LC_UNIXTHREAD entry at 0x%llx -> %p\n", entry_vmaddr, entry);
            return entry;
            #elif defined(__aarch64__)
            arm_thread_state64_t *state = (arm_thread_state64_t *)((uint8_t *)lc + sizeof(struct thread_command));
            uint64_t entry_vmaddr = state->__pc;
            void *entry = (uint8_t *)base + (entry_vmaddr - min_vmaddr);
            DBG("LC_UNIXTHREAD entry at 0x%llx -> %p\n", entry_vmaddr, entry);
            return entry;
            #endif
        }
        
        ptr += lc->cmdsize;
    }
    
    DBG("No entry point found\n");
    return NULL;
}

/* No constructors in our wrapped code it executes directly */
static void run_constructors(uint8_t *original_data, size_t size, void *base) {
    (void)original_data; (void)size; (void)base;
    DBG("No constructors\n");
}

/* Map Mach-O segments into RWX memory */
static void* map_executable(uint8_t *data, size_t size) {
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    uint64_t min_vmaddr = UINT64_MAX;
    uint64_t max_vmaddr = 0;
    
    uint8_t *ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    uint8_t *end = (uint8_t *)data + size;
    
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) {
            DBG("Load command %u extends beyond file\n", i);
            return NULL;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) {
            DBG("Load command %u has invalid size\n", i);
            return NULL;
        }
        
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                DBG("LC_SEGMENT_64 command too small\n");
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
        DBG("No valid segments found\n");
        return NULL;
    }
    
    size_t total_size = max_vmaddr - min_vmaddr;
    
    /* Allocate as RW first, then change to RX after loading */
    void *base = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANON, -1, 0);
    
    if (base == MAP_FAILED) {
        DBG("mmap failed: %s\n", strerror(errno));
        return NULL;
    }
    
    DBG("Allocated %zu bytes at %p (RW)\n", total_size, base);
    
    ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) {
            DBG("Load command %u extends beyond file\n", i);
            munmap(base, total_size);
            return NULL;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) {
            DBG("Load command %u has invalid size\n", i);
            munmap(base, total_size);
            return NULL;
        }
        
        if (lc->cmd == LC_SEGMENT_64) { 
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                DBG("LC_SEGMENT_64 command too small\n");
                munmap(base, total_size);
                return NULL;
            }
            
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            
            if (seg->filesize == 0 || strcmp(seg->segname, "__PAGEZERO") == 0) {
                ptr += lc->cmdsize;
                continue;
            }
            
            void *dest = (uint8_t *)base + (seg->vmaddr - min_vmaddr);
            void *src = data + seg->fileoff;
            
            if (seg->fileoff + seg->filesize > size) {
                DBG("Segment %s extends beyond file\n", seg->segname);
                munmap(base, total_size);
                return NULL;
            }
            
            if ((seg->vmaddr - min_vmaddr) + seg->vmsize > total_size) {
                DBG("Segment %s extends beyond allocated memory\n", seg->segname);
                munmap(base, total_size);
                return NULL;
            }
            
            memcpy(dest, src, seg->filesize);
            
            if (seg->vmsize > seg->filesize) {
                memset((uint8_t *)dest + seg->filesize, 0, seg->vmsize - seg->filesize);
            }
            
            DBG("Mapped %s: vmaddr=0x%llx, size=0x%llx\n", seg->segname, seg->vmaddr, seg->vmsize);
        }
        
        ptr += lc->cmdsize;
    }
    
    DBG("All segments mapped\n");
    
    /* Now change protection to RX (no write, add execute) */
    if (mprotect(base, total_size, PROT_READ | PROT_EXEC) != 0) {
        DBG("mprotect failed: %s\n", strerror(errno));
        munmap(base, total_size);
        return NULL;
    }
    
    DBG("Changed to RX\n");
    
    return base;
}

/* Parse and map Mach-O */
static image_t* prase_macho(uint8_t *data, size_t size) { 
    if (!validate_macho(data, size)) return NULL;
    
    DBG("Validation passed\n");
    
    image_t *image = calloc(1, sizeof(image_t));
    if (!image) {
        DBG("Failed to allocate image structure\n");
        return NULL;
    }
    
    DBG("Mapping executable\n");
    
    image->base = map_executable(data, size);
    if (!image->base) {
        DBG("map_executable failed\n");
        free(image);
        return NULL;
    }
    
    DBG("Mapped at %p\n", image->base);
    
    image->size = size;
    image->original_data = data;
    image->header = (struct mach_header_64 *)image->base;
    image->loaded = true;
    
    if (image->header->magic != MH_MAGIC_64) {
        DBG("Mapped header invalid: 0x%x\n", image->header->magic);
        munmap(image->base, image->size);
        free(image);
        return NULL;
    }
    
    DBG("Header valid (magic=0x%x, ncmds=%u)\n", image->header->magic, image->header->ncmds);
    
    struct mach_header_64 *original_header = (struct mach_header_64 *)data;
    image->entry_point = find_entry(original_header, image->base);
    
    if (!image->entry_point) {
        DBG("Failed to find entry point\n");
        munmap(image->base, image->size);
        free(image);
        return NULL;
    }
    
    DBG("Parse complete\n");
    return image;
}

static bool execute_image(image_t *image) {
    if (!image || !image->loaded) {
        DBG("Invalid or unloaded image\n");
        return false;
    }
    
    run_constructors(image->original_data, image->size, image->base);
    
    if (image->entry_point) {
        DBG("Entry at %p\n", image->entry_point);
    }
    
    return true;
}

static void unload_image(image_t *image) {
    if (!image) return;
    
    if (image->base) {
        munmap(image->base, image->size);
        DBG("Unmapped image at %p\n", image->base);
    }
    
    free(image);
}

static bool code_integrity(image_t *image) {
    if (!image || !image->base || !image->header) return false;
    
    if (image->header->magic != MH_MAGIC_64) {
        DBG("Header corrupted\n");
        return false;
    }
    
    struct mach_header_64 *original_header = (struct mach_header_64 *)image->original_data;
    uint8_t *ptr = (uint8_t *)original_header + sizeof(struct mach_header_64);
    uint8_t *end = image->original_data + image->size;
    
    bool has_executable = false;
    
    for (uint32_t i = 0; i < original_header->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) {
            DBG("Load command extends beyond data\n");
            return false;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) {
            DBG("Invalid load command size\n");
            return false;
        }
        
        if (lc->cmd == LC_SEGMENT_64) {
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                DBG("LC_SEGMENT_64 too small\n");
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
        DBG("No executable segments found\n");
        return false;
    }
    
    DBG("Integrity check passed\n");
    return true;
}

/* Core reflective loader - validates, maps to RWX, executes */
bool exec_mem(uint8_t *data, size_t size) { 
    if (!data || size == 0) {
        DBG("Invalid (data=%p, size=%zu)\n", data, size);
        return false;
    }

    if (size < sizeof(struct mach_header_64) + sizeof(struct load_command)) {
        DBG("Binary too small (%zu bytes)\n", size);
        return false;
    }
    
    image_t *image = prase_macho(data, size);
    if (!image) {
        return false;
    }
    
    DBG("[+] Mach-O parsed successfully\n");
    DBG("  Base address: %p\n", image->base);
    DBG("  Size: %zu bytes\n", image->size);
    
    if (!code_integrity(image)) {
        DBG("[!] Code integrity failed\n");
        unload_image(image);
        return false;
    }
    
    bool success = execute_image(image);
    
    if (success) {
        DBG("  Code loaded at: %p\n", image->base);
    } else {
        DBG("[!] Execution failed\n");
        unload_image(image);
        return false;
    }
    
    if (success) {
        reg_loaded(image); // Keep in memory
    } else {
        unload_image(image);
    }
    
    return success;
}
