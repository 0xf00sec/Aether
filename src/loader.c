#include <aether.h>

/* Reflective Mach-O loader maps from memory without disk */

static void unload_image(image_t *image);

static image_t *loaded_images[_IMGZ] = {NULL};
static size_t num_loaded_images = 0;
static pthread_mutex_t images_mutex = PTHREAD_MUTEX_INITIALIZER;


static void reg_loaded(image_t *image) { 
    if (!image) return;
    
    pthread_mutex_lock(&images_mutex);
    
    if (num_loaded_images < _IMGZ) {
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

/* Create dual-mapped memory region Returns RW address, stores RX address in rx_out */
void* alloc_dual(size_t size, void **rx_out) {
    if (!rx_out) return NULL;
    
    kern_return_t kr;
    mach_port_t task = mach_task_self();
    
    /* Allocate RW memory first */
    vm_address_t rw_addr = 0;
    kr = vm_allocate(task, &rw_addr, size, VM_FLAGS_ANYWHERE);
    
    if (kr != KERN_SUCCESS) {
        DBG("vm_allocate failed: %d\n", kr);
        return NULL;
    }
    
    /* Set to RW */
    kr = vm_protect(task, rw_addr, size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    if (kr != KERN_SUCCESS) {
        DBG("vm_protect (RW) failed: %d\n", kr);
        vm_deallocate(task, rw_addr, size);
        return NULL;
    }
    
    /* Create RX mapping of the same memory */
    vm_address_t rx_addr = 0;
    vm_prot_t cur_prot, max_prot;
    
    kr = vm_remap(task, &rx_addr, size, 0,
                  VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                  task, rw_addr, FALSE,
                  &cur_prot, &max_prot, VM_INHERIT_NONE);
    
    if (kr != KERN_SUCCESS) {
        DBG("vm_remap failed: %d, falling back to single mapping\n", kr);
        /* Fallback just use RW and hope for the best */
        *rx_out = (void*)rw_addr;
        return (void*)rw_addr;
    }
    
    /* Set RX mapping to read+execute */
    kr = vm_protect(task, rx_addr, size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    if (kr != KERN_SUCCESS) {
        DBG("vm_protect (RX) failed: %d\n", kr);
        vm_deallocate(task, rx_addr, size);
        vm_deallocate(task, rw_addr, size);
        return NULL;
    }
    
    DBG("Mapping: RW=%p, RX=%p, size=%zu\n", (void*)rw_addr, (void*)rx_addr, size);
    
    *rx_out = (void*)rx_addr;
    return (void*)rw_addr;
}

/* Free dual-mapped region */
void free_dual(void *rw_addr, void *rx_addr, size_t size) {
    mach_port_t task = mach_task_self();
    
    if (rw_addr && rw_addr != rx_addr) {
        vm_deallocate(task, (vm_address_t)rw_addr, size);
    }
    
    if (rx_addr) {
        vm_deallocate(task, (vm_address_t)rx_addr, size);
    }
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
#if defined(__x86_64__) || defined(_M_X64)
            x86_thread_state64_t *state = (x86_thread_state64_t *)((uint8_t *)lc + sizeof(struct thread_command));
            uint64_t entry_vmaddr = state->__rip;
#elif defined(__aarch64__) || defined(_M_ARM64)
            arm_thread_state64_t *state = (arm_thread_state64_t *)((uint8_t *)lc + sizeof(struct thread_command));
            uint64_t entry_vmaddr = state->__pc;
#endif
            void *entry = (uint8_t *)base + (entry_vmaddr - min_vmaddr);
            DBG("LC_UNIXTHREAD entry at 0x%llx -> %p\n", entry_vmaddr, entry);
            return entry;
        }
        
        ptr += lc->cmdsize;
    }
    
    DBG("No entry point found\n");
    return NULL;
}

/* Execute entry point in separate thread for isolation */
static void* entry_thread(void *arg) {
    image_t *image = (image_t *)arg;
    
    if (!image || !image->entry_point) {
        DBG("Invalid entry point\n");
        return NULL;
    }
    
    DBG("Executing entry at %p\n", image->entry_point);
    
    /* Cast to function pointer and execute */
    typedef int (*entry_fn)(int, char**, char**, char**);
    entry_fn entry = (entry_fn)image->entry_point;
    
    /* Execute with minimal environment */
    char *empty_argv[] = {NULL};
    char *empty_envp[] = {NULL};
    
    int result = entry(0, empty_argv, empty_envp, empty_argv);
    
    DBG("Entry returned: %d\n", result);
    
    image->entry_running = false;
    return (void*)(intptr_t)result;
}

extern void* alloc_dual(size_t size, void **rx_out);
extern void free_dual(void *rw_addr, void *rx_addr, size_t size);

/* This works around W^X by using file-backed memory or vm_remap */
static mapping_t* map_exec(uint8_t *data, size_t size) {
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
    
    mapping_t *mapping = calloc(1, sizeof(mapping_t));
    if (!mapping) {
        DBG("Failed to allocate mapping structure\n");
        return NULL;
    }
    
    mapping->size = total_size;
    mapping->is_dual = false;
    mapping->is_jit = false;
    
    /* Try dual mapping with vm_remap */
    void *rw = NULL, *rx = NULL;
    rw = alloc_dual(total_size, &rx);
    if (rw && rx && rw != rx) {
        DBG("Using vm_remap dual mapping (RW=%p, RX=%p)\n", rw, rx);
        mapping->rw_base = rw;
        mapping->rx_base = rx;
        mapping->is_dual = true;
        goto have_memory;
    }
    
    /* file-backed memory via shm_open, this has better chance of getting exec permission */
    int shm_fd = -1;
    char shm_name[64];
    DBG(shm_name, sizeof(shm_name), "/tmp.%d.%lx", getpid(), (unsigned long)time(NULL));
    
    shm_fd = shm_open(shm_name, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (shm_fd >= 0) {
        shm_unlink(shm_name);
        
        if (ftruncate(shm_fd, total_size) == 0) {
            void *mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                            MAP_SHARED, shm_fd, 0);
            
            if (mem != MAP_FAILED) {
                DBG("Using shm_open file-backed memory\n");
                mapping->rw_base = mem;
                mapping->rx_base = mem;
                mapping->is_dual = false;
                close(shm_fd);
                goto have_memory;
            }
        }
        close(shm_fd);
    }
    
    void *mem = mmap(NULL, total_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANON, -1, 0);
    
    if (mem == MAP_FAILED) {
        DBG("All allocation methods failed\n");
        free(mapping);
        return NULL;
    }
    
    mapping->rw_base = mem;
    mapping->rx_base = mem;
    mapping->is_dual = false;
    DBG("Allocated %zu bytes at %p (anonymous)\n", total_size, mem);

have_memory:
    
    /* Copy segments to RW mapping */
    ptr = (uint8_t *)mh + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) {
            DBG("Load command %u extends beyond file\n", i);
            goto cleanup_mapping;
        }
        
        struct load_command *lc = (struct load_command *)ptr;
        
        if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) {
            DBG("Load command %u has invalid size\n", i);
            goto cleanup_mapping;
        }
        
        if (lc->cmd == LC_SEGMENT_64) { 
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                DBG("LC_SEGMENT_64 command too small\n");
                goto cleanup_mapping;
            }
            
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            
            if (seg->filesize == 0 || strcmp(seg->segname, "__PAGEZERO") == 0) {
                ptr += lc->cmdsize;
                continue;
            }
            
            /* Write to RW mapping */
            void *dest = (uint8_t *)mapping->rw_base + (seg->vmaddr - min_vmaddr);
            void *src = data + seg->fileoff;
            
            if (seg->fileoff + seg->filesize > size) {
                DBG("Segment %s extends beyond file\n", seg->segname);
                goto cleanup_mapping;
            }
            
            if ((seg->vmaddr - min_vmaddr) + seg->vmsize > total_size) {
                DBG("Segment %s extends beyond allocated memory\n", seg->segname);
                goto cleanup_mapping;
            }
            
            memcpy(dest, src, seg->filesize);
            
            if (seg->vmsize > seg->filesize) {
                memset((uint8_t *)dest + seg->filesize, 0, seg->vmsize - seg->filesize);
            }
            
            DBG("Mapped %s: vmaddr=0x%llx, size=0x%llx to %p\n", 
                   seg->segname, seg->vmaddr, seg->vmsize, dest);
        }
        
        ptr += lc->cmdsize;
    }
    
    DBG("All segments mapped to RW region\n");
    
    /* If single mapping (not dual), try to make it executable 
            for dual mapping, RX is already set up correctly */
    if (!mapping->is_dual && !mapping->is_jit) {
        if (mprotect(mapping->rw_base, total_size, PROT_READ | PROT_EXEC) != 0) {
            DBG("mprotect to RX failed: %s\n", strerror(errno));
            
            /* Try alternative: remap as RX directly */
            void *new_base = mmap(mapping->rw_base, total_size, PROT_READ | PROT_EXEC,
                                  MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
            
            if (new_base == MAP_FAILED || new_base != mapping->rw_base) {
                DBG("Remap failed, execution may fail\n");
            } else {
                DBG("Remapped to RX successfully\n");
            }
        } else {
            DBG("Changed to RX via mprotect\n");
        }
        /* Update rx_base to point to the now-executable memory */
        mapping->rx_base = mapping->rw_base;
    }
    
    return mapping;

cleanup_mapping:
    if (mapping->is_dual) {
        if (mapping->rw_base) munmap(mapping->rw_base, total_size);
        if (mapping->rx_base) munmap(mapping->rx_base, total_size);
    } else {
        if (mapping->rw_base) munmap(mapping->rw_base, total_size);
    }
    free(mapping);
    return NULL;
}

/* Parse and map Mach-O */
static image_t* prase_macho(uint8_t *data, size_t size) { 
    if (!data || size < sizeof(struct mach_header_64)) {
        DBG("Size too small\n");
        return NULL;
    }
    
    struct mach_header_64 *mh = (struct mach_header_64 *)data;
    
    if (mh->magic != MH_MAGIC_64) {
        DBG("Magic (0x%x), expected 0x%x\n", mh->magic, MH_MAGIC_64);
        return NULL;
    }
    
    if (mh->cputype != CPU_TYPE_X86_64 && mh->cputype != CPU_TYPE_ARM64) {
        return NULL;
    }
    
    if (mh->filetype != MH_EXECUTE && mh->filetype != MH_DYLIB && mh->filetype != MH_BUNDLE) {
        return NULL;
    }
    
    DBG("Mach-O 64-bit binary\n");
    DBG("  CPU: %s\n", mh->cputype == CPU_TYPE_X86_64 ? "x86_64" : "ARM64");
    DBG("  Type: %d\n", mh->filetype);
    DBG("  Load commands: %u\n", mh->ncmds);
    
    DBG("Validation passed\n");
    
    image_t *image = calloc(1, sizeof(image_t));
    if (!image) {
        DBG("Failed to allocate image structure\n");
        return NULL;
    }
    
    DBG("Mapping executable\n");
    
    mapping_t *mapping = map_exec(data, size);
    if (!mapping) {
        DBG("map_exec failed\n");
        free(image);
        return NULL;
    }
    
    DBG("Mapped: RW=%p, RX=%p (dual=%d, jit=%d)\n", 
           mapping->rw_base, mapping->rx_base, mapping->is_dual, mapping->is_jit);
    
    /* We'll use RX for execution */
    image->base = mapping->rx_base;
    image->size = mapping->size;
    image->original_data = data;
    image->header = (struct mach_header_64 *)mapping->rx_base;
    image->loaded = true;
    
    /* Store mapping info for cleanup */
    image->rw_base = mapping->rw_base;
    image->is_dual_mapped = mapping->is_dual;
    image->is_jit = mapping->is_jit;
    free(mapping);  /* We've copied the info we need */
    
    if (image->header->magic != MH_MAGIC_64) {
        DBG("Mapped header invalid: 0x%x\n", image->header->magic);
        if (image->is_dual_mapped) {
            munmap(image->rw_base, image->size);
            munmap(image->base, image->size);
        } else {
            munmap(image->base, image->size);
        }
        free(image);
        return NULL;
    }
    
    DBG("Header valid (magic=0x%x, ncmds=%u)\n", image->header->magic, image->header->ncmds);    
    struct mach_header_64 *original_header = (struct mach_header_64 *)data;
    
    /* Find minimum vmaddr across all segments (excluding PAGEZERO) */
    uint64_t min_vmaddr = UINT64_MAX;
    uint8_t *ptr = (uint8_t *)original_header + sizeof(struct mach_header_64);
    uint8_t *end = (uint8_t *)data + size;
    
    for (uint32_t i = 0; i < original_header->ncmds; i++) {
        if (ptr + sizeof(struct load_command) > end) break;
        
        struct load_command *lc = (struct load_command *)ptr;
        if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) break;
        
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (seg->vmsize > 0 && strcmp(seg->segname, "__PAGEZERO") != 0) {
                if (seg->vmaddr < min_vmaddr) {
                    min_vmaddr = seg->vmaddr;
                }
            }
        }
        ptr += lc->cmdsize;
    }
    
    if (min_vmaddr == UINT64_MAX) {
        DBG("Failed to find minimum vmaddr\n");
        if (image->is_dual_mapped) {
            munmap(image->rw_base, image->size);
            munmap(image->base, image->size);
        } else {
            munmap(image->base, image->size);
        }
        free(image);
        return NULL;
    }
    
    /* Slide = where we actually loaded - where it was supposed to load 
            This is consistent across all segments */
    uint64_t actual_base = (uint64_t)image->base;
    image->slide = actual_base - min_vmaddr;
    image->min_vmaddr = min_vmaddr;
    
    DBG("Relocation base: original=0x%llx, actual=0x%llx, slide=0x%llx\n",
           min_vmaddr, actual_base, image->slide);
    
    /* Apply relocations to make code position-independent */
    uint8_t arch_type = ARCH_X86;
    
    /* Scan relocations from the RX mapping (where code will execute)
     but use the original base address for calculating targets */
    reloc_table_t *relocs = reloc_scan(image->original_data, size, min_vmaddr, arch_type);
    if (!relocs) {
        DBG(" Failed to create relocation table\n");
        if (image->is_dual_mapped) {
            munmap(image->rw_base, image->size);
            munmap(image->base, image->size);
        } else {
            munmap(image->base, image->size);
        }
        free(image);
        return NULL;
    }
    
    DBG("Found %zu relocations\n", relocs->count);
    
    /* Check if code is self-contained */
    bool self_contained = own_self(relocs, image->size);
        
    /* Apply relocations if there's a slide */
    if (image->slide != 0) {
        /* 
         * For dual-mapped memory, we need to:
         * Enable write on the RW mapping and apply relocations to RW mapping
         * Changes visible in RX mapping
         */
        uint8_t *target_code = NULL;
        if (image->is_dual_mapped) {
            target_code = (uint8_t*)image->rw_base;
            DBG("Applying to RW mapping at %p\n", target_code);
        } else {
            /* Need to make memory writable temporarily */
            if (mprotect(image->base, image->size, PROT_READ | PROT_WRITE) != 0) {
                DBG(" Failed to make memory writable for relocations\n");
                reloc_free(relocs);
                if (image->is_dual_mapped) {
                    munmap(image->rw_base, image->size);
                    munmap(image->base, image->size);
                } else {
                    munmap(image->base, image->size);
                }
                free(image);
                return NULL;
            }
            target_code = (uint8_t*)image->base;
            DBG("Applying to single mapping at %p (made writable)\n", target_code);
        }
        
        bool reloc_success = reloc_apply(target_code, image->size, relocs, 
                                        actual_base, arch_type);
        
        /* Restore protection if needed */
        if (!image->is_dual_mapped) {
            mprotect(image->base, image->size, PROT_READ | PROT_EXEC);
        }
        
        if (!reloc_success) {
            DBG(" Relocation application failed\n");
            reloc_free(relocs);
            if (image->is_dual_mapped) {
                munmap(image->rw_base, image->size);
                munmap(image->base, image->size);
            } else {
                munmap(image->base, image->size);
            }
            free(image);
            return NULL;
        }
        
        DBG("[+] Relocations done\n");
    } else {
        DBG("[!] No slide\n");
    }
    
    /* Keep relocation table for potential future use */
    image->reloc_table = relocs;
    
    /* Find entry point */
    image->entry_point = find_entry(original_header, image->base);
    
    if (!image->entry_point) {
        DBG("Failed to find entry point\n");
        if (image->is_dual_mapped) {
            munmap(image->rw_base, image->size);
            munmap(image->base, image->size);
        } else {
            munmap(image->base, image->size);
        }
        free(image);
        return NULL;
    }
    
    DBG("Entry point: %p\n", image->entry_point);
    DBG("\n Image Loading Complete \n");
    DBG("  RX Base: %p\n", image->base);
    if (image->is_dual_mapped) {
        DBG("  RW Base: %p\n", image->rw_base);
    }
    DBG("  Size: %zu bytes\n", image->size);
    DBG("  Entry: %p\n", image->entry_point);
    DBG("  Slide: 0x%llx\n", image->slide);
    
    return image;
}

static bool execute_image(image_t *image) {
    if (!image || !image->loaded) {
        DBG("Invalid or unloaded image\n");
        return false;
    }
    
    (void)image->original_data; (void)image->size; (void)image->base;
    
    if (!image->entry_point) {
        DBG("No entry point found\n");
        return false;
    }
    
    DBG("Launching entry at %p\n", image->entry_point);
    
    /* Create detached thread to execute the entry point */
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    
    image->entry_running = true;
    
    int ret = pthread_create(&image->entry_thread, &attr, entry_thread, image);
    pthread_attr_destroy(&attr);
    
    if (ret != 0) {
        DBG("pthread_create failed: %d\n", ret);
        image->entry_running = false;
        return false;
    }
    
    /* Give it a moment to start */
    usleep(10000);
    return true;
}

static void unload_image(image_t *image) {
    if (!image) return;
    
    /* Free relocation table */
    if (image->reloc_table) {
        reloc_free(image->reloc_table);
        image->reloc_table = NULL;
    }
    
    if (image->is_dual_mapped) {
        /* Unmap both RW and RX regions */
        if (image->rw_base) {
            munmap(image->rw_base, image->size);
            DBG("Unmapped RW region at %p\n", image->rw_base);
        }
        if (image->base) {
            munmap(image->base, image->size);
            DBG("Unmapped RX region at %p\n", image->base);
        }
    } else {
        /* Single mapping */
        if (image->base) {
            munmap(image->base, image->size);
            DBG("Unmapped image at %p\n", image->base);
        }
    }
    
    free(image);
}

/* Core reflective loader validates, maps to RWX, executes */
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
    
    {
        bool integrity_ok = true;
        
        if (!image || !image->base || !image->header) {
            integrity_ok = false;
        } else if (image->header->magic != MH_MAGIC_64) {
            DBG("Header corrupted\n");
            integrity_ok = false;
        } else {
            struct mach_header_64 *original_header = (struct mach_header_64 *)image->original_data;
            uint8_t *ptr = (uint8_t *)original_header + sizeof(struct mach_header_64);
            uint8_t *end = image->original_data + image->size;
            
            bool has_executable = false;
            
            for (uint32_t i = 0; i < original_header->ncmds; i++) {
                if (ptr + sizeof(struct load_command) > end) {
                    DBG("Load command extends beyond data\n");
                    integrity_ok = false;
                    break;
                }
                
                struct load_command *lc = (struct load_command *)ptr;
                
                if (lc->cmdsize < sizeof(struct load_command) || ptr + lc->cmdsize > end) {
                    DBG("Invalid load command size\n");
                    integrity_ok = false;
                    break;
                }
                
                if (lc->cmd == LC_SEGMENT_64) {
                    if (lc->cmdsize < sizeof(struct segment_command_64)) {
                        DBG("LC_SEGMENT_64 too small\n");
                        integrity_ok = false;
                        break;
                    }
                    
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    
                    if (seg->initprot & VM_PROT_EXECUTE) {
                        has_executable = true;
                    }
                }
                
                ptr += lc->cmdsize;
            }
            
            if (integrity_ok && !has_executable) {
                DBG("No executable segments found\n");
                integrity_ok = false;
            }
        }
        
        if (!integrity_ok) {
            DBG("[!] Code integrity failed\n");
            unload_image(image);
            return false;
        }
    }
    
    bool success = execute_image(image);
    
    if (success) {
        DBG("[+] Code loaded at: %p\n", image->base);
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
