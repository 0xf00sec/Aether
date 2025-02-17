#include "load.h"
#include "xfrm.h"
#include <mach/mach.h>
#include <mach/vm_map.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

inmem_binary_t *inmem_load(integrated_code_t *ic, macho_file_t *mf) {
    if (!ic || !mf) return NULL;
    
    inmem_binary_t *ib = calloc(1, sizeof(inmem_binary_t));
    if (!ib) return NULL;
    
    uint64_t min_addr = UINT64_MAX, max_addr = 0;
    for (int i = 0; i < mf->num_segments; i++) {
        if (mf->segments[i].vmsize == 0) continue;
        if (mf->segments[i].vmaddr < min_addr) min_addr = mf->segments[i].vmaddr;
        if (mf->segments[i].vmaddr + mf->segments[i].vmsize > max_addr)
            max_addr = mf->segments[i].vmaddr + mf->segments[i].vmsize;
    }
    
    if (min_addr == UINT64_MAX) {
        ib->size = (ic->size + 0xFFF) & ~0xFFF;
    } else {
        ib->size = ((max_addr - min_addr) + 0xFFF) & ~0xFFF;
    }
    
    /* Dual-mapping */
    vm_address_t rw_addr = 0, rx_addr = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &rw_addr, ib->size, VM_FLAGS_ANYWHERE);
    
    if (kr != KERN_SUCCESS) {
        free(ib);
        return NULL;
    }
    
    vm_protect(mach_task_self(), rw_addr, ib->size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    
    /* try vm_remap */
    vm_prot_t cur, max;
    kr = vm_remap(mach_task_self(), &rx_addr, ib->size, 0,
                  VM_FLAGS_ANYWHERE | VM_FLAGS_RETURN_DATA_ADDR,
                  mach_task_self(), rw_addr, FALSE, &cur, &max, VM_INHERIT_NONE);
    
    if (kr == KERN_SUCCESS) {
        vm_protect(mach_task_self(), rx_addr, ib->size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
        
        /* Copy all */
        for (int i = 0; i < mf->num_segments; i++) {
            if (mf->segments[i].filesize == 0) continue;
            uint64_t offset = mf->segments[i].vmaddr - min_addr;
            if (offset + mf->segments[i].filesize <= ib->size) {
                /* For __TEXT segment, use integrated code */
                if (mf->text_segment && mf->segments[i].vmaddr == mf->text_segment->vmaddr) {
                    memcpy((uint8_t*)rw_addr + offset, ic->code, ic->size);
                } else {
                    memcpy((uint8_t*)rw_addr + offset, 
                           mf->data + mf->segments[i].fileoff, 
                           mf->segments[i].filesize);
                }
            }
        }
        
        ib->base_addr = (void*)rx_addr;
        ib->rw_addr = (void*)rw_addr;
        ib->dual_mapped = true;
        ib->entry_offset = mf->entry_point;
        return ib;
    }
    
    /* single mapping */
    for (int i = 0; i < mf->num_segments; i++) {
        if (mf->segments[i].filesize == 0) continue;
        uint64_t offset = mf->segments[i].vmaddr - min_addr;
        if (offset + mf->segments[i].filesize <= ib->size) {
            if (mf->text_segment && mf->segments[i].vmaddr == mf->text_segment->vmaddr) {
                memcpy((uint8_t*)rw_addr + offset, ic->code, ic->size);
            } else {
                memcpy((uint8_t*)rw_addr + offset,
                       mf->data + mf->segments[i].fileoff,
                       mf->segments[i].filesize);
            }
        }
    }
    
    vm_protect(mach_task_self(), rw_addr, ib->size, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    ib->base_addr = (void*)rw_addr;
    ib->rw_addr = NULL;
    ib->dual_mapped = false;
    ib->entry_offset = mf->entry_point;
    return ib;
}

static void *exec_thread(void *arg) {
    inmem_binary_t *ib = (inmem_binary_t *)arg;
    
    typedef int (*entry_fn_t)(void);
    entry_fn_t entry = (entry_fn_t)((uint8_t*)ib->base_addr + ib->entry_offset);
    
    int result = entry();
    return (void*)(intptr_t)result;
}

int inmem_execute(inmem_binary_t *ib) {
    if (!ib || !ib->base_addr) return -1;
    
    pthread_t thread;
    void *ret_val;
    
    if (pthread_create(&thread, NULL, exec_thread, ib) != 0)
        return -1;
    
    pthread_join(thread, &ret_val);
    return (int)(intptr_t)ret_val;
}

void inmem_free(inmem_binary_t *ib) {
    if (!ib) return;
    
    if (ib->dual_mapped) {
        if (ib->rw_addr)
            vm_deallocate(mach_task_self(), (vm_address_t)ib->rw_addr, ib->size);
        if (ib->base_addr)
            vm_deallocate(mach_task_self(), (vm_address_t)ib->base_addr, ib->size);
    } else {
        if (ib->base_addr)
            vm_deallocate(mach_task_self(), (vm_address_t)ib->base_addr, ib->size);
    }
    
    free(ib);
}

/* Full pipeline */
inmem_binary_t *aether_mutate_and_load(uint8_t *binary, size_t size, uint32_t seed_unused, unsigned intensity) {
    /* Parse */
    macho_file_t *mf = macho_parse(binary, size);
    if (!mf) return NULL;
    
    uint64_t protected[2] = {0, 2048};
    insertion_map_t *map = macho_find_insertion_points(mf, protected, 2);
    if (!map) { macho_free(mf); return NULL; }
    
    int engine_size = 100 + intensity * 20;
    uint32_t *engine = calloc(engine_size, sizeof(uint32_t));
    if (!engine) { insertion_map_free(map); macho_free(mf); return NULL; }
    
    mutate_ctx_t ctx = {0};
    aether_rng_t rng;
    aether_rng_init(&rng);
    ctx.rng = &rng;
    for (int i = 0; i < engine_size; i++)
        engine[i] = 0xD503201F; /* nop */
    
    /* Weave */
    integrated_code_t *ic = macho_weave_code(mf, map, engine, engine_size, aether_rand(&rng));
    free(engine);
    insertion_map_free(map);
    
    if (!ic) { macho_free(mf); return NULL; }
    macho_fixup_branches(ic);
    
    /* Load into memory */
    inmem_binary_t *ib = inmem_load(ic, mf);
    
    integrated_code_free(ic);
    macho_free(mf);
    
    return ib;
}
