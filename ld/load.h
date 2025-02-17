#ifndef AETHER_INMEM_H
#define AETHER_INMEM_H

#include "macho.h"
#include "link.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    void *base_addr;
    void *rw_addr;      /* RW mapping */
    size_t size;
    uint64_t entry_offset;
    bool dual_mapped;
} inmem_binary_t;

/* Load integrated code into memory */
inmem_binary_t *inmem_load(integrated_code_t *ic, macho_file_t *mf);

/* Execute loaded binary in isolated thread */
int inmem_execute(inmem_binary_t *ib);
void inmem_free(inmem_binary_t *ib);
inmem_binary_t *aether_mutate_and_load(uint8_t *binary, size_t size, uint32_t seed, unsigned intensity);

#endif
