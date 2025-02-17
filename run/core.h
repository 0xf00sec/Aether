#ifndef AETHER_CORE_H
#define AETHER_CORE_H

#include <stddef.h>
#include <stdint.h>

int hunt_procs(void);
int payload_run(void);

#ifdef AETHER_TEST
void collect(void);
uint8_t *pack(size_t *out_sz);
size_t profile_host(char *buf, size_t sz);
uint8_t *seal(const uint8_t *data, size_t len, size_t *out_sz);
uint8_t *json_wrap(const uint8_t *data, size_t len, size_t *out_sz);
void free_files(void);
#endif

#endif
