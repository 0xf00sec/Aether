#ifndef AETHER_MACHO_H
#define AETHER_MACHO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

typedef struct {
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t nsects;
    struct section_64 *sections;
} macho_segment_t;

typedef struct {
    struct mach_header_64 *header;
    uint8_t *data;
    size_t size;
    
    macho_segment_t *segments;
    int num_segments;
    
    macho_segment_t *text_segment;  /* __TEXT segment */
    struct section_64 *text_section; /* __text section */
    
    uint64_t entry_point;
} macho_file_t;

/* Parse Mach-O from memory */
macho_file_t *macho_parse(uint8_t *data, size_t size);

/* Free parsed Mach-O */
void macho_free(macho_file_t *mf);

/* Get __TEXT segment code */
uint8_t *macho_get_text_code(macho_file_t *mf, size_t *out_size);

/* Code integration: identify cool insertion points */
typedef struct {
    int offset;      /* Offset in instructions */
    int priority;    /* Higher = better insertion point */
} insertion_point_t;

typedef struct {
    insertion_point_t *points;
    int num_points;
    int capacity;
} insertion_map_t;

/* Find cool insertion points in code using CFG analysis */
insertion_map_t *macho_find_insertion_points(macho_file_t *mf, uint64_t *protected, int num_protected);
void insertion_map_free(insertion_map_t *map);

typedef struct {
    uint32_t *code;      
    size_t size;         
    uint64_t *addr_map;  
    int map_size;
} integrated_code_t;

/* Weave engine code into host at insertion points */
integrated_code_t *macho_weave_code(macho_file_t *mf, insertion_map_t *map, 
                                     uint32_t *engine_code, int engine_size, uint32_t seed);
void integrated_code_free(integrated_code_t *ic);
bool macho_fixup_branches(integrated_code_t *ic);
bool macho_rebuild(macho_file_t *mf, integrated_code_t *ic, const char *output_path);
bool macho_update_fixups(uint8_t *data, size_t size, int64_t delta);

#endif
