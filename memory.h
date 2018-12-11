#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

int get_metadata_key(void);

void *memory_map(size_t size);
int memory_map_fixed(void *ptr, size_t size);
int memory_unmap(void *ptr, size_t size);
int memory_protect_ro(void *ptr, size_t size);
int memory_protect_rw(void *ptr, size_t size);
int memory_protect_rw_metadata(void *ptr, size_t size);
int memory_remap(void *old, size_t old_size, size_t new_size);
int memory_remap_fixed(void *old, size_t old_size, void *new, size_t new_size);
void memory_set_name(void *ptr, size_t size, const char *name);

#endif
