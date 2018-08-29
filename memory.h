#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>

void *memory_map(size_t size);
int memory_unmap(void *ptr, size_t size);
int memory_protect(void *ptr, size_t size, int prot);
int memory_remap_fixed(void *old, size_t old_size, void *new, size_t new_size);

#endif
