#ifndef MEMORY_H
#define MEMORY_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __linux__
#define HAVE_COMPATIBLE_MREMAP
#endif

int get_metadata_key(void);

void *memory_map(size_t size);
bool memory_map_fixed(void *ptr, size_t size);
bool memory_unmap(void *ptr, size_t size);
bool memory_protect_ro(void *ptr, size_t size);
bool memory_protect_rw(void *ptr, size_t size);
bool memory_protect_rw_metadata(void *ptr, size_t size);
#ifdef HAVE_COMPATIBLE_MREMAP
bool memory_remap(void *old, size_t old_size, size_t new_size);
bool memory_remap_fixed(void *old, size_t old_size, void *new, size_t new_size);
#endif
bool memory_purge(void *ptr, size_t size);
bool memory_set_name(void *ptr, size_t size, const char *name);

#endif
