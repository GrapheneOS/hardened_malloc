#include <errno.h>

#include <sys/mman.h>

#include "memory.h"
#include "util.h"

void *memory_map(size_t size) {
    void *p = mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (unlikely(p == MAP_FAILED)) {
        if (errno != ENOMEM) {
            fatal_error("non-ENOMEM mmap failure");
        }
        return NULL;
    }
    return p;
}

int memory_map_fixed(void *ptr, size_t size) {
    void *p = mmap(ptr, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    if (unlikely(p == MAP_FAILED)) {
        if (errno != ENOMEM) {
            fatal_error("non-ENOMEM MAP_FIXED mmap failure");
        }
        return 1;
    }
    return 0;
}

int memory_unmap(void *ptr, size_t size) {
    int ret = munmap(ptr, size);
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM munmap failure");
    }
    return ret;
}

static int memory_protect_prot(void *ptr, size_t size, int prot, UNUSED int pkey) {
#ifdef USE_PKEY
    int ret = pkey_mprotect(ptr, size, prot, pkey);
#else
    int ret = mprotect(ptr, size, prot);
#endif
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM mprotect failure");
    }
    return ret;
}

int memory_protect_ro(void *ptr, size_t size) {
    return memory_protect_prot(ptr, size, PROT_READ, -1);
}

int memory_protect_rw(void *ptr, size_t size) {
    return memory_protect_prot(ptr, size, PROT_READ|PROT_WRITE, -1);
}

int memory_protect_rw_metadata(void *ptr, size_t size) {
    return memory_protect_prot(ptr, size, PROT_READ|PROT_WRITE, get_metadata_key());
}

int memory_remap(void *old, size_t old_size, size_t new_size) {
    void *ptr = mremap(old, old_size, new_size, 0);
    if (unlikely(ptr == MAP_FAILED)) {
        if (errno != ENOMEM) {
            fatal_error("non-ENOMEM mremap failure");
        }
        return 1;
    }
    return 0;
}

int memory_remap_fixed(void *old, size_t old_size, void *new, size_t new_size) {
    void *ptr = mremap(old, old_size, new_size, MREMAP_MAYMOVE|MREMAP_FIXED, new);
    if (unlikely(ptr == MAP_FAILED)) {
        if (errno != ENOMEM) {
            fatal_error("non-ENOMEM MREMAP_FIXED mremap failure");
        }
        return 1;
    }
    return 0;
}
