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

int memory_unmap(void *ptr, size_t size) {
    int ret = munmap(ptr, size);
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM munmap failure");
    }
    return ret;
}

int memory_protect(void *ptr, size_t size, int prot) {
    int ret = mprotect(ptr, size, prot);
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM mprotect failure");
    }
    return ret;
}

int memory_remap_fixed(void *old, size_t old_size, void *new, size_t new_size) {
    void *ptr = mremap(old, old_size, new_size, MREMAP_MAYMOVE|MREMAP_FIXED, new);
    if (unlikely(ptr == MAP_FAILED)) {
        if (errno != ENOMEM) {
            fatal_error("non-ENOMEM mremap failure");
        }
        return 1;
    }
    return 0;
}
