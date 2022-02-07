#include <errno.h>

#include <sys/mman.h>

#ifdef LABEL_MEMORY
#include <sys/prctl.h>
#endif

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif

#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

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

bool memory_map_fixed(void *ptr, size_t size) {
    void *p = mmap(ptr, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    bool ret = p == MAP_FAILED;
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM MAP_FIXED mmap failure");
    }
    return ret;
}

bool memory_unmap(void *ptr, size_t size) {
    bool ret = munmap(ptr, size);
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM munmap failure");
    }
    return ret;
}

static bool memory_protect_prot(void *ptr, size_t size, int prot, UNUSED int pkey) {
#ifdef USE_PKEY
    bool ret = pkey_mprotect(ptr, size, prot, pkey);
#else
    bool ret = mprotect(ptr, size, prot);
#endif
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM mprotect failure");
    }
    return ret;
}

bool memory_protect_ro(void *ptr, size_t size) {
    return memory_protect_prot(ptr, size, PROT_READ, -1);
}

bool memory_protect_rw(void *ptr, size_t size) {
    return memory_protect_prot(ptr, size, PROT_READ|PROT_WRITE, -1);
}

bool memory_protect_rw_metadata(void *ptr, size_t size) {
    return memory_protect_prot(ptr, size, PROT_READ|PROT_WRITE, get_metadata_key());
}

#ifdef HAVE_COMPATIBLE_MREMAP
bool memory_remap(void *old, size_t old_size, size_t new_size) {
    void *ptr = mremap(old, old_size, new_size, 0);
    bool ret = ptr == MAP_FAILED;
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM mremap failure");
    }
    return ret;
}

bool memory_remap_fixed(void *old, size_t old_size, void *new, size_t new_size) {
    void *ptr = mremap(old, old_size, new_size, MREMAP_MAYMOVE|MREMAP_FIXED, new);
    bool ret = ptr == MAP_FAILED;
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM MREMAP_FIXED mremap failure");
    }
    return ret;
}
#endif

bool memory_purge(void *ptr, size_t size) {
    int ret = madvise(ptr, size, MADV_DONTNEED);
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM MADV_DONTNEED madvise failure");
    }
    return ret;
}

bool memory_set_name(UNUSED void *ptr, UNUSED size_t size, UNUSED const char *name) {
#ifdef LABEL_MEMORY
    return prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, size, name);
#else
    return false;
#endif
}
