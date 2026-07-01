#include <errno.h>
#include <stdatomic.h>

#include <sys/mman.h>

#include <sys/prctl.h>

#ifndef MADV_GUARD_INSTALL
#define MADV_GUARD_INSTALL 102
#endif

#ifndef PR_SET_VMA
#define PR_SET_VMA 0x53564d41
#endif

#ifndef PR_SET_VMA_ANON_NAME
#define PR_SET_VMA_ANON_NAME 0
#endif

#include "memory.h"
#include "pages.h"
#include "util.h"

static void *memory_map_prot(size_t size, int prot) {
    void *p = mmap(NULL, size, prot, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (unlikely(p == MAP_FAILED)) {
        if (errno != ENOMEM) {
            fatal_error("non-ENOMEM mmap failure");
        }
        return NULL;
    }
    return p;
}

void *memory_map(size_t size) {
    return memory_map_prot(size, PROT_NONE);
}

void *memory_map_rw(size_t size) {
    return memory_map_prot(size, PROT_READ|PROT_WRITE);
}

#ifdef HAS_ARM_MTE
// Note that PROT_MTE can't be cleared via mprotect
void *memory_map_mte(size_t size) {
    return memory_map_prot(size, PROT_MTE);
}
#endif

static bool memory_map_fixed_prot(void *ptr, size_t size, int prot) {
    void *p = mmap(ptr, size, prot, MAP_ANONYMOUS|MAP_PRIVATE|MAP_FIXED, -1, 0);
    bool ret = p == MAP_FAILED;
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM MAP_FIXED mmap failure");
    }
    return ret;
}

bool memory_map_fixed(void *ptr, size_t size) {
    return memory_map_fixed_prot(ptr, size, PROT_NONE);
}

#ifdef HAS_ARM_MTE
// Note that PROT_MTE can't be cleared via mprotect
bool memory_map_fixed_mte(void *ptr, size_t size) {
    return memory_map_fixed_prot(ptr, size, PROT_MTE);
}
#endif

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
    bool ret = madvise(ptr, size, MADV_DONTNEED);
    if (unlikely(ret) && errno != ENOMEM) {
        fatal_error("non-ENOMEM MADV_DONTNEED madvise failure");
    }
    return ret;
}

// 0 = unknown, 1 = supported, -1 = unsupported/disabled
static atomic_int guard_install_state;

// EINVAL means the mapping is locked, so reset the state to trigger a re-probe
bool memory_guard_install(void *ptr, size_t size) {
    int saved_errno = errno;
    if (likely(madvise(ptr, size, MADV_GUARD_INSTALL) == 0)) {
        return false;
    }
    if (errno == EINVAL) {
        int expected = 1;
        atomic_compare_exchange_strong_explicit(&guard_install_state, &expected, 0,
            memory_order_relaxed, memory_order_relaxed);
    }
    errno = saved_errno;
    return true;
}

bool memory_guard_install_supported(void) {
    int s = atomic_load_explicit(&guard_install_state, memory_order_relaxed);
    if (likely(s)) {
        return s > 0;
    }
    int saved_errno = errno;
    void *p = mmap(NULL, PAGE_SIZE, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        errno = saved_errno;
        return false;
    }
    // EINVAL on a fresh mapping means no kernel support or mlockall(MCL_FUTURE)
    s = madvise(p, PAGE_SIZE, MADV_GUARD_INSTALL) == 0 ? 1 : (errno == EINVAL ? -1 : 0);
    munmap(p, PAGE_SIZE);
    errno = saved_errno;
    if (s) {
        int expected = 0;
        if (!atomic_compare_exchange_strong_explicit(&guard_install_state, &expected, s,
                memory_order_relaxed, memory_order_relaxed)) {
            s = expected;
        }
    }
    return s > 0;
}

bool memory_guard_or_protnone(void *ptr, size_t size) {
    if (GUARD_PAGES_USE_MADVISE && memory_guard_install_supported()) {
        return memory_guard_install(ptr, size) && memory_map_fixed(ptr, size);
    }
    return memory_map_fixed(ptr, size);
}

bool memory_set_name(UNUSED void *ptr, UNUSED size_t size, UNUSED const char *name) {
    if (CONFIG_LABEL_MEMORY) {
        return prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, size, name);
    }
    return false;
}
