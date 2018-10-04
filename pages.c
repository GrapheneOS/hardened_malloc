#include <errno.h>

#include "memory.h"
#include "pages.h"
#include "util.h"

#define ALIGNMENT_CEILING(s, alignment) (((s) + (alignment - 1)) & ((~(alignment)) + 1))

void *allocate_pages(size_t usable_size, size_t guard_size, bool unprotect) {
    size_t real_size;
    if (unlikely(__builtin_add_overflow(usable_size, guard_size * 2, &real_size))) {
        errno = ENOMEM;
        return NULL;
    }
    void *real = memory_map(real_size);
    if (unlikely(real == NULL)) {
        return NULL;
    }
    void *usable = (char *)real + guard_size;
    if (unprotect && unlikely(memory_protect_rw(usable, usable_size))) {
        memory_unmap(real, real_size);
        return NULL;
    }
    return usable;
}

void deallocate_pages(void *usable, size_t usable_size, size_t guard_size) {
    memory_unmap((char *)usable - guard_size, usable_size + guard_size * 2);
}

void *allocate_pages_aligned(size_t usable_size, size_t alignment, size_t guard_size) {
    usable_size = PAGE_CEILING(usable_size);
    if (unlikely(!usable_size)) {
        errno = ENOMEM;
        return NULL;
    }

    size_t alloc_size;
    if (unlikely(__builtin_add_overflow(usable_size, alignment - PAGE_SIZE, &alloc_size))) {
        errno = ENOMEM;
        return NULL;
    }

    size_t real_alloc_size;
    if (unlikely(__builtin_add_overflow(alloc_size, guard_size * 2, &real_alloc_size))) {
        errno = ENOMEM;
        return NULL;
    }

    void *real = memory_map(real_alloc_size);
    if (unlikely(real == NULL)) {
        return NULL;
    }

    void *usable = (char *)real + guard_size;

    size_t lead_size = ALIGNMENT_CEILING((uintptr_t)usable, alignment) - (uintptr_t)usable;
    size_t trail_size = alloc_size - lead_size - usable_size;
    void *base = (char *)usable + lead_size;

    if (unlikely(memory_protect_rw(base, usable_size))) {
        memory_unmap(real, real_alloc_size);
        return NULL;
    }

    if (lead_size) {
        if (unlikely(memory_unmap(real, lead_size))) {
            memory_unmap(real, real_alloc_size);
            return NULL;
        }
    }

    if (trail_size) {
        if (unlikely(memory_unmap((char *)base + usable_size + guard_size, trail_size))) {
            memory_unmap(real, real_alloc_size);
            return NULL;
        }
    }

    return base;
}
