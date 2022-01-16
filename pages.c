#include <errno.h>

#include "memory.h"
#include "pages.h"
#include "util.h"

static bool add_guards(size_t size, size_t guard_size, size_t *total_size) {
    return __builtin_add_overflow(size, guard_size, total_size) ||
        __builtin_add_overflow(*total_size, guard_size, total_size);
}

void *allocate_pages(size_t usable_size, size_t guard_size, bool unprotect, const char *name) {
    size_t real_size;
    if (unlikely(add_guards(usable_size, guard_size, &real_size))) {
        errno = ENOMEM;
        return NULL;
    }
    void *real = memory_map(real_size);
    if (unlikely(real == NULL)) {
        return NULL;
    }
    memory_set_name(real, real_size, name);
    void *usable = (char *)real + guard_size;
    if (unprotect && unlikely(memory_protect_rw(usable, usable_size))) {
        memory_unmap(real, real_size);
        return NULL;
    }
    return usable;
}

void *allocate_pages_aligned(size_t usable_size, size_t alignment, size_t guard_size, const char *name) {
    usable_size = page_align(usable_size);
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
    if (unlikely(add_guards(alloc_size, guard_size, &real_alloc_size))) {
        errno = ENOMEM;
        return NULL;
    }

    void *real = memory_map(real_alloc_size);
    if (unlikely(real == NULL)) {
        return NULL;
    }
    memory_set_name(real, real_alloc_size, name);

    void *usable = (char *)real + guard_size;

    size_t lead_size = align((uintptr_t)usable, alignment) - (uintptr_t)usable;
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

void deallocate_pages(void *usable, size_t usable_size, size_t guard_size) {
    if (unlikely(memory_unmap((char *)usable - guard_size, usable_size + guard_size * 2))) {
        memory_purge(usable, usable_size);
    }
}
