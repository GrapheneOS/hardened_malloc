#ifndef PAGES_H
#define PAGES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "util.h"

#define PAGE_SHIFT 12
#ifndef PAGE_SIZE
#define PAGE_SIZE ((size_t)1 << PAGE_SHIFT)
#endif

void *allocate_pages(size_t usable_size, size_t guard_size, bool unprotect, const char *name);
void *allocate_pages_aligned(size_t usable_size, size_t alignment, size_t guard_size, const char *name);
void deallocate_pages(void *usable, size_t usable_size, size_t guard_size);

static inline size_t page_align(size_t size) {
    return align(size, PAGE_SIZE);
}

static inline size_t hash_page(const void *p) {
    uintptr_t u = (uintptr_t)p >> PAGE_SHIFT;
    size_t sum = u;
    sum = (sum << 7) - sum + (u >> 16);
    sum = (sum << 7) - sum + (u >> 32);
    sum = (sum << 7) - sum + (u >> 48);
    return sum;
}

#endif
