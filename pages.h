#ifndef PAGES_H
#define PAGES_H

#include <stdbool.h>
#include <stddef.h>

#define PAGE_SHIFT 12
#ifndef PAGE_SIZE
#define PAGE_SIZE ((size_t)1 << PAGE_SHIFT)
#endif
#define PAGE_CEILING(s) (((s) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))

void *allocate_pages(size_t usable_size, size_t guard_size, bool unprotect);
void deallocate_pages(void *usable, size_t usable_size, size_t guard_size);
void *allocate_pages_aligned(size_t usable_size, size_t alignment, size_t guard_size);

#endif
