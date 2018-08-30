#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdio.h>

#include <malloc.h>

#ifndef H_MALLOC_PREFIX
#define h_malloc malloc
#define h_calloc calloc
#define h_realloc realloc
#define h_posix_memalign posix_memalign
#define h_aligned_alloc aligned_alloc
#define h_memalign memalign
#define h_valloc valloc
#define h_pvalloc pvalloc
#define h_free free
#define h_malloc_usable_size malloc_usable_size
#define h_mallopt mallopt
#define h_malloc_trim malloc_trim
#define h_malloc_stats malloc_stats
#define h_mallinfo mallinfo
#define h_malloc_info malloc_info
#define h_malloc_get_state malloc_get_state
#define h_malloc_set_state malloc_set_state
#define h_cfree cfree
#endif

// C standard
void *h_malloc(size_t size);
void *h_calloc(size_t nmemb, size_t size);
void *h_realloc(void *ptr, size_t size);
void *h_aligned_alloc(size_t alignment, size_t size);
void h_free(void *ptr);

// POSIX
int h_posix_memalign(void **memptr, size_t alignment, size_t size);

// glibc extensions
size_t h_malloc_usable_size(void *ptr);
int h_mallopt(int param, int value);
int h_malloc_trim(size_t pad);
void h_malloc_stats(void);
struct mallinfo h_mallinfo(void);
int h_malloc_info(int options, FILE *fp);
void *h_malloc_get_state(void);
int h_malloc_set_state(void *state);

// obsolete glibc extensions
void *h_memalign(size_t alignment, size_t size);
void *h_valloc(size_t size);
void *h_pvalloc(size_t size);
void h_cfree(void *ptr);

// custom extensions

// return an upper bound on object size for any pointer based on malloc metadata
size_t h_malloc_object_size(void *ptr);

// similar to malloc_object_size, but avoiding locking so the results are much more limited
size_t h_malloc_object_size_fast(void *ptr);

#endif
