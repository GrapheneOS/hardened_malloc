#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdio.h>

#include <malloc.h>

__BEGIN_DECLS

#ifndef H_MALLOC_PREFIX
#define h_malloc malloc
#define h_calloc calloc
#define h_realloc realloc
#define h_aligned_alloc aligned_alloc
#define h_free free

#define h_posix_memalign posix_memalign

#define h_malloc_usable_size malloc_usable_size
#define h_mallopt mallopt
#define h_malloc_trim malloc_trim
#define h_malloc_stats malloc_stats
#define h_mallinfo mallinfo
#define h_malloc_info malloc_info

#define h_memalign memalign
#define h_valloc valloc
#define h_pvalloc pvalloc
#define h_cfree cfree
#define h_malloc_get_state malloc_get_state
#define h_malloc_set_state malloc_set_state

#define h_iterate iterate
#define h_malloc_disable malloc_disable
#define h_malloc_enable malloc_enable

#define h_malloc_object_size malloc_object_size
#define h_malloc_object_size_fast malloc_object_size_fast
#define h_free_sized free_sized
#endif

// C standard
void *h_malloc(size_t size);
void *h_calloc(size_t nmemb, size_t size);
void *h_realloc(void *ptr, size_t size);
void *h_aligned_alloc(size_t alignment, size_t size);
void h_free(void *ptr);

// POSIX
int h_posix_memalign(void **memptr, size_t alignment, size_t size);

#ifdef __ANDROID__
#define H_MALLOC_USABLE_SIZE_CONST const
#else
#define H_MALLOC_USABLE_SIZE_CONST
#endif

// glibc extensions
size_t h_malloc_usable_size(H_MALLOC_USABLE_SIZE_CONST void *ptr);
int h_mallopt(int param, int value);
int h_malloc_trim(size_t pad);
void h_malloc_stats(void);
#if defined(__GLIBC__) || defined(__ANDROID__)
struct mallinfo h_mallinfo(void);
#endif
int h_malloc_info(int options, FILE *fp);

// obsolete glibc extensions
void *h_memalign(size_t alignment, size_t size);
void *h_valloc(size_t size);
void *h_pvalloc(size_t size);
void h_cfree(void *ptr);
void *h_malloc_get_state(void);
int h_malloc_set_state(void *state);

// Android extensions
#ifdef __ANDROID__
size_t __mallinfo_narenas(void);
size_t __mallinfo_nbins(void);
struct mallinfo __mallinfo_arena_info(size_t arena);
struct mallinfo __mallinfo_bin_info(size_t arena, size_t bin);
int h_iterate(uintptr_t base, size_t size, void (*callback)(uintptr_t ptr, size_t size, void *arg),
              void *arg);
void h_malloc_disable(void);
void h_malloc_enable(void);
#endif

// custom extensions

// return an upper bound on object size for any pointer based on malloc metadata
size_t h_malloc_object_size(void *ptr);

// similar to malloc_object_size, but avoiding locking so the results are much more limited
size_t h_malloc_object_size_fast(void *ptr);

// The free function with an extra parameter for passing the size requested at
// allocation time.
//
// This offers the same functionality as C++14 sized deallocation and can be
// used to implement it.
//
// A performance-oriented allocator would use this as a performance
// enhancement with undefined behavior on a mismatch. Instead, this hardened
// allocator implementation uses it to improve security by checking that the
// passed size matches the allocated size.
void h_free_sized(void *ptr, size_t expected_size);

__END_DECLS

#endif
