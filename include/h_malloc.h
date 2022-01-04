#ifndef ALLOCATOR_H
#define ALLOCATOR_H

#include <stdio.h>

#include <malloc.h>

#ifdef __cplusplus
extern "C" {
#endif

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
#define h_mallinfo2 mallinfo2
#define h_malloc_info malloc_info

#define h_memalign memalign
#define h_valloc valloc
#define h_pvalloc pvalloc
#define h_cfree cfree
#define h_malloc_get_state malloc_get_state
#define h_malloc_set_state malloc_set_state

#define h_mallinfo_narenas mallinfo_narenas
#define h_mallinfo_nbins mallinfo_nbins
#define h_mallinfo_arena_info mallinfo_arena_info
#define h_mallinfo_bin_info mallinfo_bin_info

#define h_malloc_iterate malloc_iterate
#define h_malloc_disable malloc_disable
#define h_malloc_enable malloc_enable

#define h_malloc_object_size malloc_object_size
#define h_malloc_object_size_fast malloc_object_size_fast
#define h_free_sized free_sized
#endif

// C standard
__attribute__((malloc)) __attribute__((alloc_size(1))) void *h_malloc(size_t size);
__attribute__((malloc)) __attribute__((alloc_size(1, 2))) void *h_calloc(size_t nmemb, size_t size);
__attribute__((alloc_size(2))) void *h_realloc(void *ptr, size_t size);
__attribute__((malloc)) __attribute__((alloc_size(2))) __attribute__((alloc_align(1)))
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
#ifndef __ANDROID__
int h_malloc_info(int options, FILE *fp);
#endif

// obsolete glibc extensions
__attribute__((malloc)) __attribute__((alloc_size(2))) __attribute__((alloc_align(1)))
void *h_memalign(size_t alignment, size_t size);
#ifndef __ANDROID__
__attribute__((malloc)) __attribute__((alloc_size(1))) void *h_valloc(size_t size);
__attribute__((malloc)) void *h_pvalloc(size_t size);
#endif
#ifdef __GLIBC__
void h_cfree(void *ptr) __THROW;
void *h_malloc_get_state(void);
int h_malloc_set_state(void *state);
#endif

// Android extensions
#ifdef __ANDROID__
size_t h_mallinfo_narenas(void);
size_t h_mallinfo_nbins(void);
struct mallinfo h_mallinfo_arena_info(size_t arena);
struct mallinfo h_mallinfo_bin_info(size_t arena, size_t bin);
int h_malloc_iterate(uintptr_t base, size_t size, void (*callback)(uintptr_t ptr, size_t size, void *arg),
              void *arg);
void h_malloc_disable(void);
void h_malloc_enable(void);
#endif

// hardened_malloc extensions

// return an upper bound on object size for any pointer based on malloc metadata
size_t h_malloc_object_size(const void *ptr);

// similar to malloc_object_size, but avoiding locking so the results are much more limited
size_t h_malloc_object_size_fast(const void *ptr);

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

#ifdef __cplusplus
}
#endif

#endif
