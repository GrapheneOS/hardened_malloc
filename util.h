#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// C11 noreturn doesn't work in C++
#define noreturn __attribute__((noreturn))

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define min(x, y) ({ \
    __typeof__(x) _x = (x); \
    __typeof__(y) _y = (y); \
    (void) (&_x == &_y); \
    _x < _y ? _x : _y; })

#define max(x, y) ({ \
    __typeof__(x) _x = (x); \
    __typeof__(y) _y = (y); \
    (void) (&_x == &_y); \
    _x > _y ? _x : _y; })

#define COLD __attribute__((cold))
#define UNUSED __attribute__((unused))
#define EXPORT __attribute__((visibility("default")))

#define STRINGIFY(s) #s
#define ALIAS(f) __attribute__((alias(STRINGIFY(f))))

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned __int128 u128;

#define U64_WIDTH 64

static inline int ffz64(u64 x) {
    return __builtin_ffsll(~x);
}

// parameter must not be 0
static inline int clz64(u64 x) {
    return __builtin_clzll(x);
}

// parameter must not be 0
static inline u64 log2u64(u64 x) {
    return U64_WIDTH - clz64(x) - 1;
}

static inline size_t align(size_t size, size_t align) {
    size_t mask = align - 1;
    return (size + mask) & ~mask;
}

// u4_arr_{set,get} are helper functions for using u8 array as an array of unsigned 4-bit values.

// val is treated as a 4-bit value
static inline void u4_arr_set(u8 *arr, size_t idx, u8 val) {
    size_t off = idx >> 1;
    size_t shift = (idx & 1) << 2;
    u8 mask = (u8) (0xf0 >> shift);
    arr[off] = (arr[off] & mask) | (val << shift);
}

static inline u8 u4_arr_get(const u8 *arr, size_t idx) {
    size_t off = idx >> 1;
    size_t shift = (idx & 1) << 2;
    return (u8) ((arr[off] >> shift) & 0xf);
}

COLD noreturn void fatal_error(const char *s);

#if CONFIG_SEAL_METADATA

#ifdef __GLIBC__
#define USE_PKEY
#else
#error "CONFIG_SEAL_METADATA requires Memory Protection Key support"
#endif

#endif // CONFIG_SEAL_METADATA

#endif
