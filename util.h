#ifndef UTIL_H
#define UTIL_H

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


#ifdef __APPLE__
#define ALIAS(f) 
#else
#define STRINGIFY(s) #s
#define ALIAS(f) __attribute__((alias(STRINGIFY(f))))
#endif


static inline int ffzl(unsigned long x) {
    return __builtin_ffsl(~x);
}

COLD noreturn void fatal_error(const char *s);

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned __int128 u128;

#if CONFIG_SEAL_METADATA

#ifdef __GLIBC__
#define USE_PKEY
#else
#error "CONFIG_SEAL_METADATA requires Memory Protection Key support"
#endif

#endif // CONFIG_SEAL_METADATA

#endif
