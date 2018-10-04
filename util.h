#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdnoreturn.h>

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define COLD __attribute__((cold))
#define UNUSED __attribute__((unused))
#define EXPORT __attribute__((visibility("default")))

#define STRINGIFY(s) #s
#define ALIAS(f) __attribute__((alias(STRINGIFY(f))))

static inline int ffzl(long x) {
    return __builtin_ffsl(~x);
}

COLD noreturn void fatal_error(const char *s);

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned __int128 u128;

#endif
