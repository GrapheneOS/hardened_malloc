#ifndef UTIL_H
#define UTIL_H

#include <stdint.h>
#include <stdnoreturn.h>

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

static inline int ffzl(long x) {
    return __builtin_ffsl(~x);
}

COLD noreturn void fatal_error(const char *s);

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned __int128 u128;

// use __register_atfork directly to avoid linking with libpthread for glibc < 2.28
#ifdef __GLIBC__
#if !__GLIBC_PREREQ(2, 28)
extern void *__dso_handle;
extern int __register_atfork(void (*)(void), void (*)(void), void (*)(void), void *);
#define atfork(prepare, parent, child) __register_atfork(prepare, parent, child, __dso_handle)
#endif
#endif

#ifndef atfork
#define atfork pthread_atfork
#endif

#ifdef CONFIG_SEAL_METADATA

#ifdef __GLIBC__
#if __GLIBC_PREREQ(2, 27)
#define USE_PKEY
#endif
#endif

#ifndef USE_PKEY
#error "CONFIG_SEAL_METADATA requires Memory Protection Key support"
#endif

#endif // CONFIG_SEAL_METADATA

#endif
