#ifndef MEMTAG_H
#define MEMTAG_H

#include "util.h"

#ifdef HAS_ARM_MTE
#include "arm_mte.h"
#define MEMTAG 1
#define RESERVED_TAG 15
#define TAG_WIDTH 4
#endif

#ifdef MEMTAG
extern bool __is_memtag_enabled;
#endif

static inline bool is_memtag_enabled(void) {
#ifdef MEMTAG
    return __is_memtag_enabled;
#else
    return false;
#endif
}

static inline void *untag_pointer(void *ptr) {
#ifdef HAS_ARM_MTE
    const uintptr_t mask = UINTPTR_MAX >> 8;
    return (void *) ((uintptr_t) ptr & mask);
#else
    return ptr;
#endif
}

static inline void *set_pointer_tag(void *ptr, u8 tag) {
#ifdef HAS_ARM_MTE
    return (void *) (((uintptr_t) tag << 56) | (uintptr_t) untag_pointer(ptr));
#else
    (void) tag;
    return ptr;
#endif
}

static inline u8 get_pointer_tag(void *ptr) {
#ifdef HAS_ARM_MTE
    return (((uintptr_t) ptr) >> 56) & 0xf;
#else
    (void) ptr;
    return 0;
#endif
}

#endif
