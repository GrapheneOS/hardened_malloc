#ifndef ARM_MTE_H
#define ARM_MTE_H

#include <arm_acle.h>
#include <util.h>

// Returns a tagged pointer.
// See https://developer.arm.com/documentation/ddi0602/2023-09/Base-Instructions/IRG--Insert-Random-Tag-
static inline void *arm_mte_create_random_tag(void *p, u64 exclusion_mask) {
    return __arm_mte_create_random_tag(p, exclusion_mask);
}

// Tag the memory region with the tag specified in tag bits of tagged_ptr. Memory region itself is
// zeroed.
// Arm's software optimization guide says:
// "it is recommended to use STZGM (or DCZGVA) to set tag if data is not a concern." (STZGM and
// DCGZVA are zeroing variants of tagging instructions).
//
// Contents of this function were copied from scudo:
// https://android.googlesource.com/platform/external/scudo/+/refs/tags/android-14.0.0_r1/standalone/memtag.h#167
//
// scudo is licensed under the Apache License v2.0 with LLVM Exceptions, which is compatible with
// the hardened_malloc's MIT license
static inline void arm_mte_store_tags_and_clear(void *tagged_ptr, size_t len) {
    uintptr_t Begin = (uintptr_t) tagged_ptr;
    uintptr_t End = Begin + len;
    uintptr_t LineSize, Next, Tmp;
    __asm__ __volatile__(
        ".arch_extension memtag \n\t"

        // Compute the cache line size in bytes (DCZID_EL0 stores it as the log2
        // of the number of 4-byte words) and bail out to the slow path if DCZID_EL0
        // indicates that the DC instructions are unavailable.
        "DCZID .req %[Tmp] \n\t"
        "mrs DCZID, dczid_el0 \n\t"
        "tbnz DCZID, #4, 3f \n\t"
        "and DCZID, DCZID, #15 \n\t"
        "mov %[LineSize], #4 \n\t"
        "lsl %[LineSize], %[LineSize], DCZID \n\t"
        ".unreq DCZID \n\t"

        // Our main loop doesn't handle the case where we don't need to perform any
        // DC GZVA operations. If the size of our tagged region is less than
        // twice the cache line size, bail out to the slow path since it's not
        // guaranteed that we'll be able to do a DC GZVA.
        "Size .req %[Tmp] \n\t"
        "sub Size, %[End], %[Cur] \n\t"
        "cmp Size, %[LineSize], lsl #1 \n\t"
        "b.lt 3f \n\t"
        ".unreq Size \n\t"

        "LineMask .req %[Tmp] \n\t"
        "sub LineMask, %[LineSize], #1 \n\t"

        // STZG until the start of the next cache line.
        "orr %[Next], %[Cur], LineMask \n\t"

        "1:\n\t"
        "stzg %[Cur], [%[Cur]], #16 \n\t"
        "cmp %[Cur], %[Next] \n\t"
        "b.lt 1b \n\t"

        // DC GZVA cache lines until we have no more full cache lines.
        "bic %[Next], %[End], LineMask \n\t"
        ".unreq LineMask \n\t"

        "2: \n\t"
        "dc gzva, %[Cur] \n\t"
        "add %[Cur], %[Cur], %[LineSize] \n\t"
        "cmp %[Cur], %[Next] \n\t"
        "b.lt 2b \n\t"

        // STZG until the end of the tagged region. This loop is also used to handle
        // slow path cases.

        "3: \n\t"
        "cmp %[Cur], %[End] \n\t"
        "b.ge 4f \n\t"
        "stzg %[Cur], [%[Cur]], #16 \n\t"
        "b 3b \n\t"

        "4: \n\t"

        : [Cur] "+&r"(Begin), [LineSize] "=&r"(LineSize), [Next] "=&r"(Next), [Tmp] "=&r"(Tmp)
        : [End] "r"(End)
        : "memory"
    );
}
#endif
