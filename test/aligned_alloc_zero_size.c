#include <stdint.h>
#include <stdlib.h>

#include "../include/h_malloc.h"
#include "test_util.h"

OPTNONE int main(void) {
    size_t alignment = 8192;
    void *p = aligned_alloc(alignment, 0);
    if (!p || (uintptr_t)p % alignment) {
        return 1;
    }
    free_aligned_sized(p, alignment, 0);

    void *q;
    if (posix_memalign(&q, alignment, 0) || !q || (uintptr_t)q % alignment) {
        return 1;
    }
    free(q);

    return 0;
}
