#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "test_util.h"

OPTNONE int main(void) {
    size_t size = 40 * 1024 * 1024;
    char *p = malloc(size);
    if (!p) {
        return 1;
    }
    memset(p, 'a', size);

    // splits the mapping, which prevents moving it with mremap
    if (mprotect(p + size / 2, 4096, PROT_READ)) {
        return 1;
    }

    uintptr_t old = (uintptr_t)p;
    char *q = realloc(p, size * 2);
    if (!q) {
        return 1;
    }
    for (size_t i = 0; i < size; i += 4096) {
        if (q[i] != 'a' || q[i + 4095] != 'a') {
            return 1;
        }
    }

    unsigned char vec;
    if (mincore((void *)old, 4096, &vec) != -1 || errno != ENOMEM) {
        return 1;
    }

    free(q);
    return 0;
}
