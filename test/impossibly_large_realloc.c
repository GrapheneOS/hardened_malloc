#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    // above the threshold for moving large allocations with mremap
    size_t size = 40 * 1024 * 1024;
    char *p = malloc(size);
    if (!p) {
        return 1;
    }
    memset(p, 'a', size);

    errno = 0;
    char *q = realloc(p, SIZE_MAX / 2);
    if (q || errno != ENOMEM || p[0] != 'a' || p[size - 1] != 'a') {
        return 1;
    }
    free(p);
    return 0;
}
