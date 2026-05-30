#include <malloc.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(4 * 1024 * 1024);
    if (!p) {
        return 1;
    }
    memset(p, 'a', 4 * 1024 * 1024);
    char *q = realloc(p, 1024 * 1024);
    if (!q) {
        return 1;
    }
    size_t size = malloc_usable_size(q);
    *(q + size) = 0;
    free(q);
    return 0;
}
