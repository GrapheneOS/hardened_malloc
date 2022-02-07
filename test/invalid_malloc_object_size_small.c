#include <stdlib.h>

#include "test_util.h"

size_t malloc_object_size(void *ptr);

OPTNONE int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    char *q = p + 4096 * 4;
    malloc_object_size(q);
    return 0;
}
