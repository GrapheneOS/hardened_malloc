#include <stdlib.h>

#include "test_util.h"

size_t malloc_object_size(void *ptr);

OPTNONE int main(void) {
    char *p = malloc(16);
    // offset past the usable size, into the slab canary region
    return (int)malloc_object_size(p + 25);
}
