#include <stdlib.h>

#include "test_util.h"

size_t malloc_object_size(void *ptr);

OPTNONE int main(void) {
    void *p = malloc(16);
    if (!p) {
        return 1;
    }
    free(p);
    malloc_object_size(p);
    return 0;
}
