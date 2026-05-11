#include <stdlib.h>

#include "test_util.h"
#include "../include/h_malloc.h"

OPTNONE int main(void) {
    void *p = malloc(32768);
    if (!p) {
        return 1;
    }
    free(p);
    h_malloc_object_size(p);
    return 0;
}
