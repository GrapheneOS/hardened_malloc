#include <stdbool.h>
#include <stdlib.h>

#include "test_util.h"

size_t malloc_object_size(void *ptr);

OPTNONE int main(void) {
    char *p = malloc(0);
    size_t size = malloc_object_size(p);
    return size == 0;
}
