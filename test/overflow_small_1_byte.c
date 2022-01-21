#include <malloc.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(8);
    if (!p) {
        return 1;
    }
    size_t size = malloc_usable_size(p);
    *(p + size) = 1;
    free(p);
    return 0;
}
