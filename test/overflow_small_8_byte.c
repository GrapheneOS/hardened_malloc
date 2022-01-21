#include <malloc.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(8);
    if (!p) {
        return 1;
    }
    size_t size = malloc_usable_size(p);
    // XOR is used to avoid the test having a 1/256 chance to fail
    *(p + size + 7) ^= 1;
    free(p);
    return 0;
}
