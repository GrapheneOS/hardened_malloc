#include <malloc.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = NULL;
    if (posix_memalign(&p, 64 * 1024, 256 * 1024)) {
        return 1;
    }
    size_t size = malloc_usable_size(p);
    *((char *)p + size) = 0;
    free(p);
    return 0;
}
