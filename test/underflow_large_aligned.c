#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = NULL;
    if (posix_memalign(&p, 64 * 1024, 256 * 1024)) {
        return 1;
    }
    *((char *)p - 1) = 0;
    free(p);
    return 0;
}
