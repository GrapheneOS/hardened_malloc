#include <malloc.h>
#include <stdlib.h>

#include "../include/h_malloc.h"
#include "test_util.h"

OPTNONE int main(void) {
    // pvalloc(0) must return a valid, freeable allocation
    void *p = pvalloc(0);
    if (p == NULL) {
        return 1;
    }
    free(p);

    void *q = pvalloc(100);
    if (q == NULL) {
        return 1;
    }
    free(q);

    return 0;
}
