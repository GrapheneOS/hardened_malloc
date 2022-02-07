#include <stdlib.h>

#include "test_util.h"
#include "../util.h"

OPTNONE int main(void) {
    char *p = malloc(128);
    if (!p) {
        return 1;
    }
    free(p);
    UNUSED char *q = malloc(128);

    p[65] = 'a';

    // trigger reuse of the allocation
    for (size_t i = 0; i < 100000; i++) {
        free(malloc(128));
    }
    return 0;
}
