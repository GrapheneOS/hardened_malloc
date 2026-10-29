#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = malloc(16);
    if (!p) {
        return 1;
    }
    free(p);
    // same size class as the freed allocation, so realloc may return p in-place
    realloc(p, 16);
    return 0;
}
