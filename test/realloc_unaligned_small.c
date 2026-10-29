#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    // same size class as the allocation, so realloc may return the pointer in-place
    realloc(p + 1, 16);
    return 0;
}
