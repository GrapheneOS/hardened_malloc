#include <stdlib.h>

#include "test_util.h"

#pragma GCC diagnostic ignored "-Wfree-nonheap-object"

OPTNONE int main(void) {
    void *p = realloc((void *)1, 16);
    if (!p) {
        return 1;
    }
    return 0;
}
