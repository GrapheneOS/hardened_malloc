#include <stdlib.h>

#include "test_util.h"

#pragma GCC diagnostic ignored "-Wfree-nonheap-object"

OPTNONE int main(void) {
    free((void *)1);
    return 0;
}
