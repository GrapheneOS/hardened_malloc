#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "test_util.h"

#pragma GCC diagnostic ignored "-Walloc-size-larger-than="

OPTNONE int main(void) {
    errno = 0;
    void *p = calloc(SIZE_MAX, 2);
    return !(p == NULL && errno == ENOMEM);
}
