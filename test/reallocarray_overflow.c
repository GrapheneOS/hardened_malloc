#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "test_util.h"

#pragma GCC diagnostic ignored "-Walloc-size-larger-than="

OPTNONE int main(void) {
    errno = 0;
    // (SIZE_MAX / 2 + 2) * 2 wraps to 2 which would be accepted without the reallocarray check
    void *p = reallocarray(NULL, SIZE_MAX / 2 + 2, 2);
    return !(p == NULL && errno == ENOMEM);
}
