#include <errno.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    errno = 0;
    // alignment is not a power of two
    void *p = aligned_alloc(17, 100);
    return !(p == NULL && errno == EINVAL);
}
