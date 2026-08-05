#include <errno.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = (void *)0x1;
    // alignment must be a power of two multiple of sizeof(void *)
    if (posix_memalign(&p, 17, 100) != EINVAL) {
        return 1;
    }
    // the output pointer must be left untouched on failure
    return p != (void *)0x1;
}
