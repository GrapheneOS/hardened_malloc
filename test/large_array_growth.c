#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = NULL;
    size_t size = 256 * 1024;

    for (unsigned i = 0; i < 20; i++) {
        p = realloc(p, size);
        if (!p) {
            return 1;
        }
        memset(p, 'a', size);
        size = size * 3 / 2;
    }
}
