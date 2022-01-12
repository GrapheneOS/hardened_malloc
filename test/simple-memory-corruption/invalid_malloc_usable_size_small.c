#include <malloc/malloc.h>
#include <stdlib.h>

#include "../test_util.h"

OPTNONE int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    char *q = p + 4096 * 4;
    malloc_size(q);
    return 0;
}
