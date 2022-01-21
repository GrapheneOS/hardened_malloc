#include <malloc.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    malloc_usable_size(p + 1);
    return 0;
}
