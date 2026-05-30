#include <stdlib.h>
#include <string.h>

#include "../include/h_malloc.h"
#include "test_util.h"

OPTNONE int main(void) {
    size_t size = 100;
    char *p = malloc(size);
    if (!p) {
        return 1;
    }
    memset(p, 'a', size);

    free_sized(p, size);
    return 0;
}
