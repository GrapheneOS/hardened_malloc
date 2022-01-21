#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <malloc.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }

    size_t size = malloc_usable_size(p);
    memset(p, 'a', size);
    printf("overflow by %zu bytes\n", strlen(p) - size);

    return 0;
}
