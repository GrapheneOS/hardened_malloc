#include <stdio.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p, *q, *r;

    p = malloc(16);
    if (!p) {
        return 1;
    }

    q = realloc(p, 0);

    free(q);

    return 0;
}
