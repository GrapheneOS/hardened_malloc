#include <stdio.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p, *q, *r;

    p = malloc(256 * 1024);
    if (!p) {
        return 1;
    }

    q = realloc(p, 0);

    printf("%c\n", *p);

    free(q);

    return 0;
}
