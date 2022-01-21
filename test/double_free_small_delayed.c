#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = malloc(16);
    if (!p) {
        return 1;
    }
    void *q = malloc(16);
    if (!q) {
        return 1;
    }
    free(p);
    free(q);
    free(p);
    return 0;
}
