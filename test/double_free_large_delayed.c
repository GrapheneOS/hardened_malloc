#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = malloc(256 * 1024);
    if (!p) {
        return 1;
    }
    void *q = malloc(256 * 1024);
    if (!q) {
        return 1;
    }
    free(p);
    free(q);
    free(p);
    return 0;
}
