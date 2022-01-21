#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    char *q = p + 1024 * 1024 * 1024;
    free(q);
    return 0;
}
