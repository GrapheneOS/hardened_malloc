#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(256 * 1024);
    if (!p) {
        return 1;
    }
    free(p);
    p[64 * 1024 + 1] = 'a';
    return 0;
}
