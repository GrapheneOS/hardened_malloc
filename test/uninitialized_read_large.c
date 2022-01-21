#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(256 * 1024);
    for (unsigned i = 0; i < 256 * 1024; i++) {
        if (p[i] != 0) {
            return 1;
        }
    }
    free(p);
    return 0;
}
