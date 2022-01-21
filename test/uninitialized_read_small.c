#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(8);
    for (unsigned i = 0; i < 8; i++) {
        if (p[i] != 0) {
            return 1;
        }
    }
    free(p);
    return 0;
}
