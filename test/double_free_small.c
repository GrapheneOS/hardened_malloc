#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = malloc(16);
    if (!p) {
        return 1;
    }
    free(p);
    free(p);
    return 0;
}
