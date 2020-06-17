#include <stdlib.h>

#include "../test_util.h"

OPTNONE int main(void) {
    void *p = malloc(128 * 1024);
    if (!p) {
        return 1;
    }
    free(p);
    free(p);
    return 0;
}
