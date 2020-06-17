#include <stdlib.h>

#include "../test_util.h"

OPTNONE int main(void) {
    char *p = malloc(256 * 1024);
    if (!p) {
        return 1;
    }
    *(p + 256 * 1024 + 7) = 0;
    free(p);
    return 0;
}
