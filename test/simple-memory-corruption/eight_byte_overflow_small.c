#include <stdlib.h>

#include "../test_util.h"

OPTNONE int main(void) {
    char *p = malloc(8);
    if (!p) {
        return 1;
    }
    *(p + 8 + 7) = 0;
    free(p);
    return 0;
}
