#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(0);
    if (!p) {
        return 1;
    }
    *p = 5;
    return 0;
}
