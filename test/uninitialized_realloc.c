#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = realloc((void *)1, 16);
    if (!p) {
        return 1;
    }
    return 0;
}
