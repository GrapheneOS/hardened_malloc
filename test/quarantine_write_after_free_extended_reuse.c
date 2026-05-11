#include <stdlib.h>

#include "test_util.h"
#include "../util.h"

OPTNONE int main(void) {
    char *p = malloc(32768);
    if (!p) {
        return 1;
    }
    free(p);
    p[100] = 'a';
    for (size_t i = 0; i < 10000; i++) {
        free(malloc(32768));
    }
    return 0;
}
