#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    void *p = malloc(65536);
    if (!p) {
        return 1;
    }
    void *allocs[100];
    for (int i = 0; i < 100; i++) {
        allocs[i] = malloc(65536);
        if (!allocs[i]) {
            return 1;
        }
    }
    free(p);
    for (int i = 0; i < 100; i++) {
        free(allocs[i]);
    }
    free(p);
    return 0;
}
