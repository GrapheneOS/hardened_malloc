#include <stdlib.h>
#include <string.h>

#include "../test_util.h"

#define CANARY_SIZE 8

// Check that the slab canary can't be leaked with a C-string function.
OPTNONE int main(void) {
    char leaked_str_canary[CANARY_SIZE] = {0};
    char leaked_canary[CANARY_SIZE] = {0};
    char *p = malloc(8);
    if (!p) {
        return 1;
    }
    strncpy(leaked_str_canary, p + 8, CANARY_SIZE);
    memcpy(leaked_canary, p + 8, CANARY_SIZE);
    if (!memcmp(leaked_canary, leaked_str_canary, CANARY_SIZE)) {
        free(p);
        return 1;
    }
    free(p);
    return 0;
}
