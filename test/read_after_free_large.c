#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(256 * 1024);
    if (!p) {
        return 1;
    }
    memset(p, 'a', 16);
    free(p);
    for (size_t i = 0; i < 256 * 1024; i++) {
        printf("%x\n", p[i]);
        if (p[i] != '\0') {
            return 1;
        }
    }
    return 0;
}
