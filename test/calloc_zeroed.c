#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    size_t nmemb = 128;
    size_t size = 16;
    unsigned char *p = calloc(nmemb, size);
    if (!p) {
        return 1;
    }

    for (size_t i = 0; i < nmemb * size; i++) {
        if (p[i] != 0) {
            return 1;
        }
    }

    free(p);
    return 0;
}
