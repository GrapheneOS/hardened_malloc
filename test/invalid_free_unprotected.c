#include <stdlib.h>

#include <sys/mman.h>

#include "test_util.h"

OPTNONE int main(void) {
    free(malloc(16));
    char *p = mmap(NULL, 4096 * 16, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        return 1;
    }
    free(p + 4096 * 8);
    return 0;
}
