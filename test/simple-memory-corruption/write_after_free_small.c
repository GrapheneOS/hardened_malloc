#include <stdlib.h>
#include <string.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(128);
    if (!p) {
        return 1;
    }
    free(p);

    p[65] = 'a';

    // trigger reuse of the allocation
    for (size_t i = 0; i < 100000; i++) {
        free(malloc(128));
    }
    return 0;
}
