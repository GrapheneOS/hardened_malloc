#include <stdlib.h>

__attribute__((optimize(0)))
int main(void) {
    void *p = malloc(128 * 1024);
    if (!p) {
        return 1;
    }
    void *q = malloc(128 * 1024);
    if (!q) {
        return 1;
    }
    free(p);
    free(q);
    free(p);
    return 0;
}
