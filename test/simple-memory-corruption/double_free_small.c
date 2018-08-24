#include <stdlib.h>

__attribute__((optimize(0)))
int main(void) {
    void *p = malloc(16);
    if (!p) {
        return 1;
    }
    free(p);
    free(p);
    return 0;
}
