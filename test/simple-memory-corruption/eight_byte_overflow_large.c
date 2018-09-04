#include <stdlib.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(128 * 1024);
    if (!p) {
        return 1;
    }
    *(p + 128 * 1024 + 7) = 0;
    free(p);
    return 0;
}
