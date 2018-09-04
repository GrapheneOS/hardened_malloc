#include <stdlib.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(8);
    if (!p) {
        return 1;
    }
    *(p + 8 + 7) = 0;
    free(p);
    return 0;
}
