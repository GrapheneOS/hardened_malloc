#include <malloc.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    char *q = p + 4096 * 4;
    malloc_usable_size(q);
    return 0;
}
