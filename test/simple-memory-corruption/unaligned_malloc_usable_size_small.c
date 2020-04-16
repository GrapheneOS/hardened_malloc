#include <malloc.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    malloc_usable_size(p + 1);
    return 0;
}
