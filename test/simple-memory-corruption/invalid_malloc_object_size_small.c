#include <malloc.h>

size_t malloc_object_size(void *ptr);

__attribute__((optimize(0)))
int main() {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    char *q = p + 4096 * 4;
    malloc_object_size(q);
    return 0;
}
