#include <malloc.h>

size_t malloc_object_size(void *ptr);

__attribute__((optimize(0)))
int main() {
    void *p = malloc(16);
    if (!p) {
        return 1;
    }
    free(p);
    malloc_object_size(p);
    return 0;
}
