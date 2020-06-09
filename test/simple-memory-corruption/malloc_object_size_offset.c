#include <stdbool.h>
#include <malloc.h>

size_t malloc_object_size(void *ptr);

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(16);
    size_t size = malloc_object_size(p + 5);
    return size != (SLAB_CANARY ? 19 : 27);
}
