#include <malloc.h>

__attribute__((optimize(0)))
int main(void) {
    malloc_usable_size((void *)1);
    return 0;
}
