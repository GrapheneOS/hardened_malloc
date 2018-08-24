#include <stdlib.h>

__attribute__((optimize(0)))
int main(void) {
    void *p = realloc((void *)1, 16);
    if (!p) {
        return 1;
    }
    return 0;
}
