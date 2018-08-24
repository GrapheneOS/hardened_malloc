#include <stdlib.h>

__attribute__((optimize(0)))
int main(void) {
    free((void *)1);
    return 0;
}
