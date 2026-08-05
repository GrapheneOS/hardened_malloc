#include "../include/h_malloc.h"

int main(void) {
    void *p = malloc(16);
    // alignment 3 is not a power of two
    free_aligned_sized(p, 3, 16);
    return 0;
}
