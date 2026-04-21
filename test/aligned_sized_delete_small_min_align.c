#include "../include/h_malloc.h"

int main(void) {
    void *p = NULL;
    if (posix_memalign(&p, 16, 0) != 0) {
        return 1;
    }

    free_aligned_sized(p, 16, 0);
    return 0;
}
