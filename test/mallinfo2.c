#include <stdio.h>
#include <stdlib.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include "test_util.h"

static void print_mallinfo2(void) {
#if defined(__GLIBC__)
#if __GLIBC_PREREQ(2, 33)
    struct mallinfo2 info = mallinfo2();
    printf("mallinfo2:\n");
    printf("arena: %zu\n", (size_t)info.arena);
    printf("ordblks: %zu\n", (size_t)info.ordblks);
    printf("smblks: %zu\n", (size_t)info.smblks);
    printf("hblks: %zu\n", (size_t)info.hblks);
    printf("hblkhd: %zu\n", (size_t)info.hblkhd);
    printf("usmblks: %zu\n", (size_t)info.usmblks);
    printf("fsmblks: %zu\n", (size_t)info.fsmblks);
    printf("uordblks: %zu\n", (size_t)info.uordblks);
    printf("fordblks: %zu\n", (size_t)info.fordblks);
    printf("keepcost: %zu\n", (size_t)info.keepcost);
#endif
#endif
}

OPTNONE int main(void) {
    void *a[4];

    a[0] = malloc(1024 * 1024 * 1024);
    a[1] = malloc(16);
    a[2] = malloc(32);
    a[3] = malloc(64);

    print_mallinfo2();

    free(a[0]);
    free(a[1]);
    free(a[2]);
    free(a[3]);

    printf("\n");
    print_mallinfo2();
}
