#include <stdio.h>

#include <malloc.h>

#include "test_util.h"

static void print_mallinfo(void) {
    struct mallinfo info = mallinfo();
    printf("mallinfo:\n");
    printf("arena: %zu\n", info.arena);
    printf("ordblks: %zu\n", info.ordblks);
    printf("smblks: %zu\n", info.smblks);
    printf("hblks: %zu\n", info.hblks);
    printf("hblkhd: %zu\n", info.hblkhd);
    printf("usmblks: %zu\n", info.usmblks);
    printf("fsmblks: %zu\n", info.fsmblks);
    printf("uordblks: %zu\n", info.uordblks);
    printf("fordblks: %zu\n", info.fordblks);
    printf("keepcost: %zu\n", info.keepcost);
}

OPTNONE int main(void) {
    void *a[4];

    a[0] = malloc(1024 * 1024 * 1024);
    a[1] = malloc(16);
    a[2] = malloc(32);
    a[3] = malloc(64);

    print_mallinfo();

    free(a[0]);
    free(a[1]);
    free(a[2]);
    free(a[3]);

    printf("\n");
    print_mallinfo();
}
