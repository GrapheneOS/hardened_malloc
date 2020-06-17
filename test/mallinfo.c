#include <stdio.h>

#include <malloc.h>

#include "test_util.h"

OPTNONE int main(void) {
    malloc(1024 * 1024 * 1024);
    malloc(16);
    malloc(32);
    malloc(64);

    struct mallinfo info = mallinfo();
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
