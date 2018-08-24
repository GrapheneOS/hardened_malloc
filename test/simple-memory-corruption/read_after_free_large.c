#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(128 * 1024);
    if (!p) {
        return 1;
    }
    memset(p, 'a', 16);
    free(p);
    for (size_t i = 0; i < 128 * 1024; i++) {
        printf("%x\n", p[i]);
    }
    return 0;
}
