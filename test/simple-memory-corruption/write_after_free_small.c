#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(16);
    if (!p) {
        return 1;
    }
    free(p);
    memset(p, 'a', 16);
    return 0;
}
