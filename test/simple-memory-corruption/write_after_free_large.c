#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(128 * 1024);
    if (!p) {
        return 1;
    }
    free(p);
    memset(p, 'a', 128 * 1024);
    return 0;
}
