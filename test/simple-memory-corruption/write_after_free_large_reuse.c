#include <stdlib.h>
#include <string.h>

__attribute__((optimize(0)))
int main(void) {
    char *p = malloc(128 * 1024);
    if (!p) {
        return 1;
    }
    free(p);
    char *q = malloc(128 * 1024);
    p[64 * 1024 + 1] = 'a';
    return 0;
}
