#include <stdlib.h>
#include <stdio.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(0);
    if (!p) {
        return 1;
    }
    printf("%c\n", *p);
    return 0;
}
