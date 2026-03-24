#include <stdbool.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(0);
    char *q = malloc(0);
    return p != q;
}
