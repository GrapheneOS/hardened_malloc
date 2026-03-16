#include <stdlib.h>

#include "test_util.h"

#pragma GCC diagnostic ignored "-Walloc-size-larger-than="

OPTNONE int main(void) {
    char *p = malloc(-8);
    return !(p == NULL);
}
