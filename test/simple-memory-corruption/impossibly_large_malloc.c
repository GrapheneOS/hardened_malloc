#include <stdlib.h>
#include <stddef.h>

#include "../test_util.h"

OPTNONE int main(void) {
    char *p = malloc(-8);
    return !(p == NULL);
}
