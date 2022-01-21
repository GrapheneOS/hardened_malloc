#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    free((void *)1);
    return 0;
}
