#include <malloc.h>

#include "test_util.h"

OPTNONE int main(void) {
    malloc_usable_size((void *)1);
    return 0;
}
