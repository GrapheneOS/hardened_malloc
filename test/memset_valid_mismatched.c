#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *buffer = malloc(32);
    if (!buffer) {
        return 1;
    }
    memset(buffer, 'a', 16);
    return 0;
}
