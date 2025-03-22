#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *buffer = malloc(16);
    if (!buffer) {
        return 1;
    }
    memset(buffer, 'a', 32);
    return 1;
}
