#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *firstbuffer = malloc(32);
    char *secondbuffer = malloc(16);
    if (!firstbuffer && !secondbuffer) {
        return 1;
    }
    memset(secondbuffer, 'a', 16);
    memmove(firstbuffer, secondbuffer, 32);
    return 1;
}
