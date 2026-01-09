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
    memcpy(firstbuffer, secondbuffer, 16);
    return 0;
}
