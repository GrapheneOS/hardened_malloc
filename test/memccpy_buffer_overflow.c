#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *firstbuffer = malloc(16);
    char *secondbuffer = malloc(32);
    if (!firstbuffer && !secondbuffer) {
        return 1;
    }
    memset(secondbuffer, 'a', 32);
    memccpy(firstbuffer, secondbuffer, 'b', 32);
    return 1;
}
