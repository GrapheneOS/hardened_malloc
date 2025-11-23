#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *firstbuffer = malloc(16);
    char *secondbuffer = malloc(16);
    if (!firstbuffer && !secondbuffer) {
        return 1;
    }
    memset(secondbuffer, 'a', 16);
    memccpy(firstbuffer, secondbuffer, 'b', 16);
    return 0;
}
