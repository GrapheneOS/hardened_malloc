#include <stdlib.h>
#include <string.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(4 * 1024 * 1024);
    if (!p) {
        return 1;
    }
    memset(p, 'a', 4 * 1024 * 1024);
    if (!realloc(p, 1024 * 1024)) {
        return 1;
    }
    // the discarded tail is guarded or quarantined, never still readable
    return p[2 * 1024 * 1024] == 'a' ? 0 : 1;
}
