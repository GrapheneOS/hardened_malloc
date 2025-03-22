#include <stdlib.h>
#include <wchar.h>

#include "test_util.h"

OPTNONE int main(void) {
    wchar_t *firstbuffer = malloc(16 * sizeof(wchar_t));
    wchar_t *secondbuffer = malloc(32 * sizeof(wchar_t));
    if (!firstbuffer && !secondbuffer) {
        return 1;
    }
    wmemset(secondbuffer, L'\U0001F642', 32);
    wmemmove(firstbuffer, secondbuffer, 32);
    return 1;
}
