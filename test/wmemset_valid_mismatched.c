#include <stdlib.h>
#include <wchar.h>

#include "test_util.h"

OPTNONE int main(void) {
    wchar_t *buffer = malloc(32 * sizeof(wchar_t));
    if (!buffer) {
        return 1;
    }
    wmemset(buffer, L'\U0001F642', 16);
    return 0;
}
