#include <stdint.h>

#include "test_util.h"

struct foo {
    uint64_t a, b, c, d;
};

OPTNONE int main(void) {
    void *p = new char;
    struct foo *c = (struct foo *)p;
    delete c;
    return 0;
}
