#include <stdint.h>

struct foo {
    uint64_t a, b, c, d;
};

__attribute__((optimize(0)))
int main(void) {
    void *p = new char;
    struct foo *c = (struct foo *)p;
    delete c;
    return 0;
}
