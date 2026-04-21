#include <new>

struct alignas(64) S {
    char x[24];
};

int main() {
    S *p = new S;
    operator delete(p, sizeof(S) + 64, std::align_val_t(alignof(S)));
}
