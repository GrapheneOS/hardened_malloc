#include <new>

struct alignas(8192) S {
    char x[9000];
};

int main() {
    S *p = new S;
    operator delete(p, sizeof(S), std::align_val_t(alignof(S)));
}
