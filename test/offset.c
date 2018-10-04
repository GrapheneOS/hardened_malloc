#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static const unsigned size_classes[] = {
    /* large */ 4 * 1024 * 1024,
    /* 0 */ 0,
    /* 16 */ 16, 32, 48, 64, 80, 96, 112, 128,
    /* 32 */ 160, 192, 224, 256,
    /* 64 */ 320, 384, 448, 512,
    /* 128 */ 640, 768, 896, 1024,
    /* 256 */ 1280, 1536, 1792, 2048,
    /* 512 */ 2560, 3072, 3584, 4096,
    /* 1024 */ 5120, 6144, 7168, 8192,
    /* 2048 */ 10240, 12288, 14336, 16384
};

#define N_SIZE_CLASSES (sizeof(size_classes) / sizeof(size_classes[0]))

static size_t canary_size = 8;

int main(void) {
    void *p[N_SIZE_CLASSES];
    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        unsigned size = size_classes[i];
        if (size) {
            size -= canary_size;
        }
        p[i] = malloc(size);
        if (!p) {
            return 1;
        }
        void *q = malloc(size);
        if (!q) {
            return 1;
        }
        if (i != 0) {
            printf("%zu to %zu: %zd\n", size_classes[i - 1], size, p[i] - p[i - 1]);
        }
        printf("%zu to %zu: %zd\n", size, size, q - p[i]);
    }
    return 0;
}
