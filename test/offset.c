#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static size_t size_classes[] = {
    /* large */ 4 * 1024 * 1024,
    /* 0 */ 0,
    /* 16 */ 16, 32, 48, 64, 80, 96, 112, 128,
    /* 32 */ 160, 192, 224, 256,
    /* 64 */ 320, 384, 448, 512,
    /* 128 */ 640, 768, 896, 1024,
    /* 256 */ 1280, 1536, 1792, 2048,
    /* 512 */ 2560, 3072, 3584, 4096,
    /* 1024 */ 5120, 6144, 7168, 8192,
    /* 2048 */ 10240, 12288, 14336, 16384,
#if CONFIG_EXTENDED_SIZE_CLASSES
    /* 4096 */ 20480, 24576, 28672, 32768,
    /* 8192 */ 40960, 49152, 57344, 65536,
    /* 16384 */ 81920, 98304, 114688, 131072,
#endif
};

#define N_SIZE_CLASSES (sizeof(size_classes) / sizeof(size_classes[0]))

static const size_t canary_size = SLAB_CANARY ? sizeof(uint64_t) : 0;

int main(void) {
    for (unsigned i = 2; i < N_SIZE_CLASSES; i++) {
        size_classes[i] -= canary_size;
    }

    void *p[N_SIZE_CLASSES];
    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        size_t size = size_classes[i];
        p[i] = malloc(size);
        if (!p[i]) {
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
