#include <pthread.h>
#include <stdio.h>

#if defined(__GLIBC__) || defined(__ANDROID__)
#include <malloc.h>
#endif

#include "test_util.h"
#include "../util.h"

OPTNONE static void leak_memory(void) {
    (void)!malloc(1024 * 1024 * 1024);
    (void)!malloc(16);
    (void)!malloc(32);
    (void)!malloc(4096);
}

static void *do_work(UNUSED void *p) {
    leak_memory();
    return NULL;
}

int main(void) {
    pthread_t thread[4];
    for (int i = 0; i < 4; i++) {
        pthread_create(&thread[i], NULL, do_work, NULL);
    }
    for (int i = 0; i < 4; i++) {
        pthread_join(thread[i], NULL);
    }

#if defined(__GLIBC__) || defined(__ANDROID__)
    malloc_info(0, stdout);
#endif
}
