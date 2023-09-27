#include <pthread.h>
#include <stdlib.h>


static void* thread_func(void *arg) {
    arg = realloc(arg, 1024);
    if (!arg)
        exit(EXIT_FAILURE);

    free(arg);

    return NULL;
}

int main(void) {
    void *mem;
    pthread_t thread;
    int r;

    mem = realloc(NULL, 12);
    if (!mem)
        return EXIT_FAILURE;

    r = pthread_create(&thread, NULL, thread_func, mem);
    if (r != 0)
        return EXIT_FAILURE;

    r = pthread_join(thread, NULL);
    if (r != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
