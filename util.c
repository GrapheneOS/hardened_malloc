#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#ifdef __ANDROID__
#include <async_safe/log.h>
int mallopt(int param, int value);
#define M_BIONIC_RESTORE_DEFAULT_SIGABRT_HANDLER (-1003)
#endif

#include "util.h"

#ifndef __ANDROID__
static int write_full(int fd, const char *buf, size_t length) {
    do {
        ssize_t bytes_written = write(fd, buf, length);
        if (bytes_written == -1) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        buf += bytes_written;
        length -= bytes_written;
    } while (length);

    return 0;
}
#endif

COLD noreturn void fatal_error(const char *s) {
#ifdef __ANDROID__
    mallopt(M_BIONIC_RESTORE_DEFAULT_SIGABRT_HANDLER, 0);
    async_safe_fatal("hardened_malloc: fatal allocator error: %s", s);
#else
    const char *prefix = "fatal allocator error: ";
    (void)(write_full(STDERR_FILENO, prefix, strlen(prefix)) != -1 &&
        write_full(STDERR_FILENO, s, strlen(s)) != -1 &&
        write_full(STDERR_FILENO, "\n", 1));
    abort();
#endif
}
