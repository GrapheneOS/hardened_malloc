#include <stdlib.h>
#include <string.h>

#include <unistd.h>

#include "util.h"

COLD noreturn void fatal_error(const char *s) {
    write(STDERR_FILENO, s, strlen(s));
    write(STDERR_FILENO, "\n", 1);
    abort();
}
