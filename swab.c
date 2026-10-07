#include "musl.h"

/* Copied from musl libc version 1.2.5 licensed under the MIT license */

#include <unistd.h>

void musl_swab(const void *restrict _src, void *restrict _dest, ssize_t n)
{
       const char *src = _src;
       char *dest = _dest;
       for (; n>1; n-=2) {
               dest[0] = src[1];
               dest[1] = src[0];
               dest += 2;
               src += 2;
       }
}
