#include "musl.h"

/* Copied from musl libc version 1.2.5 licensed under the MIT license */

#include <wchar.h>

wchar_t *musl_wmemset(wchar_t *d, wchar_t c, size_t n)
{
	wchar_t *ret = d;
	while (n--) *d++ = c;
	return ret;
}
