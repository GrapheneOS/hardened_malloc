#pragma once

#include <stddef.h>
#include <sys/types.h>

void *musl_memcpy(void *dst, const void *src, size_t len);
void *musl_memccpy(void *restrict dest, const void *restrict src, int c, size_t n);
void *musl_memmove(void *dst, const void *src, size_t len);
void *musl_memset(void *dst, int value, size_t len);
void musl_swab(const void *_src, void *_dest, ssize_t n);
wchar_t *musl_wmemset(wchar_t *dst, wchar_t value, size_t len);
