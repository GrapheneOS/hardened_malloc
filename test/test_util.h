#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#ifdef __clang__
#define OPTNONE __attribute__((optnone))
#else
#define OPTNONE __attribute__((optimize(0)))
#endif

#endif
