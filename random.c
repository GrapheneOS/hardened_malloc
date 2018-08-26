#include <errno.h>
#include <string.h>

#include "random.h"
#include "util.h"

#if __has_include(<sys/random.h>)
// glibc 2.25 and later
#include <sys/random.h>
#else
#include <unistd.h>
#include <sys/syscall.h>

static ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) {
    return syscall(SYS_getrandom, buf, buflen, flags);
}
#endif

#include "chacha.h"

static void get_random_seed(void *buf, size_t size) {
    while (size > 0) {
        ssize_t r;

        do {
            r = getrandom(buf, size, 0);
        } while (r == -1 && errno == EINTR);

        if (r <= 0) {
            fatal_error("getrandom failed");
        }

        buf = (char *)buf + r;
        size -= r;
    }
}

#define KEY_SIZE 32
#define IV_SIZE 8

void random_state_init(struct random_state *state) {
    uint8_t rnd[KEY_SIZE + IV_SIZE];
    get_random_seed(rnd, sizeof(rnd));
    chacha_keysetup(&state->ctx, rnd, KEY_SIZE * 8);
    chacha_ivsetup(&state->ctx, rnd + KEY_SIZE);
    chacha_keystream_bytes(&state->ctx, state->cache, RANDOM_CACHE_SIZE);
    state->index = 0;
    state->reseed = 0;
}

void get_random_bytes(struct random_state *state, void *buf, size_t size) {
    if (size > RANDOM_CACHE_SIZE / 2) {
        chacha_keystream_bytes(&state->ctx, state->cache, RANDOM_CACHE_SIZE);
        return;
    }

    while (size) {
        if (state->index == RANDOM_CACHE_SIZE) {
            if (state->reseed >= RANDOM_RESEED_SIZE) {
                random_state_init(state);
            } else {
                chacha_keystream_bytes(&state->ctx, state->cache, RANDOM_CACHE_SIZE);
                state->index = 0;
                state->reseed += RANDOM_CACHE_SIZE;
            }
        }
        size_t remaining = RANDOM_CACHE_SIZE - state->index;
        size_t copy_size = size < remaining ? size : remaining;
        memcpy(buf, state->cache + state->index, copy_size);
        state->index += copy_size;
        size -= copy_size;
    }
}

uint16_t get_random_u16(struct random_state *state) {
    uint16_t value;
    get_random_bytes(state, &value, sizeof(value));
    return value;
}

// based on OpenBSD arc4random_uniform
uint16_t get_random_u16_uniform(struct random_state *state, uint16_t bound) {
    if (bound < 2) {
        return 0;
    }

    uint16_t min = (uint16_t)-bound % bound;

    uint16_t r;
    do {
        r = get_random_u16(state);
    } while (r < min);

    return r % bound;
}

uint64_t get_random_u64(struct random_state *state) {
    uint64_t value;
    get_random_bytes(state, &value, sizeof(value));
    return value;
}

// based on OpenBSD arc4random_uniform
uint64_t get_random_u64_uniform(struct random_state *state, uint64_t bound) {
    if (bound < 2) {
        return 0;
    }

    uint64_t min = -bound % bound;

    uint64_t r;
    do {
        r = get_random_u64(state);
    } while (r < min);

    return r % bound;
}
