#include <errno.h>
#include <string.h>

#include "chacha.h"
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

static void get_random_seed(void *buf, size_t size) {
    while (size) {
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

void random_state_init(struct random_state *state) {
    u8 rnd[CHACHA_KEY_SIZE + CHACHA_IV_SIZE];
    get_random_seed(rnd, sizeof(rnd));
    chacha_keysetup(&state->ctx, rnd);
    chacha_ivsetup(&state->ctx, rnd + CHACHA_KEY_SIZE);
    chacha_keystream_bytes(&state->ctx, state->cache, RANDOM_CACHE_SIZE);
    state->index = 0;
    state->reseed = 0;
}

static void refill(struct random_state *state) {
    if (state->reseed < RANDOM_RESEED_SIZE) {
        chacha_keystream_bytes(&state->ctx, state->cache, RANDOM_CACHE_SIZE);
        state->index = 0;
        state->reseed += RANDOM_CACHE_SIZE;
    } else {
        random_state_init(state);
    }
}

void get_random_bytes(struct random_state *state, void *buf, size_t size) {
    // avoid needless copying to and from the cache as an optimization
    if (size > RANDOM_CACHE_SIZE / 2) {
        chacha_keystream_bytes(&state->ctx, buf, size);
        return;
    }

    while (size) {
        if (state->index == RANDOM_CACHE_SIZE) {
            refill(state);
        }

        size_t remaining = RANDOM_CACHE_SIZE - state->index;
        size_t copy_size = min(size, remaining);
        memcpy(buf, state->cache + state->index, copy_size);
        state->index += copy_size;

        buf = (char *)buf + copy_size;
        size -= copy_size;
    }
}

u16 get_random_u16(struct random_state *state) {
    u16 value;
    unsigned remaining = RANDOM_CACHE_SIZE - state->index;
    if (remaining < sizeof(value)) {
        refill(state);
    }
    memcpy(&value, state->cache + state->index, sizeof(value));
    state->index += sizeof(value);
    return value;
}

// See Fast Random Integer Generation in an Interval by Daniel Lemire
u16 get_random_u16_uniform(struct random_state *state, u16 bound) {
    u32 random = get_random_u16(state);
    u32 multiresult = random * bound;
    u16 leftover = multiresult;
    if (leftover < bound) {
        u16 threshold = -bound % bound;
        while (leftover < threshold) {
            random =  get_random_u16(state);
            multiresult = random * bound;
            leftover = (u16)multiresult;
        }
    }
    return multiresult >> 16;
}

u64 get_random_u64(struct random_state *state) {
    u64 value;
    unsigned remaining = RANDOM_CACHE_SIZE - state->index;
    if (remaining < sizeof(value)) {
        refill(state);
    }
    memcpy(&value, state->cache + state->index, sizeof(value));
    state->index += sizeof(value);
    return value;
}

// See Fast Random Integer Generation in an Interval by Daniel Lemire
u64 get_random_u64_uniform(struct random_state *state, u64 bound) {
    u128 random = get_random_u64(state);
    u128 multiresult = random * bound;
    u64 leftover = multiresult;
    if (leftover < bound) {
        u64 threshold = -bound % bound;
        while (leftover < threshold) {
            random =  get_random_u64(state);
            multiresult = random * bound;
            leftover = multiresult;
        }
    }
    return multiresult >> 64;
}
