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

void random_state_init(struct random_state *state) {
    uint8_t rnd[CHACHA_KEY_SIZE + CHACHA_IV_SIZE];
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

uint16_t get_random_u16(struct random_state *state) {
    uint16_t value;
    size_t remaining = RANDOM_CACHE_SIZE - state->index;
    if (remaining < sizeof(value)) {
        refill(state);
    }
    memcpy(&value, state->cache + state->index, sizeof(value));
    state->index += sizeof(value);
    return value;
}

// See Fast Random Integer Generation in an Interval by Daniel Lemire
uint16_t get_random_u16_uniform(struct random_state *state, uint16_t bound) {
    uint32_t random = get_random_u16(state);
    uint32_t multiresult = random * bound;
    uint16_t leftover = multiresult;
    if (leftover < bound) {
        uint16_t threshold = -bound % bound;
        while (leftover < threshold) {
            random =  get_random_u16(state);
            multiresult = random * bound;
            leftover = (uint16_t)multiresult;
        }
    }
    return multiresult >> 16;
}

uint64_t get_random_u64(struct random_state *state) {
    uint64_t value;
    size_t remaining = RANDOM_CACHE_SIZE - state->index;
    if (remaining < sizeof(value)) {
        refill(state);
    }
    memcpy(&value, state->cache + state->index, sizeof(value));
    state->index += sizeof(value);
    return value;
}

// See Fast Random Integer Generation in an Interval by Daniel Lemire
uint64_t get_random_u64_uniform(struct random_state *state, uint64_t bound) {
    unsigned __int128 random = get_random_u64(state);
    unsigned __int128 multiresult = random * bound;
    uint64_t leftover = multiresult;
    if (leftover < bound) {
        uint64_t threshold = -bound % bound;
        while (leftover < threshold) {
            random =  get_random_u64(state);
            multiresult = random * bound;
            leftover = multiresult;
        }
    }
    return multiresult >> 64;
}
