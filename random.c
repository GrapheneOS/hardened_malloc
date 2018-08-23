#include <errno.h>
#include <string.h>

#include <sys/random.h>

#include "random.h"
#include "util.h"

void get_random_seed(void *buf, size_t size) {
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
    state->index = RANDOM_CACHE_SIZE;
}

void get_random_bytes(struct random_state *state, void *buf, size_t size) {
    if (size > RANDOM_CACHE_SIZE / 2) {
        get_random_seed(buf, size);
        return;
    }

    while (size) {
        if (state->index == RANDOM_CACHE_SIZE) {
            state->index = 0;
            get_random_seed(state->cache, RANDOM_CACHE_SIZE);
        }
        size_t remaining = RANDOM_CACHE_SIZE - state->index;
        size_t copy_size = size < remaining ? size : remaining;
        memcpy(buf, state->cache + state->index, copy_size);
        state->index += copy_size;
        size -= copy_size;
    }
}

size_t get_random_size(struct random_state *state) {
    size_t size;
    get_random_bytes(state, &size, sizeof(size));
    return size;
}

// based on OpenBSD arc4random_uniform
size_t get_random_size_uniform(struct random_state *state, size_t bound) {
    if (bound < 2) {
        return 0;
    }

    size_t min = -bound % bound;

    size_t r;
    do {
        r = get_random_size(state);
    } while (r < min);

    return r % bound;
}
