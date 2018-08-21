#include <errno.h>

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

void random_state_init(UNUSED struct random_state *state) {
}

// TODO: add ChaCha20-based CSPRNG, for now avoid using this other than during initialization...
void get_random_bytes(UNUSED struct random_state *state, void *buf, size_t size) {
    get_random_seed(buf, size);
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
