#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

#include "chacha.h"

#define RANDOM_CACHE_SIZE 256ULL
#define RANDOM_RESEED_SIZE 256ULL * 1024

struct random_state {
    size_t index;
    size_t reseed;
    chacha_ctx ctx;
    uint8_t cache[RANDOM_CACHE_SIZE];
};

void random_state_init(struct random_state *state);
uint16_t get_random_u16(struct random_state *state);
uint16_t get_random_u16_uniform(struct random_state *state, uint16_t bound);
uint64_t get_random_u64(struct random_state *state);
uint64_t get_random_u64_uniform(struct random_state *state, uint64_t bound);

#endif
