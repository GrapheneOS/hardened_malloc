#ifndef RANDOM_H
#define RANDOM_H

#include "chacha.h"
#include "util.h"

#define RANDOM_CACHE_SIZE 256U
#define RANDOM_RESEED_SIZE (256U * 1024)

struct random_state {
    unsigned index;
    unsigned reseed;
    chacha_ctx ctx;
    u8 cache[RANDOM_CACHE_SIZE];
};

void random_state_init(struct random_state *state);
void random_state_init_from_random_state(struct random_state *state, struct random_state *source);
void get_random_bytes(struct random_state *state, void *buf, size_t size);
u16 get_random_u16(struct random_state *state);
u16 get_random_u16_uniform(struct random_state *state, u16 bound);
u64 get_random_u64(struct random_state *state);
u64 get_random_u64_uniform(struct random_state *state, u64 bound);

#endif
