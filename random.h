#ifndef RANDOM_H
#define RANDOM_H

#include <stdint.h>

#define RANDOM_CACHE_SIZE 4096

struct random_state {
    size_t index;
    uint8_t cache[RANDOM_CACHE_SIZE];
};

void random_state_init(struct random_state *state);
void get_random_bytes(struct random_state *state, void *buf, size_t size);
uint16_t get_random_u16(struct random_state *state);
uint16_t get_random_u16_uniform(struct random_state *state, uint16_t bound);
uint64_t get_random_u64(struct random_state *state);
uint64_t get_random_u64_uniform(struct random_state *state, uint64_t bound);

#endif
