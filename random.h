#ifndef RANDOM_H
#define RANDOM_H

struct random_state {
    char unused;
};

void get_random_seed(void *buf, size_t size);
void random_state_init(struct random_state *state);
void get_random_bytes(struct random_state *state, void *buf, size_t size);
size_t get_random_size(struct random_state *state);
size_t get_random_size_uniform(struct random_state *state, size_t bound);

#endif
