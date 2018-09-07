#ifndef MUTEX_H
#define MUTEX_H

#include <pthread.h>

#include "util.h"

struct mutex {
    pthread_mutex_t lock;
};

#define MUTEX_INITIALIZER (struct mutex){PTHREAD_MUTEX_INITIALIZER}

static inline void mutex_init(struct mutex *m) {
    if (unlikely(pthread_mutex_init(&m->lock, NULL))) {
        fatal_error("mutex initialization failed");
    }
}

static inline void mutex_lock(struct mutex *m) {
    pthread_mutex_lock(&m->lock);
}

static inline void mutex_unlock(struct mutex *m) {
    pthread_mutex_unlock(&m->lock);
}

#endif
