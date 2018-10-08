#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>

#define WRITE_AFTER_FREE_CHECK true
#define SLOT_RANDOMIZE true
#define ZERO_ON_FREE true
#define SLAB_CANARY true
#define GUARD_SLABS_INTERVAL 1
#define GUARD_SIZE_DIVISOR 2
#define REGION_QUARANTINE_SIZE 1024
#define REGION_QUARANTINE_SKIP_THRESHOLD (32 * 1024 * 1024)

#endif
