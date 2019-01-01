#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <threads.h>

#include <malloc.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "third_party/libdivide.h"

#include "h_malloc.h"
#include "memory.h"
#include "mutex.h"
#include "pages.h"
#include "random.h"
#include "util.h"

#define SLAB_QUARANTINE (SLAB_QUARANTINE_RANDOM_LENGTH > 0 || SLAB_QUARANTINE_QUEUE_LENGTH > 0)
#define REGION_QUARANTINE (REGION_QUARANTINE_RANDOM_LENGTH > 0 || REGION_QUARANTINE_QUEUE_LENGTH > 0)
#define MREMAP_MOVE_THRESHOLD (32 * 1024 * 1024)

static_assert(sizeof(void *) == 8, "64-bit only");

static_assert(!WRITE_AFTER_FREE_CHECK || ZERO_ON_FREE, "WRITE_AFTER_FREE_CHECK depends on ZERO_ON_FREE");

static_assert(SLAB_QUARANTINE_RANDOM_LENGTH >= 0 && SLAB_QUARANTINE_RANDOM_LENGTH <= 65536,
    "invalid slab quarantine random length");
static_assert(SLAB_QUARANTINE_QUEUE_LENGTH >= 0 && SLAB_QUARANTINE_QUEUE_LENGTH <= 65536,
    "invalid slab quarantine queue length");
static_assert(REGION_QUARANTINE_RANDOM_LENGTH >= 0 && REGION_QUARANTINE_RANDOM_LENGTH <= 65536,
    "invalid region quarantine random length");
static_assert(REGION_QUARANTINE_QUEUE_LENGTH >= 0 && REGION_QUARANTINE_QUEUE_LENGTH <= 65536,
    "invalid region quarantine queue length");
static_assert(FREE_SLABS_QUARANTINE_RANDOM_LENGTH >= 0 && FREE_SLABS_QUARANTINE_RANDOM_LENGTH <= 65536,
    "invalid free slabs quarantine random length");

static_assert(GUARD_SLABS_INTERVAL >= 1, "invalid guard slabs interval (minimum 1)");
static_assert(GUARD_SIZE_DIVISOR >= 1, "invalid guard size divisor (minimum 1)");
static_assert(CONFIG_CLASS_REGION_SIZE >= 1048576, "invalid class region size (minimum 1048576)");
static_assert(CONFIG_CLASS_REGION_SIZE <= 1099511627776, "invalid class region size (maximum 1099511627776)");
static_assert(REGION_QUARANTINE_SKIP_THRESHOLD >= 0,
    "invalid region quarantine skip threshold (minimum 0)");
static_assert(MREMAP_MOVE_THRESHOLD >= REGION_QUARANTINE_SKIP_THRESHOLD,
    "mremap move threshold must be above region quarantine limit");

// either sizeof(u64) or 0
static const size_t canary_size = SLAB_CANARY ? sizeof(u64) : 0;

static_assert(N_ARENA >= 1, "must have at least 1 arena");
static_assert(N_ARENA <= 256, "maximum number of arenas is currently 256");
#define CACHELINE_SIZE 64

#if N_ARENA > 1
__attribute__((tls_model("initial-exec")))
static thread_local unsigned thread_arena = N_ARENA;
static atomic_uint thread_arena_counter = 0;
#else
static const unsigned thread_arena = 0;
#endif

static union {
    struct {
        void *slab_region_start;
        void *_Atomic slab_region_end;
        struct size_class *size_class_metadata[N_ARENA];
        struct region_allocator *region_allocator;
        struct region_metadata *regions[2];
#ifdef USE_PKEY
        int metadata_pkey;
#endif
        bool zero_on_free;
        bool purge_slabs;
        bool region_quarantine_protect;
    };
    char padding[PAGE_SIZE];
} ro __attribute__((aligned(PAGE_SIZE)));

static inline void *get_slab_region_end() {
    return atomic_load_explicit(&ro.slab_region_end, memory_order_acquire);
}

#define SLAB_METADATA_COUNT

struct slab_metadata {
    u64 bitmap[4];
    struct slab_metadata *next;
    struct slab_metadata *prev;
    u64 canary_value;
#ifdef SLAB_METADATA_COUNT
    u16 count;
#endif
#if SLAB_QUARANTINE
    u64 quarantine_bitmap[4];
#endif
};

static const size_t min_align = 16;
#define MIN_SLAB_SIZE_CLASS_SHIFT 4

// set slab cache size based on the size of the largest slab
#if !CONFIG_EXTENDED_SIZE_CLASSES
static const size_t MAX_SLAB_SIZE_CLASS = 65536;
#define MAX_SLAB_SIZE_CLASS_SHIFT 14
#else
static const size_t MAX_SLAB_SIZE_CLASS = 131072;
#define MAX_SLAB_SIZE_CLASS_SHIFT 17
#endif

static const u32 size_classes[] = {
    /* 0 */ 0,
    /* 16 */ 16, 32, 48, 64, 80, 96, 112, 128,
    /* 32 */ 160, 192, 224, 256,
    /* 64 */ 320, 384, 448, 512,
    /* 128 */ 640, 768, 896, 1024,
    /* 256 */ 1280, 1536, 1792, 2048,
    /* 512 */ 2560, 3072, 3584, 4096,
    /* 1024 */ 5120, 6144, 7168, 8192,
    /* 2048 */ 10240, 12288, 14336, 16384,
#if CONFIG_EXTENDED_SIZE_CLASSES
    /* 4096 */ 20480, 24576, 28672, 32768,
    /* 8192 */ 40960, 49152, 57344, 65536,
    /* 16384 */ 81920, 98304, 114688, 131072,
#endif
};

static const u16 size_class_slots[] = {
    /* 0 */ 256,
    /* 16 */ 256, 128, 85, 64, 51, 42, 36, 64,
    /* 32 */ 51, 64, 54, 64,
    /* 64 */ 64, 64, 64, 64,
    /* 128 */ 64, 64, 64, 64,
    /* 256 */ 16, 16, 16, 16,
    /* 512 */ 8, 8, 8, 8,
    /* 1024 */ 8, 8, 8, 8,
    /* 2048 */ 6, 5, 4, 4,
#if CONFIG_EXTENDED_SIZE_CLASSES
    /* 4096 */ 2, 2, 2, 2,
    /* 8192 */ 1, 1, 1, 1,
    /* 16384 */ 1, 1, 1, 1,
#endif
};

static const char *const size_class_labels[] = {
    /* 0 */ "malloc 0",
    /* 16 */ "malloc 16", "malloc 32", "malloc 48", "malloc 64",
    /* 16 */ "malloc 80", "malloc 96", "malloc 112", "malloc 128",
    /* 32 */ "malloc 160", "malloc 192", "malloc 224", "malloc 256",
    /* 64 */ "malloc 320", "malloc 384", "malloc 448", "malloc 512",
    /* 128 */ "malloc 640", "malloc 768", "malloc 896", "malloc 1024",
    /* 256 */ "malloc 1280", "malloc 1536", "malloc 1792", "malloc 2048",
    /* 512 */ "malloc 2560", "malloc 3072", "malloc 3584", "malloc 4096",
    /* 1024 */ "malloc 5120", "malloc 6144", "malloc 7168", "malloc 8192",
    /* 2048 */ "malloc 10240", "malloc 12288", "malloc 14336", "malloc 16384",
#if CONFIG_EXTENDED_SIZE_CLASSES
    /* 4096 */ "malloc 20480", "malloc 24576", "malloc 28672", "malloc 32768",
    /* 8192 */ "malloc 40960", "malloc 49152", "malloc 57344", "malloc 65536",
    /* 16384 */ "malloc 81920", "malloc 98304", "malloc 114688", "malloc 131072",
#endif
};

static void label_slab(void *slab, size_t slab_size, unsigned class) {
    memory_set_name(slab, slab_size, size_class_labels[class]);
}

#define N_SIZE_CLASSES (sizeof(size_classes) / sizeof(size_classes[0]))

struct size_info {
    size_t size;
    size_t class;
};

static inline struct size_info get_size_info(size_t size) {
    if (size == 0) {
        return (struct size_info){0, 0};
    }
    if (size <= 128) {
        return (struct size_info){(size + 15) & ~15, ((size - 1) >> 4) + 1};
    }
    for (unsigned class = 9; class < N_SIZE_CLASSES; class++) {
        size_t real_size = size_classes[class];
        if (size <= real_size) {
            return (struct size_info){real_size, class};
        }
    }
    fatal_error("invalid size for slabs");
}

// alignment must be a power of 2 <= PAGE_SIZE since slabs are only page aligned
static inline struct size_info get_size_info_align(size_t size, size_t alignment) {
    for (unsigned class = 1; class < N_SIZE_CLASSES; class++) {
        size_t real_size = size_classes[class];
        if (size <= real_size && !(real_size & (alignment - 1))) {
            return (struct size_info){real_size, class};
        }
    }
    fatal_error("invalid size for slabs");
}

static size_t get_slab_size(size_t slots, size_t size) {
    return PAGE_CEILING(slots * size);
}

// limit on the number of cached empty slabs before attempting purging instead
static const size_t max_empty_slabs_total = MAX_SLAB_SIZE_CLASS;

struct __attribute__((aligned(CACHELINE_SIZE))) size_class {
    struct mutex lock;

    void *class_region_start;
    struct slab_metadata *slab_info;
    struct libdivide_u32_t size_divisor;
    struct libdivide_u64_t slab_size_divisor;

#if SLAB_QUARANTINE_RANDOM_LENGTH > 0
    void *quarantine_random[SLAB_QUARANTINE_RANDOM_LENGTH << (MAX_SLAB_SIZE_CLASS_SHIFT - MIN_SLAB_SIZE_CLASS_SHIFT)];
#endif

#if SLAB_QUARANTINE_QUEUE_LENGTH > 0
    void *quarantine_queue[SLAB_QUARANTINE_QUEUE_LENGTH << (MAX_SLAB_SIZE_CLASS_SHIFT - MIN_SLAB_SIZE_CLASS_SHIFT)];
    size_t quarantine_queue_index;
#endif

    // slabs with at least one allocated slot and at least one free slot
    //
    // LIFO doubly-linked list
    struct slab_metadata *partial_slabs;

    // slabs without allocated slots that are cached for near-term usage
    //
    // LIFO singly-linked list
    struct slab_metadata *empty_slabs;
    size_t empty_slabs_total; // length * slab_size

    // slabs without allocated slots that are purged and memory protected
    //
    // FIFO singly-linked list
    struct slab_metadata *free_slabs_head;
    struct slab_metadata *free_slabs_tail;
    struct slab_metadata *free_slabs_quarantine[FREE_SLABS_QUARANTINE_RANDOM_LENGTH];

#if CONFIG_STATS
    u64 nmalloc; // may wrap (per jemalloc API)
    u64 ndalloc; // may wrap (per jemalloc API)
    size_t allocated;
    size_t slab_allocated;
#endif

    struct random_state rng;
    size_t metadata_allocated;
    size_t metadata_count;
    size_t metadata_count_unguarded;
};

#define CLASS_REGION_SIZE (size_t)CONFIG_CLASS_REGION_SIZE
#define REAL_CLASS_REGION_SIZE (CLASS_REGION_SIZE * 2)
#define ARENA_SIZE (REAL_CLASS_REGION_SIZE * N_SIZE_CLASSES)
static const size_t slab_region_size = ARENA_SIZE * N_ARENA;
static_assert(PAGE_SIZE == 4096, "bitmap handling will need adjustment for other page sizes");

static void *get_slab(struct size_class *c, size_t slab_size, struct slab_metadata *metadata) {
    size_t index = metadata - c->slab_info;
    return (char *)c->class_region_start + (index * slab_size);
}

#define MAX_METADATA_MAX (CLASS_REGION_SIZE / PAGE_SIZE)

static size_t get_metadata_max(size_t slab_size) {
    return CLASS_REGION_SIZE / slab_size;
}

static struct slab_metadata *alloc_metadata(struct size_class *c, size_t slab_size, bool non_zero_size) {
    if (unlikely(c->metadata_count >= c->metadata_allocated)) {
        size_t metadata_max = get_metadata_max(slab_size);
        if (c->metadata_count >= metadata_max) {
            errno = ENOMEM;
            return NULL;
        }
        size_t allocate = max(c->metadata_allocated * 2, PAGE_SIZE / sizeof(struct slab_metadata));
        if (allocate > metadata_max) {
            allocate = metadata_max;
        }
        if (memory_protect_rw_metadata(c->slab_info, allocate * sizeof(struct slab_metadata))) {
            return NULL;
        }
        c->metadata_allocated = allocate;
    }

    struct slab_metadata *metadata = c->slab_info + c->metadata_count;
    void *slab = get_slab(c, slab_size, metadata);
    if (non_zero_size && memory_protect_rw(slab, slab_size)) {
        return NULL;
    }
    c->metadata_count++;
    c->metadata_count_unguarded++;
    if (c->metadata_count_unguarded >= GUARD_SLABS_INTERVAL) {
        c->metadata_count++;
        c->metadata_count_unguarded = 0;
    }
    return metadata;
}

static void set_slot(struct slab_metadata *metadata, size_t index) {
    size_t bucket = index / 64;
    metadata->bitmap[bucket] |= 1UL << (index - bucket * 64);
#ifdef SLAB_METADATA_COUNT
    metadata->count++;
#endif
}

static void clear_slot(struct slab_metadata *metadata, size_t index) {
    size_t bucket = index / 64;
    metadata->bitmap[bucket] &= ~(1UL << (index - bucket * 64));
#ifdef SLAB_METADATA_COUNT
    metadata->count--;
#endif
}

static bool get_slot(struct slab_metadata *metadata, size_t index) {
    size_t bucket = index / 64;
    return (metadata->bitmap[bucket] >> (index - bucket * 64)) & 1UL;
}

#if SLAB_QUARANTINE
static void set_quarantine(struct slab_metadata *metadata, size_t index) {
    size_t bucket = index / 64;
    metadata->quarantine_bitmap[bucket] |= 1UL << (index - bucket * 64);
}

static void clear_quarantine(struct slab_metadata *metadata, size_t index) {
    size_t bucket = index / 64;
    metadata->quarantine_bitmap[bucket] &= ~(1UL << (index - bucket * 64));
}

static bool get_quarantine(struct slab_metadata *metadata, size_t index) {
    size_t bucket = index / 64;
    return (metadata->quarantine_bitmap[bucket] >> (index - bucket * 64)) & 1UL;
}
#endif

static u64 get_mask(size_t slots) {
    return slots < 64 ? ~0UL << slots : 0;
}

static size_t get_free_slot(struct random_state *rng, size_t slots, struct slab_metadata *metadata) {
    if (SLOT_RANDOMIZE) {
        // randomize start location for linear search (uniform random choice is too slow)
        unsigned random_index = get_random_u16_uniform(rng, slots);
        unsigned first_bitmap = random_index / 64;
        u64 random_split = ~(~0UL << (random_index - first_bitmap * 64));

        unsigned i = first_bitmap;
        u64 masked = metadata->bitmap[i];
        masked |= random_split;
        for (;;) {
            if (i == slots / 64) {
                masked |= get_mask(slots - i * 64);
            }

            if (masked != ~0UL) {
                return ffzl(masked) - 1 + i * 64;
            }

            i = i == (slots - 1) / 64 ? 0 : i + 1;
            masked = metadata->bitmap[i];
        }
    } else {
        for (unsigned i = 0; i <= (slots - 1) / 64; i++) {
            u64 masked = metadata->bitmap[i];
            if (i == (slots - 1) / 64) {
                masked |= get_mask(slots - i * 64);
            }

            if (masked != ~0UL) {
                return ffzl(masked) - 1 + i * 64;
            }
        }
    }

    fatal_error("no zero bits");
}

static bool has_free_slots(size_t slots, struct slab_metadata *metadata) {
#ifdef SLAB_METADATA_COUNT
    return metadata->count < slots;
#else
    if (slots <= 64) {
        u64 masked = metadata->bitmap[0] | get_mask(slots);
        return masked != ~0UL;
    }
    if (slots <= 128) {
        u64 masked = metadata->bitmap[1] | get_mask(slots - 64);
        return metadata->bitmap[0] != ~0UL || masked != ~0UL;
    }
    if (slots <= 192) {
        u64 masked = metadata->bitmap[2] | get_mask(slots - 128);
        return metadata->bitmap[0] != ~0UL || metadata->bitmap[1] != ~0UL || masked != ~0UL;
    }
    u64 masked = metadata->bitmap[3] | get_mask(slots - 192);
    return metadata->bitmap[0] != ~0UL || metadata->bitmap[1] != ~0UL || metadata->bitmap[2] != ~0UL || masked != ~0UL;
#endif
}

static bool is_free_slab(struct slab_metadata *metadata) {
#ifdef SLAB_METADATA_COUNT
    return !metadata->count;
#else
    return !metadata->bitmap[0] && !metadata->bitmap[1] && !metadata->bitmap[2] &&
        !metadata->bitmap[3];
#endif
}

static struct slab_metadata *get_metadata(struct size_class *c, const void *p) {
    size_t offset = (const char *)p - (const char *)c->class_region_start;
    size_t index = libdivide_u64_do(offset, &c->slab_size_divisor);
    // still caught without this check either as a read access violation or "double free"
    if (index >= c->metadata_allocated) {
        fatal_error("invalid free within a slab yet to be used");
    }
    return c->slab_info + index;
}

static void *slot_pointer(size_t size, void *slab, size_t slot) {
    return (char *)slab + slot * size;
}

static void write_after_free_check(const char *p, size_t size) {
    if (!WRITE_AFTER_FREE_CHECK || !ro.zero_on_free) {
        return;
    }

    for (size_t i = 0; i < size; i += sizeof(u64)) {
        if (*(const u64 *)(const void *)(p + i)) {
            fatal_error("detected write after free");
        }
    }
}

static const u64 canary_mask = __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__ ?
    0xffffffffffffff00UL :
    0x00ffffffffffffffUL;

static void set_canary(struct slab_metadata *metadata, void *p, size_t size) {
    memcpy((char *)p + size - canary_size, &metadata->canary_value, canary_size);
}

static u64 get_random_canary(struct random_state *rng) {
    return get_random_u64(rng) & canary_mask;
}

static inline void stats_small_allocate(UNUSED struct size_class *c, UNUSED size_t size) {
#if CONFIG_STATS
    c->allocated += size;
    c->nmalloc++;
#endif
}

static inline void stats_small_deallocate(UNUSED struct size_class *c, UNUSED size_t size) {
#if CONFIG_STATS
    c->allocated -= size;
    c->ndalloc++;
#endif
}

static inline void stats_slab_allocate(UNUSED struct size_class *c, UNUSED size_t slab_size) {
#if CONFIG_STATS
    c->slab_allocated += slab_size;
#endif
}

static inline void stats_slab_deallocate(UNUSED struct size_class *c, UNUSED size_t slab_size) {
#if CONFIG_STATS
    c->slab_allocated -= slab_size;
#endif
}

static inline void *allocate_small(unsigned arena, size_t requested_size) {
    struct size_info info = get_size_info(requested_size);
    size_t size = info.size ? info.size : 16;

    struct size_class *c = &ro.size_class_metadata[arena][info.class];
    size_t slots = size_class_slots[info.class];
    size_t slab_size = get_slab_size(slots, size);

    mutex_lock(&c->lock);

    if (c->partial_slabs == NULL) {
        if (c->empty_slabs != NULL) {
            struct slab_metadata *metadata = c->empty_slabs;
            c->empty_slabs = c->empty_slabs->next;
            c->empty_slabs_total -= slab_size;

            metadata->next = NULL;
            metadata->prev = NULL;

            c->partial_slabs = slots > 1 ? metadata : NULL;

            void *slab = get_slab(c, slab_size, metadata);
            size_t slot = get_free_slot(&c->rng, slots, metadata);
            set_slot(metadata, slot);
            void *p = slot_pointer(size, slab, slot);
            if (requested_size) {
                write_after_free_check(p, size - canary_size);
                set_canary(metadata, p, size);
            }
            stats_small_allocate(c, size);

            mutex_unlock(&c->lock);
            return p;
        }

        if (c->free_slabs_head != NULL) {
            struct slab_metadata *metadata = c->free_slabs_head;
            metadata->canary_value = get_random_canary(&c->rng);

            void *slab = get_slab(c, slab_size, metadata);
            if (requested_size && memory_protect_rw(slab, slab_size)) {
                mutex_unlock(&c->lock);
                return NULL;
            }

            c->free_slabs_head = c->free_slabs_head->next;
            if (c->free_slabs_head == NULL) {
                c->free_slabs_tail = NULL;
            }

            metadata->next = NULL;
            metadata->prev = NULL;

            c->partial_slabs = slots > 1 ? metadata : NULL;

            size_t slot = get_free_slot(&c->rng, slots, metadata);
            set_slot(metadata, slot);
            void *p = slot_pointer(size, slab, slot);
            if (requested_size) {
                set_canary(metadata, p, size);
            }
            stats_slab_allocate(c, slab_size);
            stats_small_allocate(c, size);

            mutex_unlock(&c->lock);
            return p;
        }

        struct slab_metadata *metadata = alloc_metadata(c, slab_size, requested_size);
        if (unlikely(metadata == NULL)) {
            mutex_unlock(&c->lock);
            return NULL;
        }
        metadata->canary_value = get_random_canary(&c->rng);

        c->partial_slabs = slots > 1 ? metadata : NULL;
        void *slab = get_slab(c, slab_size, metadata);
        size_t slot = get_free_slot(&c->rng, slots, metadata);
        set_slot(metadata, slot);
        void *p = slot_pointer(size, slab, slot);
        if (requested_size) {
            set_canary(metadata, p, size);
        }
        stats_slab_allocate(c, slab_size);
        stats_small_allocate(c, size);

        mutex_unlock(&c->lock);
        return p;
    }

    struct slab_metadata *metadata = c->partial_slabs;
    size_t slot = get_free_slot(&c->rng, slots, metadata);
    set_slot(metadata, slot);

    if (!has_free_slots(slots, metadata)) {
        c->partial_slabs = c->partial_slabs->next;
        if (c->partial_slabs) {
            c->partial_slabs->prev = NULL;
        }
    }

    void *slab = get_slab(c, slab_size, metadata);
    void *p = slot_pointer(size, slab, slot);
    if (requested_size) {
        write_after_free_check(p, size - canary_size);
        set_canary(metadata, p, size);
    }
    stats_small_allocate(c, size);

    mutex_unlock(&c->lock);
    return p;
}

struct slab_size_class_info {
    unsigned arena;
    size_t class;
};

static struct slab_size_class_info slab_size_class(const void *p) {
    size_t offset = (const char *)p - (const char *)ro.slab_region_start;
    unsigned arena = 0;
    if (N_ARENA > 1) {
        arena = offset / ARENA_SIZE;
        offset -= arena * ARENA_SIZE;
    }
    return (struct slab_size_class_info){arena, offset / REAL_CLASS_REGION_SIZE};
}

static size_t slab_usable_size(const void *p) {
    return size_classes[slab_size_class(p).class];
}

static void enqueue_free_slab(struct size_class *c, struct slab_metadata *metadata) {
    metadata->next = NULL;

    static_assert(FREE_SLABS_QUARANTINE_RANDOM_LENGTH < (u16)-1, "free slabs quarantine too large");
    size_t index = get_random_u16_uniform(&c->rng, FREE_SLABS_QUARANTINE_RANDOM_LENGTH);
    struct slab_metadata *substitute = c->free_slabs_quarantine[index];
    c->free_slabs_quarantine[index] = metadata;

    if (substitute == NULL) {
        return;
    }

    if (c->free_slabs_tail != NULL) {
        c->free_slabs_tail->next = substitute;
    } else {
        c->free_slabs_head = substitute;
    }
    c->free_slabs_tail = substitute;
}

static inline void deallocate_small(void *p, const size_t *expected_size) {
    struct slab_size_class_info size_class_info = slab_size_class(p);
    size_t class = size_class_info.class;

    struct size_class *c = &ro.size_class_metadata[size_class_info.arena][class];
    size_t size = size_classes[class];
    if (expected_size && size != *expected_size) {
        fatal_error("sized deallocation mismatch (small)");
    }
    bool is_zero_size = size == 0;
    if (is_zero_size) {
        size = 16;
    }
    size_t slots = size_class_slots[class];
    size_t slab_size = get_slab_size(slots, size);

    mutex_lock(&c->lock);

    stats_small_deallocate(c, size);

    struct slab_metadata *metadata = get_metadata(c, p);
    void *slab = get_slab(c, slab_size, metadata);
    size_t slot = libdivide_u32_do((char *)p - (char *)slab, &c->size_divisor);

    if (slot_pointer(size, slab, slot) != p) {
        fatal_error("invalid unaligned free");
    }

    if (!get_slot(metadata, slot)) {
        fatal_error("double free");
    }

    if (!is_zero_size) {
        if (canary_size) {
            u64 canary_value;
            memcpy(&canary_value, (char *)p + size - canary_size, canary_size);
            if (unlikely(canary_value != metadata->canary_value)) {
                fatal_error("canary corrupted");
            }
        }

        if (ro.zero_on_free) {
            memset(p, 0, size - canary_size);
        }
    }

#if SLAB_QUARANTINE
    if (get_quarantine(metadata, slot)) {
        fatal_error("double free (quarantine)");
    }

    set_quarantine(metadata, slot);

    size_t quarantine_shift = __builtin_clzl(size) - (63 - MAX_SLAB_SIZE_CLASS_SHIFT);

#if SLAB_QUARANTINE_RANDOM_LENGTH > 0
    size_t slab_quarantine_random_length = SLAB_QUARANTINE_RANDOM_LENGTH << quarantine_shift;

    size_t random_index = get_random_u16_uniform(&c->rng, slab_quarantine_random_length);
    void *random_substitute = c->quarantine_random[random_index];
    c->quarantine_random[random_index] = p;

    if (random_substitute == NULL) {
        mutex_unlock(&c->lock);
        return;
    }

    p = random_substitute;
#endif

#if SLAB_QUARANTINE_QUEUE_LENGTH > 0
    size_t slab_quarantine_queue_length = SLAB_QUARANTINE_QUEUE_LENGTH << quarantine_shift;

    void *queue_substitute = c->quarantine_queue[c->quarantine_queue_index];
    c->quarantine_queue[c->quarantine_queue_index] = p;
    c->quarantine_queue_index = (c->quarantine_queue_index + 1) % slab_quarantine_queue_length;

    if (queue_substitute == NULL) {
        mutex_unlock(&c->lock);
        return;
    }

    p = queue_substitute;
#endif

    metadata = get_metadata(c, p);
    slab = get_slab(c, slab_size, metadata);
    slot = libdivide_u32_do((char *)p - (char *)slab, &c->size_divisor);

    clear_quarantine(metadata, slot);
#endif

    // triggered even for slots == 1 and then undone below
    if (!has_free_slots(slots, metadata)) {
        metadata->next = c->partial_slabs;
        metadata->prev = NULL;

        if (c->partial_slabs) {
            c->partial_slabs->prev = metadata;
        }
        c->partial_slabs = metadata;
    }

    clear_slot(metadata, slot);

    if (is_free_slab(metadata)) {
        if (metadata->prev) {
            metadata->prev->next = metadata->next;
        } else {
            c->partial_slabs = metadata->next;
        }
        if (metadata->next) {
            metadata->next->prev = metadata->prev;
        }

        metadata->prev = NULL;

        if (c->empty_slabs_total + slab_size > max_empty_slabs_total) {
            if (ro.purge_slabs && !memory_map_fixed(slab, slab_size)) {
                label_slab(slab, slab_size, class);
                stats_slab_deallocate(c, slab_size);
                enqueue_free_slab(c, metadata);
                mutex_unlock(&c->lock);
                return;
            }
            // handle out-of-memory by just putting it into the empty slabs list
        }

        metadata->next = c->empty_slabs;
        c->empty_slabs = metadata;
        c->empty_slabs_total += slab_size;
    }

    mutex_unlock(&c->lock);
}

struct region_metadata {
    void *p;
    size_t size;
    size_t guard_size;
};

struct quarantine_info {
    void *p;
    size_t size;
};

#define INITIAL_REGION_TABLE_SIZE 128
#define MAX_REGION_TABLE_SIZE (CLASS_REGION_SIZE / PAGE_SIZE / sizeof(struct region_metadata))

struct region_allocator {
    struct mutex lock;
    struct region_metadata *regions;
    size_t total;
    size_t free;
#if CONFIG_STATS
    size_t allocated;
#endif
#if REGION_QUARANTINE_RANDOM_LENGTH
    struct quarantine_info quarantine_random[REGION_QUARANTINE_RANDOM_LENGTH];
#endif
#if REGION_QUARANTINE_QUEUE_LENGTH
    struct quarantine_info quarantine_queue[REGION_QUARANTINE_QUEUE_LENGTH];
    size_t quarantine_queue_index;
#endif
    struct random_state rng;
};

static inline void stats_large_allocate(UNUSED struct region_allocator *ra, UNUSED size_t size) {
#if CONFIG_STATS
    ra->allocated += size;
#endif
}

static inline void stats_large_deallocate(UNUSED struct region_allocator *ra, UNUSED size_t size) {
#if CONFIG_STATS
    ra->allocated -= size;
#endif
}

struct __attribute__((aligned(PAGE_SIZE))) slab_info_mapping {
    struct slab_metadata slab_info[MAX_METADATA_MAX];
};

struct __attribute__((aligned(PAGE_SIZE))) allocator_state {
    struct size_class size_class_metadata[N_ARENA][N_SIZE_CLASSES];
    struct region_allocator region_allocator;
    // padding until next page boundary for mprotect
    struct region_metadata regions_a[MAX_REGION_TABLE_SIZE] __attribute__((aligned(PAGE_SIZE)));
    // padding until next page boundary for mprotect
    struct region_metadata regions_b[MAX_REGION_TABLE_SIZE] __attribute__((aligned(PAGE_SIZE)));
    // padding until next page boundary for mprotect
    struct slab_info_mapping slab_info_mapping[N_ARENA][N_SIZE_CLASSES];
    // padding until next page boundary for mprotect
};

static void regions_quarantine_deallocate_pages(void *p, size_t size, size_t guard_size) {
    if (!REGION_QUARANTINE || size >= REGION_QUARANTINE_SKIP_THRESHOLD) {
        deallocate_pages(p, size, guard_size);
        return;
    }

    if (ro.region_quarantine_protect) {
        if (unlikely(memory_map_fixed(p, size))) {
            deallocate_pages(p, size, guard_size);
            return;
        }
    } else {
        madvise(p, size, MADV_DONTNEED);
    }
    memory_set_name(p, size, "malloc large quarantine");

    struct quarantine_info target =
        (struct quarantine_info){(char *)p - guard_size, size + guard_size * 2};

    struct region_allocator *ra = ro.region_allocator;

    mutex_lock(&ra->lock);

#if REGION_QUARANTINE_RANDOM_LENGTH
    size_t index = get_random_u64_uniform(&ra->rng, REGION_QUARANTINE_RANDOM_LENGTH);
    struct quarantine_info random_substitute = ra->quarantine_random[index];
    ra->quarantine_random[index] = target;
    if (random_substitute.p == NULL) {
        mutex_unlock(&ra->lock);
        return;
    }
    target = random_substitute;
#endif

#if REGION_QUARANTINE_QUEUE_LENGTH
    struct quarantine_info queue_substitute = ra->quarantine_queue[ra->quarantine_queue_index];
    ra->quarantine_queue[ra->quarantine_queue_index] = target;
    ra->quarantine_queue_index = (ra->quarantine_queue_index + 1) % REGION_QUARANTINE_QUEUE_LENGTH;
    target = queue_substitute;
#endif

    mutex_unlock(&ra->lock);

    if (target.p != NULL) {
        memory_unmap(target.p, target.size);
    }
}

static int regions_grow(void) {
    struct region_allocator *ra = ro.region_allocator;

    if (ra->total > SIZE_MAX / sizeof(struct region_metadata) / 2) {
        return 1;
    }

    size_t newtotal = ra->total * 2;
    size_t newsize = newtotal * sizeof(struct region_metadata);
    size_t mask = newtotal - 1;

    if (newtotal > MAX_REGION_TABLE_SIZE) {
        return 1;
    }

    struct region_metadata *p = ra->regions == ro.regions[0] ?
        ro.regions[1] : ro.regions[0];

    if (memory_protect_rw_metadata(p, newsize)) {
        return 1;
    }

    for (size_t i = 0; i < ra->total; i++) {
        void *q = ra->regions[i].p;
        if (q != NULL) {
            size_t index = hash_page(q) & mask;
            while (p[index].p != NULL) {
                index = (index - 1) & mask;
            }
            p[index] = ra->regions[i];
        }
    }

    memory_map_fixed(ra->regions, ra->total * sizeof(struct region_metadata));
    memory_set_name(ra->regions, ra->total * sizeof(struct region_metadata), "malloc allocator_state");
    ra->free = ra->free + ra->total;
    ra->total = newtotal;
    ra->regions = p;
    return 0;
}

static int regions_insert(void *p, size_t size, size_t guard_size) {
    struct region_allocator *ra = ro.region_allocator;

    if (ra->free * 4 < ra->total) {
        if (regions_grow()) {
            return 1;
        }
    }

    size_t mask = ra->total - 1;
    size_t index = hash_page(p) & mask;
    void *q = ra->regions[index].p;
    while (q != NULL) {
        index = (index - 1) & mask;
        q = ra->regions[index].p;
    }
    ra->regions[index].p = p;
    ra->regions[index].size = size;
    ra->regions[index].guard_size = guard_size;
    ra->free--;
    return 0;
}

static struct region_metadata *regions_find(const void *p) {
    struct region_allocator *ra = ro.region_allocator;

    size_t mask = ra->total - 1;
    size_t index = hash_page(p) & mask;
    void *r = ra->regions[index].p;
    while (r != p && r != NULL) {
        index = (index - 1) & mask;
        r = ra->regions[index].p;
    }
    return (r == p && r != NULL) ? &ra->regions[index] : NULL;
}

static void regions_delete(struct region_metadata *region) {
    struct region_allocator *ra = ro.region_allocator;

    size_t mask = ra->total - 1;

    ra->free++;

    size_t i = region - ra->regions;
    for (;;) {
        ra->regions[i].p = NULL;
        ra->regions[i].size = 0;
        size_t j = i;
        for (;;) {
            i = (i - 1) & mask;
            if (ra->regions[i].p == NULL) {
                return;
            }
            size_t r = hash_page(ra->regions[i].p) & mask;
            if ((i <= r && r < j) || (r < j && j < i) || (j < i && i <= r)) {
                continue;
            }
            ra->regions[j] = ra->regions[i];
            break;
        }
    }
}

int get_metadata_key(void) {
#ifdef USE_PKEY
    return ro.metadata_pkey;
#else
    return -1;
#endif
}

static inline void thread_set_metadata_access(UNUSED unsigned access) {
#ifdef USE_PKEY
    if (ro.metadata_pkey == -1) {
        return;
    }
    pkey_set(ro.metadata_pkey, access);
#endif
}

static inline void thread_unseal_metadata(void) {
    thread_set_metadata_access(0);
}

static inline void thread_seal_metadata(void) {
#ifdef USE_PKEY
    thread_set_metadata_access(PKEY_DISABLE_ACCESS);
#endif
}

static void full_lock(void) {
    thread_unseal_metadata();
    mutex_lock(&ro.region_allocator->lock);
    for (unsigned arena = 0; arena < N_ARENA; arena++) {
        for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
            mutex_lock(&ro.size_class_metadata[arena][class].lock);
        }
    }
    thread_seal_metadata();
}

static void full_unlock(void) {
    thread_unseal_metadata();
    mutex_unlock(&ro.region_allocator->lock);
    for (unsigned arena = 0; arena < N_ARENA; arena++) {
        for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
            mutex_unlock(&ro.size_class_metadata[arena][class].lock);
        }
    }
    thread_seal_metadata();
}

static void post_fork_child(void) {
    thread_unseal_metadata();

    mutex_init(&ro.region_allocator->lock);
    random_state_init(&ro.region_allocator->rng);
    for (unsigned arena = 0; arena < N_ARENA; arena++) {
        for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
            struct size_class *c = &ro.size_class_metadata[arena][class];
            mutex_init(&c->lock);
            random_state_init(&c->rng);
        }
    }
    thread_seal_metadata();
}

static inline bool is_init(void) {
    return get_slab_region_end() != NULL;
}

static inline void enforce_init(void) {
    if (!is_init()) {
        fatal_error("invalid uninitialized allocator usage");
    }
}

COLD static void handle_hal_bugs(void) {
    char path[256];
    if (readlink("/proc/self/exe", path, sizeof(path)) == -1) {
        return;
    }
    const char camera_provider[] = "/vendor/bin/hw/android.hardware.camera.provider@2.4-service_64";
    if (strcmp(camera_provider, path) == 0) {
        ro.zero_on_free = false;
        ro.purge_slabs = false;
        ro.region_quarantine_protect = false;
    }
}

COLD static void init_slow_path(void) {
    static struct mutex lock = MUTEX_INITIALIZER;

    mutex_lock(&lock);

    if (is_init()) {
        mutex_unlock(&lock);
        return;
    }

#ifdef USE_PKEY
    ro.metadata_pkey = pkey_alloc(0, 0);
#endif

    ro.purge_slabs = true;
    ro.zero_on_free = ZERO_ON_FREE;
    ro.region_quarantine_protect = true;
    handle_hal_bugs();

    if (sysconf(_SC_PAGESIZE) != PAGE_SIZE) {
        fatal_error("runtime page size does not match compile-time page size which is not supported");
    }

    struct random_state *rng = allocate_pages(sizeof(struct random_state), PAGE_SIZE, true, "malloc init rng");
    if (rng == NULL) {
        fatal_error("failed to allocate init rng");
    }
    random_state_init(rng);

    size_t metadata_guard_size =
        (get_random_u64_uniform(rng, REAL_CLASS_REGION_SIZE / PAGE_SIZE) + 1) * PAGE_SIZE;

    struct allocator_state *allocator_state =
        allocate_pages(sizeof(struct allocator_state), metadata_guard_size, false, "malloc allocator_state");
    if (allocator_state == NULL) {
        fatal_error("failed to reserve allocator state");
    }
    if (memory_protect_rw_metadata(allocator_state, offsetof(struct allocator_state, regions_a))) {
        fatal_error("failed to unprotect allocator state");
    }

    ro.region_allocator = &allocator_state->region_allocator;
    struct region_allocator *ra = ro.region_allocator;

    mutex_init(&ra->lock);
    random_state_init_from_random_state(&ra->rng, rng);
    ro.regions[0] = allocator_state->regions_a;
    ro.regions[1] = allocator_state->regions_b;
    ra->regions = ro.regions[0];
    ra->total = INITIAL_REGION_TABLE_SIZE;
    ra->free = INITIAL_REGION_TABLE_SIZE;
    if (memory_protect_rw_metadata(ra->regions, ra->total * sizeof(struct region_metadata))) {
        fatal_error("failed to unprotect memory for regions table");
    }

    ro.slab_region_start = memory_map(slab_region_size);
    if (ro.slab_region_start == NULL) {
        fatal_error("failed to allocate slab region");
    }
    void *slab_region_end = (char *)ro.slab_region_start + slab_region_size;
    memory_set_name(ro.slab_region_start, slab_region_size, "malloc slab region gap");

    for (unsigned arena = 0; arena < N_ARENA; arena++) {
        ro.size_class_metadata[arena] = allocator_state->size_class_metadata[arena];
        for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
            struct size_class *c = &ro.size_class_metadata[arena][class];

            mutex_init(&c->lock);
            random_state_init_from_random_state(&c->rng, rng);

            size_t bound = (REAL_CLASS_REGION_SIZE - CLASS_REGION_SIZE) / PAGE_SIZE - 1;
            size_t gap = (get_random_u64_uniform(rng, bound) + 1) * PAGE_SIZE;
            c->class_region_start = (char *)ro.slab_region_start + ARENA_SIZE * arena + REAL_CLASS_REGION_SIZE * class + gap;
            label_slab(c->class_region_start, CLASS_REGION_SIZE, class);

            size_t size = size_classes[class];
            if (size == 0) {
                size = 16;
            }
            c->size_divisor = libdivide_u32_gen(size);
            size_t slab_size = get_slab_size(size_class_slots[class], size);
            c->slab_size_divisor = libdivide_u64_gen(slab_size);
            c->slab_info = allocator_state->slab_info_mapping[arena][class].slab_info;
        }
    }

    deallocate_pages(rng, sizeof(struct random_state), PAGE_SIZE);

    atomic_store_explicit(&ro.slab_region_end, slab_region_end, memory_order_release);

    if (memory_protect_ro(&ro, sizeof(ro))) {
        fatal_error("failed to protect allocator data");
    }
    memory_set_name(&ro, sizeof(ro), "malloc read-only after init");

    mutex_unlock(&lock);

    // may allocate, so wait until the allocator is initialized to avoid deadlocking
    if (pthread_atfork(full_lock, full_unlock, post_fork_child)) {
        fatal_error("pthread_atfork failed");
    }
}

static inline unsigned init(void) {
    unsigned arena = thread_arena;
#if N_ARENA > 1
    if (likely(arena < N_ARENA)) {
        return arena;
    }
    thread_arena = arena = thread_arena_counter++ % N_ARENA;
#endif
    if (unlikely(!is_init())) {
        init_slow_path();
    }
    return arena;
}

// trigger early initialization to set up pthread_atfork and protect state as soon as possible
COLD __attribute__((constructor(101))) static void trigger_early_init(void) {
    // avoid calling init directly to skip it if this isn't the malloc implementation
    h_free(h_malloc(16));
}

// Returns 0 on overflow.
static size_t get_large_size_class(size_t size) {
    if (CONFIG_LARGE_SIZE_CLASSES) {
        // Continue small size class growth pattern of power of 2 spacing classes:
        //
        // 4 KiB [20 KiB, 24 KiB, 28 KiB, 32 KiB]
        // 8 KiB [40 KiB, 48 KiB, 54 KiB, 64 KiB]
        // 16 KiB [80 KiB, 96 KiB, 112 KiB, 128 KiB]
        // 32 KiB [160 KiB, 192 KiB, 224 KiB, 256 KiB]
        // 512 KiB [2560 KiB, 3 MiB, 3584 KiB, 4 MiB]
        // 1 MiB [5 MiB, 6 MiB, 7 MiB, 8 MiB]
        // etc.
        size_t spacing_shift = 64 - __builtin_clzl(size - 1) - 3;
        size_t spacing_class = 1ULL << spacing_shift;
        return (size + (spacing_class - 1)) & ~(spacing_class - 1);
    }
    return PAGE_CEILING(size);
}

static size_t get_guard_size(struct random_state *state, size_t size) {
    return (get_random_u64_uniform(state, size / PAGE_SIZE / GUARD_SIZE_DIVISOR) + 1) * PAGE_SIZE;
}

static void *allocate_large(size_t size) {
    size = get_large_size_class(size);
    if (unlikely(!size)) {
        errno = ENOMEM;
        return NULL;
    }

    struct region_allocator *ra = ro.region_allocator;

    mutex_lock(&ra->lock);
    size_t guard_size = get_guard_size(&ra->rng, size);
    mutex_unlock(&ra->lock);

    void *p = allocate_pages(size, guard_size, true, "malloc large");
    if (p == NULL) {
        return NULL;
    }

    mutex_lock(&ra->lock);
    if (regions_insert(p, size, guard_size)) {
        mutex_unlock(&ra->lock);
        deallocate_pages(p, size, guard_size);
        return NULL;
    }
    stats_large_allocate(ra, size);
    mutex_unlock(&ra->lock);

    return p;
}

static inline void *allocate(unsigned arena, size_t size) {
    return size <= MAX_SLAB_SIZE_CLASS ? allocate_small(arena, size) : allocate_large(size);
}

static void deallocate_large(void *p, const size_t *expected_size) {
    enforce_init();
    thread_unseal_metadata();

    struct region_allocator *ra = ro.region_allocator;

    mutex_lock(&ra->lock);
    struct region_metadata *region = regions_find(p);
    if (region == NULL) {
        fatal_error("invalid free");
    }
    size_t size = region->size;
    if (expected_size && size != *expected_size) {
        fatal_error("sized deallocation mismatch (large)");
    }
    size_t guard_size = region->guard_size;
    regions_delete(region);
    stats_large_deallocate(ra, size);
    mutex_unlock(&ra->lock);

    regions_quarantine_deallocate_pages(p, size, guard_size);
}

static int alloc_aligned(unsigned arena, void **memptr, size_t alignment, size_t size, size_t min_alignment) {
    if ((alignment - 1) & alignment || alignment < min_alignment) {
        return EINVAL;
    }

    if (alignment <= PAGE_SIZE) {
        if (size <= MAX_SLAB_SIZE_CLASS && alignment > min_align) {
            size = get_size_info_align(size, alignment).size;
        }

        void *p = allocate(arena, size);
        if (p == NULL) {
            return ENOMEM;
        }
        *memptr = p;
        return 0;
    }

    size = get_large_size_class(size);
    if (unlikely(!size)) {
        return ENOMEM;
    }

    struct region_allocator *ra = ro.region_allocator;

    mutex_lock(&ra->lock);
    size_t guard_size = get_guard_size(&ra->rng, size);
    mutex_unlock(&ra->lock);

    void *p = allocate_pages_aligned(size, alignment, guard_size, "malloc large");
    if (p == NULL) {
        return ENOMEM;
    }

    mutex_lock(&ra->lock);
    if (regions_insert(p, size, guard_size)) {
        mutex_unlock(&ra->lock);
        deallocate_pages(p, size, guard_size);
        return ENOMEM;
    }
    mutex_unlock(&ra->lock);

    *memptr = p;
    return 0;
}

static void *alloc_aligned_simple(unsigned arena, size_t alignment, size_t size) {
    void *ptr;
    int ret = alloc_aligned(arena, &ptr, alignment, size, 1);
    if (ret) {
        errno = ret;
        return NULL;
    }
    return ptr;
}

static size_t adjust_size_for_canaries(size_t size) {
    if (size > 0 && size <= MAX_SLAB_SIZE_CLASS) {
        return size + canary_size;
    }
    return size;
}

static inline void *alloc(size_t size) {
    unsigned arena = init();
    thread_unseal_metadata();
    size = adjust_size_for_canaries(size);
    void *p = allocate(arena, size);
    thread_seal_metadata();
    return p;
}

EXPORT void *h_malloc(size_t size) {
    return alloc(size);
}

EXPORT void *h_calloc(size_t nmemb, size_t size) {
    size_t total_size;
    if (unlikely(__builtin_mul_overflow(nmemb, size, &total_size))) {
        errno = ENOMEM;
        return NULL;
    }
    unsigned arena = init();
    thread_unseal_metadata();
    total_size = adjust_size_for_canaries(total_size);
    void *p = allocate(arena, total_size);
    thread_seal_metadata();
    if (!ro.zero_on_free && likely(p != NULL) && total_size && total_size <= MAX_SLAB_SIZE_CLASS) {
        memset(p, 0, total_size - canary_size);
    }
    return p;
}

EXPORT void *h_realloc(void *old, size_t size) {
    if (old == NULL) {
        return alloc(size);
    }

    size = adjust_size_for_canaries(size);

    if (size > MAX_SLAB_SIZE_CLASS) {
        size = get_large_size_class(size);
        if (unlikely(!size)) {
            errno = ENOMEM;
            return NULL;
        }
    }

    size_t old_size;
    if (old < get_slab_region_end() && old >= ro.slab_region_start) {
        old_size = slab_usable_size(old);
        if (size <= MAX_SLAB_SIZE_CLASS && get_size_info(size).size == old_size) {
            return old;
        }
        thread_unseal_metadata();
    } else {
        enforce_init();
        thread_unseal_metadata();

        struct region_allocator *ra = ro.region_allocator;

        mutex_lock(&ra->lock);
        struct region_metadata *region = regions_find(old);
        if (region == NULL) {
            fatal_error("invalid realloc");
        }
        old_size = region->size;
        size_t old_guard_size = region->guard_size;
        if (old_size == size) {
            mutex_unlock(&ra->lock);
            thread_seal_metadata();
            return old;
        }
        mutex_unlock(&ra->lock);

        if (size > MAX_SLAB_SIZE_CLASS) {
            // in-place shrink
            if (size < old_size) {
                void *new_end = (char *)old + size;
                if (memory_map_fixed(new_end, old_guard_size)) {
                    thread_seal_metadata();
                    return NULL;
                }
                memory_set_name(new_end, old_guard_size, "malloc large");
                void *new_guard_end = (char *)new_end + old_guard_size;
                regions_quarantine_deallocate_pages(new_guard_end, old_size - size, 0);

                mutex_lock(&ra->lock);
                struct region_metadata *region = regions_find(old);
                if (region == NULL) {
                    fatal_error("invalid realloc");
                }
                region->size = size;
                stats_large_deallocate(ra, old_size - size);
                mutex_unlock(&ra->lock);

                thread_seal_metadata();
                return old;
            }

#ifdef HAVE_COMPATIBLE_MREMAP
            static const bool vma_merging_reliable = false;
            if (vma_merging_reliable) {
                // in-place growth
                void *guard_end = (char *)old + old_size + old_guard_size;
                size_t extra = size - old_size;
                if (!memory_remap((char *)old + old_size, old_guard_size, old_guard_size + extra)) {
                    if (memory_protect_rw((char *)old + old_size, extra)) {
                        memory_unmap(guard_end, extra);
                    } else {
                        mutex_lock(&ra->lock);
                        struct region_metadata *region = regions_find(old);
                        if (region == NULL) {
                            fatal_error("invalid realloc");
                        }
                        region->size = size;
                        stats_large_allocate(ra, extra);
                        mutex_unlock(&ra->lock);

                        thread_seal_metadata();
                        return old;
                    }
                }
            }

            size_t copy_size = min(size, old_size);
            if (copy_size >= MREMAP_MOVE_THRESHOLD) {
                void *new = allocate_large(size);
                if (new == NULL) {
                    thread_seal_metadata();
                    return NULL;
                }

                mutex_lock(&ra->lock);
                struct region_metadata *region = regions_find(old);
                if (region == NULL) {
                    fatal_error("invalid realloc");
                }
                regions_delete(region);
                stats_large_deallocate(ra, old_size);
                mutex_unlock(&ra->lock);

                if (memory_remap_fixed(old, old_size, new, size)) {
                    memcpy(new, old, copy_size);
                    deallocate_pages(old, old_size, old_guard_size);
                } else {
                    memory_unmap((char *)old - old_guard_size, old_guard_size);
                    memory_unmap((char *)old + PAGE_CEILING(old_size), old_guard_size);
                }
                thread_seal_metadata();
                return new;
            }
#endif
        }
    }

    void *new = allocate(thread_arena, size);
    if (new == NULL) {
        thread_seal_metadata();
        return NULL;
    }
    size_t copy_size = min(size, old_size);
    if (copy_size > 0 && copy_size <= MAX_SLAB_SIZE_CLASS) {
        copy_size -= canary_size;
    }
    memcpy(new, old, copy_size);
    if (old_size <= MAX_SLAB_SIZE_CLASS) {
        deallocate_small(old, NULL);
    } else {
        deallocate_large(old, NULL);
    }
    thread_seal_metadata();
    return new;
}

EXPORT int h_posix_memalign(void **memptr, size_t alignment, size_t size) {
    unsigned arena = init();
    thread_unseal_metadata();
    size = adjust_size_for_canaries(size);
    int ret = alloc_aligned(arena, memptr, alignment, size, sizeof(void *));
    thread_seal_metadata();
    return ret;
}

EXPORT void *h_aligned_alloc(size_t alignment, size_t size) {
    unsigned arena = init();
    thread_unseal_metadata();
    size = adjust_size_for_canaries(size);
    void *p = alloc_aligned_simple(arena, alignment, size);
    thread_seal_metadata();
    return p;
}

EXPORT void *h_memalign(size_t alignment, size_t size) ALIAS(h_aligned_alloc);

#ifndef __ANDROID__
EXPORT void *h_valloc(size_t size) {
    unsigned arena = init();
    thread_unseal_metadata();
    size = adjust_size_for_canaries(size);
    void *p = alloc_aligned_simple(arena, PAGE_SIZE, size);
    thread_seal_metadata();
    return p;
}

EXPORT void *h_pvalloc(size_t size) {
    size = PAGE_CEILING(size);
    if (!size) {
        errno = ENOMEM;
        return NULL;
    }
    unsigned arena = init();
    thread_unseal_metadata();
    size = adjust_size_for_canaries(size);
    void *p = alloc_aligned_simple(arena, PAGE_SIZE, size);
    thread_seal_metadata();
    return p;
}
#endif

EXPORT void h_free(void *p) {
    if (p == NULL) {
        return;
    }

    if (p < get_slab_region_end() && p >= ro.slab_region_start) {
        thread_unseal_metadata();
        deallocate_small(p, NULL);
        thread_seal_metadata();
        return;
    }

    deallocate_large(p, NULL);

    thread_seal_metadata();
}

#ifdef __GLIBC__
EXPORT void h_cfree(void *ptr) ALIAS(h_free);
#endif

EXPORT void h_free_sized(void *p, size_t expected_size) {
    if (p == NULL) {
        return;
    }

    if (p < get_slab_region_end() && p >= ro.slab_region_start) {
        thread_unseal_metadata();
        expected_size = get_size_info(adjust_size_for_canaries(expected_size)).size;
        deallocate_small(p, &expected_size);
        thread_seal_metadata();
        return;
    }

    deallocate_large(p, &expected_size);

    thread_seal_metadata();
}

static inline void memory_corruption_check_small(const void *p) {
    struct slab_size_class_info size_class_info = slab_size_class(p);
    size_t class = size_class_info.class;
    struct size_class *c = &ro.size_class_metadata[size_class_info.arena][class];
    size_t size = size_classes[class];
    bool is_zero_size = size == 0;
    if (is_zero_size) {
        size = 16;
    }
    size_t slab_size = get_slab_size(size_class_slots[class], size);

    mutex_lock(&c->lock);

    struct slab_metadata *metadata = get_metadata(c, p);
    void *slab = get_slab(c, slab_size, metadata);
    size_t slot = libdivide_u32_do((const char *)p - (const char *)slab, &c->size_divisor);

    if (slot_pointer(size, slab, slot) != p) {
        fatal_error("invalid unaligned malloc_usable_size");
    }

    if (!get_slot(metadata, slot)) {
        fatal_error("invalid malloc_usable_size");
    }

    if (!is_zero_size && canary_size) {
        u64 canary_value;
        memcpy(&canary_value, (const char *)p + size - canary_size, canary_size);
        if (unlikely(canary_value != metadata->canary_value)) {
            fatal_error("canary corrupted");
        }
    }

#if SLAB_QUARANTINE
    if (get_quarantine(metadata, slot)) {
        fatal_error("invalid malloc_usable_size (quarantine)");
    }
#endif

    mutex_unlock(&c->lock);
}

EXPORT size_t h_malloc_usable_size(H_MALLOC_USABLE_SIZE_CONST void *p) {
    if (p == NULL) {
        return 0;
    }

    if (p < get_slab_region_end() && p >= ro.slab_region_start) {
        thread_unseal_metadata();

        memory_corruption_check_small(p);
        thread_seal_metadata();

        size_t size = slab_usable_size(p);
        return size ? size - canary_size : 0;
    }

    enforce_init();
    thread_unseal_metadata();

    struct region_allocator *ra = ro.region_allocator;
    mutex_lock(&ra->lock);
    struct region_metadata *region = regions_find(p);
    if (p == NULL) {
        fatal_error("invalid malloc_usable_size");
    }
    size_t size = region->size;
    mutex_unlock(&ra->lock);

    thread_seal_metadata();
    return size;
}

EXPORT size_t h_malloc_object_size(void *p) {
    if (p == NULL) {
        return 0;
    }

    void *slab_region_end = get_slab_region_end();
    if (p < slab_region_end && p >= ro.slab_region_start) {
        thread_unseal_metadata();

        struct slab_size_class_info size_class_info = slab_size_class(p);
        size_t class = size_class_info.class;
        size_t size_class = size_classes[class];
        struct size_class *c = &ro.size_class_metadata[size_class_info.arena][class];

        mutex_lock(&c->lock);

        struct slab_metadata *metadata = get_metadata(c, p);
        size_t slab_size = get_slab_size(size_class_slots[class], size_class);
        void *slab = get_slab(c, slab_size, metadata);
        size_t slot = libdivide_u32_do((const char *)p - (const char *)slab, &c->size_divisor);

        if (!get_slot(metadata, slot)) {
            fatal_error("invalid malloc_object_size");
        }

#if SLAB_QUARANTINE
        if (get_quarantine(metadata, slot)) {
            fatal_error("invalid malloc_object_size (quarantine)");
        }
#endif

        void *start = slot_pointer(size_class, slab, slot);
        size_t offset = (const char *)p - (const char *)start;

        mutex_unlock(&c->lock);
        thread_seal_metadata();

        size_t size = slab_usable_size(p);
        return size ? size - canary_size - offset : 0;
    }

    if (unlikely(slab_region_end == NULL)) {
        return SIZE_MAX;
    }

    thread_unseal_metadata();

    struct region_allocator *ra = ro.region_allocator;
    mutex_lock(&ra->lock);
    struct region_metadata *region = regions_find(p);
    size_t size = p == NULL ? SIZE_MAX : region->size;
    mutex_unlock(&ra->lock);

    thread_seal_metadata();
    return size;
}

EXPORT size_t h_malloc_object_size_fast(void *p) {
    if (p == NULL) {
        return 0;
    }

    void *slab_region_end = get_slab_region_end();
    if (p < slab_region_end && p >= ro.slab_region_start) {
        size_t size = slab_usable_size(p);
        return size ? size - canary_size : 0;
    }

    if (unlikely(slab_region_end == NULL)) {
        return 0;
    }

    return SIZE_MAX;
}

EXPORT int h_mallopt(UNUSED int param, UNUSED int value) {
#ifdef __ANDROID__
    if (param == M_PURGE) {
        h_malloc_trim(0);
        return 1;
    }
#endif
    return 0;
}

EXPORT int h_malloc_trim(UNUSED size_t pad) {
    if (unlikely(!is_init())) {
        return 0;
    }

    thread_unseal_metadata();

    bool is_trimmed = false;

    for (unsigned arena = 0; arena < N_ARENA; arena++) {
        // skip zero byte size class since there's nothing to change
        for (unsigned class = 1; class < N_SIZE_CLASSES; class++) {
            struct size_class *c = &ro.size_class_metadata[arena][class];
            size_t slab_size = get_slab_size(size_class_slots[class], size_classes[class]);

            mutex_lock(&c->lock);
            struct slab_metadata *iterator = c->empty_slabs;
            while (iterator) {
                void *slab = get_slab(c, slab_size, iterator);
                if (memory_map_fixed(slab, slab_size)) {
                    break;
                }
                label_slab(slab, slab_size, class);
                stats_slab_deallocate(c, slab_size);

                struct slab_metadata *trimmed = iterator;
                iterator = iterator->next;
                c->empty_slabs_total -= slab_size;

                enqueue_free_slab(c, trimmed);

                is_trimmed = true;
            }
            c->empty_slabs = iterator;
            mutex_unlock(&c->lock);
        }
    }

    thread_seal_metadata();

    return is_trimmed;
}

EXPORT void h_malloc_stats(void) {}

#if defined(__GLIBC__) || defined(__ANDROID__)
EXPORT struct mallinfo h_mallinfo(void) {
    struct mallinfo info = {0};

    // glibc mallinfo type definition and implementation are both broken
#if CONFIG_STATS && !defined(__GLIBC__)
    if (!is_init()) {
        return info;
    }

    thread_unseal_metadata();

    struct region_allocator *ra = ro.region_allocator;
    mutex_lock(&ra->lock);
    info.hblkhd += ra->allocated;
    info.uordblks += ra->allocated;
    mutex_unlock(&ra->lock);

    for (unsigned arena = 0; arena < N_ARENA; arena++) {
        for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
            struct size_class *c = &ro.size_class_metadata[arena][class];

            mutex_lock(&c->lock);
            info.hblkhd += c->slab_allocated;
            info.uordblks += c->allocated;
            mutex_unlock(&c->lock);
        }
    }

    info.fordblks = info.hblkhd - info.uordblks;
    info.usmblks = info.hblkhd;

    thread_seal_metadata();
#endif

    return info;
}
#endif

#ifndef __ANDROID__
EXPORT int h_malloc_info(int options, UNUSED FILE *fp) {
    if (options) {
        errno = EINVAL;
        return -1;
    }

    fputs("<malloc version=\"hardened_malloc-1\">", fp);

#if CONFIG_STATS
    if (is_init()) {
        thread_unseal_metadata();

        for (unsigned arena = 0; arena < N_ARENA; arena++) {
            fprintf(fp, "<heap nr=\"%u\">", arena);

            for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
                struct size_class *c = &ro.size_class_metadata[arena][class];

                mutex_lock(&c->lock);
                u64 nmalloc = c->nmalloc;
                u64 ndalloc = c->ndalloc;
                size_t slab_allocated = c->slab_allocated;
                size_t allocated = c->allocated;
                mutex_unlock(&c->lock);

                if (nmalloc || ndalloc || slab_allocated || allocated) {
                    fprintf(fp, "<bin nr=\"%u\" size=\"%" PRIu32 "\">", class, size_classes[class]);
                    fprintf(fp, "<nmalloc>%" PRIu64 "</nmalloc>", nmalloc);
                    fprintf(fp, "<ndalloc>%" PRIu64 "</ndalloc>", ndalloc);
                    fprintf(fp, "<slab_allocated>%zu</slab_allocated>", slab_allocated);
                    fprintf(fp, "<allocated>%zu</allocated>", allocated);
                    fputs("</bin>", fp);
                }
            }

            fputs("</heap>", fp);
        }

        struct region_allocator *ra = ro.region_allocator;
        mutex_lock(&ra->lock);
        size_t region_allocated = ra->allocated;
        mutex_unlock(&ra->lock);

        fprintf(fp, "<heap nr=\"%u\">", N_ARENA);
        fprintf(fp, "<allocated_large>%zu</allocated_large>", region_allocated);
        fputs("</heap>", fp);

        thread_seal_metadata();
    }
#endif

    fputs("</malloc>", fp);

    return 0;
}
#endif

#ifdef __ANDROID__
EXPORT size_t h_mallinfo_narenas(void) {
    // Consider region allocator to be an arena with index N_ARENA.
    return N_ARENA + 1;
}

EXPORT size_t h_mallinfo_nbins(void) {
    return N_SIZE_CLASSES;
}

// This internal Android API uses mallinfo in a non-standard way to implement malloc_info:
//
// hblkhd: total mapped memory as usual
// ordblks: large allocations
// uordblks: huge allocations
// fsmblks: small allocations
// (other fields are unused)
EXPORT struct mallinfo h_mallinfo_arena_info(UNUSED size_t arena) {
    struct mallinfo info = {0};

#if CONFIG_STATS
    if (!is_init()) {
        return info;
    }

    thread_unseal_metadata();

    if (arena < N_ARENA) {
        for (unsigned class = 0; class < N_SIZE_CLASSES; class++) {
            struct size_class *c = &ro.size_class_metadata[arena][class];

            mutex_lock(&c->lock);
            info.hblkhd += c->slab_allocated;
            info.fsmblks += c->allocated;
            mutex_unlock(&c->lock);
        }
    } else if (arena == N_ARENA) {
        struct region_allocator *ra = ro.region_allocator;
        mutex_lock(&ra->lock);
        info.hblkhd = ra->allocated;
        // our large allocations are roughly comparable to jemalloc huge allocations
        info.uordblks = ra->allocated;
        mutex_unlock(&ra->lock);
    }

    thread_seal_metadata();
#endif

    return info;
}

// This internal Android API uses mallinfo in a non-standard way to implement malloc_info:
//
// ordblks: total allocated space
// uordblks: nmalloc
// fordblks: ndalloc
// (other fields are unused)
EXPORT struct mallinfo h_mallinfo_bin_info(UNUSED size_t arena, UNUSED size_t bin) {
    struct mallinfo info = {0};

#if CONFIG_STATS
    if (!is_init()) {
        return info;
    }

    if (arena < N_ARENA && bin < N_SIZE_CLASSES) {
        thread_seal_metadata();

        struct size_class *c = &ro.size_class_metadata[arena][bin];

        mutex_lock(&c->lock);
        info.ordblks = c->allocated;
        info.uordblks = c->nmalloc;
        info.fordblks = c->ndalloc;
        mutex_unlock(&c->lock);

        thread_unseal_metadata();
    }
#endif

    return info;
}

COLD EXPORT int h_malloc_iterate(UNUSED uintptr_t base, UNUSED size_t size,
                          UNUSED void (*callback)(uintptr_t ptr, size_t size, void *arg),
                          UNUSED void *arg) {
    fatal_error("not implemented");
}

COLD EXPORT void h_malloc_disable(void) {
    init();
    full_lock();
}

COLD EXPORT void h_malloc_enable(void) {
    enforce_init();
    full_unlock();
}
#endif

#ifdef __GLIBC__
COLD EXPORT void *h_malloc_get_state(void) {
    return NULL;
}

COLD EXPORT int h_malloc_set_state(UNUSED void *state) {
    return -2;
}
#endif
