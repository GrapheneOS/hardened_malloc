#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <pthread.h>

#include <malloc.h>

#include "third_party/libdivide.h"

#include "malloc.h"
#include "memory.h"
#include "random.h"
#include "util.h"

static_assert(sizeof(void *) == 8, "64-bit only");

#define PAGE_SHIFT 12
#define PAGE_SIZE ((size_t)1 << PAGE_SHIFT)
#define PAGE_MASK ((size_t)(PAGE_SIZE - 1))
#define PAGE_CEILING(s) (((s) + PAGE_MASK) & ~PAGE_MASK)

#define ALIGNMENT_CEILING(s, alignment) (((s) + (alignment - 1)) & ((~(alignment)) + 1))

static void *allocate_pages(size_t usable_size, size_t guard_size, bool unprotect) {
    size_t real_size;
    if (unlikely(__builtin_add_overflow(usable_size, guard_size * 2, &real_size))) {
        errno = ENOMEM;
        return NULL;
    }
    void *real = memory_map(real_size);
    if (real == NULL) {
        return NULL;
    }
    void *usable = (char *)real + guard_size;
    if (unprotect && memory_protect_rw(usable, usable_size)) {
        memory_unmap(real, real_size);
        return NULL;
    }
    return usable;
}

static void deallocate_pages(void *usable, size_t usable_size, size_t guard_size) {
    memory_unmap((char *)usable - guard_size, usable_size + guard_size * 2);
}

static void *allocate_pages_aligned(size_t usable_size, size_t alignment, size_t guard_size) {
    usable_size = PAGE_CEILING(usable_size);
    if (unlikely(!usable_size)) {
        errno = ENOMEM;
        return NULL;
    }

    size_t alloc_size;
    if (unlikely(__builtin_add_overflow(usable_size, alignment - PAGE_SIZE, &alloc_size))) {
        errno = ENOMEM;
        return NULL;
    }

    size_t real_alloc_size;
    if (unlikely(__builtin_add_overflow(alloc_size, guard_size * 2, &real_alloc_size))) {
        errno = ENOMEM;
        return NULL;
    }

    void *real = memory_map(real_alloc_size);
    if (real == NULL) {
        return NULL;
    }

    void *usable = (char *)real + guard_size;

    size_t lead_size = ALIGNMENT_CEILING((uintptr_t)usable, alignment) - (uintptr_t)usable;
    size_t trail_size = alloc_size - lead_size - usable_size;
    void *base = (char *)usable + lead_size;

    if (memory_protect_rw(base, usable_size)) {
        memory_unmap(real, real_alloc_size);
        return NULL;
    }

    if (lead_size) {
        if (memory_unmap(real, lead_size)) {
            memory_unmap(real, real_alloc_size);
            return NULL;
        }
    }

    if (trail_size) {
        if (memory_unmap((char *)base + usable_size + guard_size, trail_size)) {
            memory_unmap(real, real_alloc_size);
            return NULL;
        }
    }

    return base;
}

static union {
    struct {
        void *slab_region_start;
        void *slab_region_end;
        atomic_bool initialized;
    };
    char padding[PAGE_SIZE];
} ro __attribute__((aligned(PAGE_SIZE))) = {
    .initialized = ATOMIC_VAR_INIT(false)
};

struct slab_metadata {
    uint64_t bitmap;
    struct slab_metadata *next;
    struct slab_metadata *prev;
};

static const size_t max_slab_size_class = 16384;

static const uint16_t size_classes[] = {
    /* 0 */ 0,
    /* 16 */ 16, 32, 48, 64, 80, 96, 112, 128,
    /* 32 */ 160, 192, 224, 256,
    /* 64 */ 320, 384, 448, 512,
    /* 128 */ 640, 768, 896, 1024,
    /* 256 */ 1280, 1536, 1792, 2048,
    /* 512 */ 2560, 3072, 3584, 4096,
    /* 1024 */ 5120, 6144, 7168, 8192,
    /* 2048 */ 10240, 12288, 14336, 16384
};

static const uint16_t size_class_slots[] = {
    /* 0 */ 256,
    /* 16 */ 256, 128, 85, 64, 51, 42, 36, 64,
    /* 32 */ 51, 64, 54, 64,
    /* 64 */ 64, 64, 64, 64,
    /* 128 */ 64, 64, 64, 64,
    /* 256 */ 16, 16, 16, 16,
    /* 512 */ 8, 8, 8, 8,
    /* 1024 */ 8, 8, 8, 8,
    /* 2048 */ 6, 5, 4, 4
};

#define N_SIZE_CLASSES (sizeof(size_classes) / sizeof(size_classes[0]))

struct size_info {
    size_t size;
    size_t class;
};

static inline struct size_info get_size_info(size_t size) {
    if (size == 0) {
        return (struct size_info){16, 0};
    }
    for (size_t i = 1; i < N_SIZE_CLASSES; i++) {
        size_t real_size = size_classes[i];
        if (size <= real_size) {
            return (struct size_info){real_size, i};
        }
    }
    fatal_error("invalid size for slabs");
}

static size_t get_slab_size(size_t slots, size_t size) {
    return PAGE_CEILING(slots * size);
}

static struct size_class {
    pthread_mutex_t mutex;
    void *class_region_start;
    struct slab_metadata *slab_info;
    struct slab_metadata *partial_slabs;
    struct slab_metadata *empty_slabs;
    struct libdivide_u32_t size_divisor;
    struct libdivide_u64_t slab_size_divisor;
    struct random_state rng;
    size_t metadata_allocated;
    size_t metadata_count;
} size_class_metadata[N_SIZE_CLASSES];

static const size_t class_region_size = 128ULL * 1024 * 1024 * 1024;
static const size_t real_class_region_size = class_region_size * 2;
static const size_t slab_region_size = real_class_region_size * N_SIZE_CLASSES;
static_assert(PAGE_SIZE == 4096, "bitmap handling will need adjustment for other page sizes");

static size_t get_metadata_max(size_t slab_size) {
    return class_region_size / slab_size;
}

static struct slab_metadata *alloc_metadata(struct size_class *c, size_t slab_size) {
    if (unlikely(c->metadata_count == c->metadata_allocated)) {
        size_t metadata_max = get_metadata_max(slab_size);
        if (c->metadata_count == metadata_max) {
            errno = ENOMEM;
            return NULL;
        }
        size_t allocate = c->metadata_allocated * 2;
        if (allocate > metadata_max) {
            allocate = metadata_max;
        }
        if (memory_protect_rw(c->slab_info, allocate * sizeof(struct slab_metadata))) {
            return NULL;
        }
        c->metadata_allocated = allocate;
    }

    struct slab_metadata *metadata = c->slab_info + c->metadata_count;
    c->metadata_count++;
    return metadata;
}

static void check_index(size_t index) {
    if (index >= 64) {
        fatal_error("invalid index");
    }
}

static void set_slot(struct slab_metadata *metadata, size_t index) {
    check_index(index);
    metadata->bitmap |= 1UL << index;
}

static void clear_slot(struct slab_metadata *metadata, size_t index) {
    check_index(index);
    metadata->bitmap &= ~(1UL << index);
}

static bool get_slot(struct slab_metadata *metadata, size_t index) {
    check_index(index);
    return (metadata->bitmap >> index) & 1UL;
}

static uint64_t get_mask(size_t slots) {
    return slots < 64 ? ~0UL << slots : 0;
}

static size_t get_free_slot(struct random_state *rng, size_t slots, struct slab_metadata *metadata) {
    if (slots > 64) {
        slots = 64;
    }

    uint64_t masked = metadata->bitmap | get_mask(slots);
    if (masked == ~0UL) {
        fatal_error("no zero bits");
    }

    // randomize start location for linear search (uniform random choice is too slow)
    uint64_t random_split = ~(~0UL << get_random_u16_uniform(rng, slots));

    size_t slot = ffzl(masked | random_split);
    if (slot) {
        return slot - 1;
    } else {
        return ffzl(masked) - 1;
    }
}

static bool has_free_slots(size_t slots, struct slab_metadata *metadata) {
    if (slots > 64) {
        slots = 64;
    }

    uint64_t masked = metadata->bitmap | get_mask(slots);
    return masked != ~0UL;
}

static bool is_free_slab(struct slab_metadata *metadata) {
    return !metadata->bitmap;
}

static void *get_slab(struct size_class *c, size_t slab_size, struct slab_metadata *metadata) {
    size_t index = metadata - c->slab_info;
    return (char *)c->class_region_start + (index * slab_size);
}

static struct slab_metadata *get_metadata(struct size_class *c, void *p) {
    size_t offset = (char *)p - (char *)c->class_region_start;
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

static inline void *slab_allocate(size_t requested_size) {
    struct size_info info = get_size_info(requested_size);
    size_t size = info.size;
    struct size_class *c = &size_class_metadata[info.class];
    size_t slots = size_class_slots[info.class];
    size_t slab_size = get_slab_size(slots, size);

    pthread_mutex_lock(&c->mutex);

    if (c->partial_slabs == NULL) {
        if (c->empty_slabs != NULL) {
            struct slab_metadata *metadata = c->empty_slabs;
            c->empty_slabs = c->empty_slabs->next;
            if (c->empty_slabs) {
                c->empty_slabs->prev = NULL;
            }

            metadata->next = c->partial_slabs;
            metadata->prev = NULL;

            if (c->partial_slabs) {
                c->partial_slabs->prev = metadata;
            }
            c->partial_slabs = metadata;

            void *slab = get_slab(c, slab_size, metadata);
            size_t slot = get_free_slot(&c->rng, slots, metadata);
            set_slot(metadata, slot);
            void *p = slot_pointer(size, slab, slot);

            pthread_mutex_unlock(&c->mutex);
            return p;
        }

        struct slab_metadata *metadata = alloc_metadata(c, slab_size);
        if (metadata == NULL) {
            pthread_mutex_unlock(&c->mutex);
            return NULL;
        }

        void *slab = get_slab(c, slab_size, metadata);
        if (requested_size != 0 && memory_protect_rw(slab, slab_size)) {
            c->metadata_count--;
            pthread_mutex_unlock(&c->mutex);
            return NULL;
        }

        c->partial_slabs = metadata;
        size_t slot = get_free_slot(&c->rng, slots, metadata);
        set_slot(metadata, slot);
        void *p = slot_pointer(size, slab, slot);

        pthread_mutex_unlock(&c->mutex);
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

    pthread_mutex_unlock(&c->mutex);
    return p;
}

static size_t slab_size_class(void *p) {
    size_t offset = (char *)p - (char *)ro.slab_region_start;
    return offset / real_class_region_size;
}

static size_t slab_usable_size(void *p) {
    return size_classes[slab_size_class(p)];
}

static inline void slab_free(void *p) {
    size_t class = slab_size_class(p);

    struct size_class *c = &size_class_metadata[class];
    size_t size = size_classes[class];
    bool is_zero_size = size == 0;
    if (is_zero_size) {
        size = 16;
    }
    size_t slots = size_class_slots[class];
    size_t slab_size = get_slab_size(slots, size);

    pthread_mutex_lock(&c->mutex);

    struct slab_metadata *metadata = get_metadata(c, p);
    void *slab = get_slab(c, slab_size, metadata);
    size_t slot = libdivide_u32_do((char *)p - (char *)slab, &c->size_divisor);

    if (slot_pointer(size, slab, slot) != p) {
        fatal_error("invalid unaligned free");
    }

    if (!get_slot(metadata, slot)) {
        fatal_error("double free");
    }

    if (!has_free_slots(slots, metadata)) {
        metadata->next = c->partial_slabs;
        metadata->prev = NULL;

        if (c->partial_slabs) {
            c->partial_slabs->prev = metadata;
        }
        c->partial_slabs = metadata;
    }

    clear_slot(metadata, slot);
    if (!is_zero_size) {
        memset(p, 0, size);
    }

    if (is_free_slab(metadata)) {
        if (metadata->prev) {
            metadata->prev->next = metadata->next;
        } else {
            if (c->partial_slabs != metadata) {
                fatal_error("not good");
            }
            c->partial_slabs = metadata->next;
        }
        if (metadata->next) {
            metadata->next->prev = metadata->prev;
        }

        metadata->next = c->empty_slabs;
        metadata->prev = NULL;

        if (c->empty_slabs) {
            c->empty_slabs->prev = metadata;
        }
        c->empty_slabs = metadata;
    }

    pthread_mutex_unlock(&c->mutex);
}

struct region_info {
    void *p;
    size_t size;
    size_t guard_size;
};

static const size_t initial_region_table_size = 256;

static struct random_state regions_rng;
static struct region_info *regions;
static size_t regions_total = initial_region_table_size;
static size_t regions_free = initial_region_table_size;
static pthread_mutex_t regions_lock = PTHREAD_MUTEX_INITIALIZER;

static size_t hash_page(void *p) {
    uintptr_t u = (uintptr_t)p >> PAGE_SHIFT;
    size_t sum = u;
    sum = (sum << 7) - sum + (u >> 16);
    sum = (sum << 7) - sum + (u >> 32);
    sum = (sum << 7) - sum + (u >> 48);
    return sum;
}

static int regions_grow(void) {
    if (regions_total > SIZE_MAX / sizeof(struct region_info) / 2) {
        return 1;
    }

    size_t newtotal = regions_total * 2;
    size_t newsize = newtotal * sizeof(struct region_info);
    size_t mask = newtotal - 1;

    struct region_info *p = allocate_pages(newsize, PAGE_SIZE, true);
    if (p == NULL) {
        return 1;
    }

    for (size_t i = 0; i < regions_total; i++) {
        void *q = regions[i].p;
        if (q != NULL) {
            size_t index = hash_page(q) & mask;
            while (p[index].p != NULL) {
                index = (index - 1) & mask;
            }
            p[index] = regions[i];
        }
    }

    deallocate_pages(regions, regions_total * sizeof(struct region_info), PAGE_SIZE);
    regions_free = regions_free + regions_total;
    regions_total = newtotal;
    regions = p;
    return 0;
}

static int regions_insert(void *p, size_t size, size_t guard_size) {
    if (regions_free * 4 < regions_total) {
        if (regions_grow()) {
            return 1;
        }
    }

    size_t mask = regions_total - 1;
    size_t index = hash_page(p) & mask;
    void *q = regions[index].p;
    while (q != NULL) {
        index = (index - 1) & mask;
        q = regions[index].p;
    }
    regions[index].p = p;
    regions[index].size = size;
    regions[index].guard_size = guard_size;
    regions_free--;
    return 0;
}

static struct region_info *regions_find(void *p) {
    size_t mask = regions_total - 1;
    size_t index = hash_page(p) & mask;
    void *r = regions[index].p;
    while (r != p && r != NULL) {
        index = (index - 1) & mask;
        r = regions[index].p;
    }
    return (r == p && r != NULL) ? &regions[index] : NULL;
}

static void regions_delete(struct region_info *region) {
    size_t mask = regions_total - 1;

    regions_free++;

    size_t i = region - regions;
    for (;;) {
        regions[i].p = NULL;
        regions[i].size = 0;
        size_t j = i;
        for (;;) {
            i = (i - 1) & mask;
            if (regions[i].p == NULL) {
                return;
            }
            size_t r = hash_page(regions[i].p) & mask;
            if ((i <= r && r < j) || (r < j && j < i) || (j < i && i <= r)) {
                continue;
            }
            regions[j] = regions[i];
            break;
        }
    }
}

static void pre_fork(void) {
    pthread_mutex_lock(&regions_lock);
    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        pthread_mutex_lock(&size_class_metadata[i].mutex);
    }
}

static void post_fork_parent(void) {
    pthread_mutex_unlock(&regions_lock);
    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        pthread_mutex_unlock(&size_class_metadata[i].mutex);
    }
}

static void post_fork_child(void) {
    if (pthread_mutex_init(&regions_lock, NULL)) {
        fatal_error("mutex initialization failed");
    }
    random_state_init(&regions_rng);
    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        struct size_class *c = &size_class_metadata[i];
        if (pthread_mutex_init(&c->mutex, NULL)) {
            fatal_error("mutex initialization failed");
        }
        random_state_init(&c->rng);
    }
}

COLD static void init_slow_path(void) {
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mutex);

    if (atomic_load_explicit(&ro.initialized, memory_order_acquire)) {
        pthread_mutex_unlock(&mutex);
        return;
    }

    if (pthread_atfork(pre_fork, post_fork_parent, post_fork_child)) {
        fatal_error("pthread_atfork failed");
    }

    if (sysconf(_SC_PAGESIZE) != PAGE_SIZE) {
        fatal_error("page size mismatch");
    }

    struct random_state rng;
    random_state_init(&rng);

    regions = allocate_pages(regions_total * sizeof(struct region_info), PAGE_SIZE, true);
    if (regions == NULL) {
        fatal_error("failed to set up allocator");
    }
    random_state_init(&regions_rng);

    ro.slab_region_start = memory_map(slab_region_size);
    if (ro.slab_region_start == NULL) {
        fatal_error("failed to allocate slab region");
    }
    ro.slab_region_end = (char *)ro.slab_region_start + slab_region_size;

    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        struct size_class *c = &size_class_metadata[i];

        if (pthread_mutex_init(&c->mutex, NULL)) {
            fatal_error("mutex initialization failed");
        }

        random_state_init(&c->rng);

        size_t bound = (real_class_region_size - class_region_size) / PAGE_SIZE - 1;
        size_t gap = (get_random_u64_uniform(&rng, bound) + 1) * PAGE_SIZE;
        c->class_region_start = (char *)ro.slab_region_start + real_class_region_size * i + gap;

        size_t size = size_classes[i];
        if (size == 0) {
            size = 16;
        }
        c->size_divisor = libdivide_u32_gen(size);
        size_t slab_size = get_slab_size(size_class_slots[i], size);
        c->slab_size_divisor = libdivide_u64_gen(slab_size);
        size_t metadata_max = get_metadata_max(slab_size);
        c->slab_info = allocate_pages(metadata_max * sizeof(struct slab_metadata), PAGE_SIZE, false);
        if (c->slab_info == NULL) {
            fatal_error("failed to allocate slab metadata");
        }
        c->metadata_allocated = PAGE_SIZE / sizeof(struct slab_metadata);
        if (memory_protect_rw(c->slab_info, c->metadata_allocated * sizeof(struct slab_metadata))) {
            fatal_error("failed to allocate initial slab info");
        }
    }

    atomic_store_explicit(&ro.initialized, true, memory_order_release);

    if (memory_protect_ro(&ro, sizeof(ro))) {
        fatal_error("failed to protect allocator data");
    }

    pthread_mutex_unlock(&mutex);
}

static inline void init(void) {
    if (likely(atomic_load_explicit(&ro.initialized, memory_order_acquire))) {
        return;
    }

    init_slow_path();
}

static inline void enforce_init(void) {
    if (!atomic_load_explicit(&ro.initialized, memory_order_acquire)) {
        fatal_error("invalid uninitialized allocator usage");
    }
}

static inline bool is_init(void) {
    return atomic_load_explicit(&ro.initialized, memory_order_acquire);
}

static size_t get_guard_size(struct random_state *state, size_t size) {
    return (get_random_u64_uniform(state, size / PAGE_SIZE / 8) + 1) * PAGE_SIZE;
}

static void *allocate(size_t size) {
    if (size <= max_slab_size_class) {
        return slab_allocate(size);
    }

    pthread_mutex_lock(&regions_lock);
    size_t guard_size = get_guard_size(&regions_rng, size);
    pthread_mutex_unlock(&regions_lock);

    void *p = allocate_pages(size, guard_size, true);
    if (p == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&regions_lock);
    if (regions_insert(p, size, guard_size)) {
        pthread_mutex_unlock(&regions_lock);
        deallocate_pages(p, size, guard_size);
        return NULL;
    }
    pthread_mutex_unlock(&regions_lock);

    return p;
}

static void deallocate(void *p) {
    if (p >= ro.slab_region_start && p < ro.slab_region_end) {
        slab_free(p);
        return;
    }

    pthread_mutex_lock(&regions_lock);
    struct region_info *region = regions_find(p);
    if (region == NULL) {
        fatal_error("invalid free");
    }
    size_t size = region->size;
    size_t guard_size = region->guard_size;
    regions_delete(region);
    pthread_mutex_unlock(&regions_lock);

    deallocate_pages(p, size, guard_size);
}

EXPORT void *h_malloc(size_t size) {
    init();
    return allocate(size);
}

EXPORT void *h_calloc(size_t nmemb, size_t size) {
    size_t total_size;
    if (unlikely(__builtin_mul_overflow(nmemb, size, &total_size))) {
        errno = ENOMEM;
        return NULL;
    }
    init();
    return allocate(total_size);
}

static const size_t mremap_threshold = 4 * 1024 * 1024;

EXPORT void *h_realloc(void *old, size_t size) {
    if (old == NULL) {
        init();
        return allocate(size);
    }

    enforce_init();

    if (size == 0) {
        deallocate(old);
        return allocate(size);
    }

    size_t old_size;
    if (old >= ro.slab_region_start && old < ro.slab_region_end) {
        old_size = slab_usable_size(old);
        if (size <= max_slab_size_class && get_size_info(size).size == old_size) {
            return old;
        }
    } else {
        pthread_mutex_lock(&regions_lock);
        struct region_info *region = regions_find(old);
        if (region == NULL) {
            fatal_error("invalid realloc");
        }
        old_size = region->size;
        if (PAGE_CEILING(old_size) == PAGE_CEILING(size)) {
            region->size = size;
            pthread_mutex_unlock(&regions_lock);
            return old;
        }
        pthread_mutex_unlock(&regions_lock);

        size_t copy_size = size < old_size ? size : old_size;
        if (copy_size >= mremap_threshold) {
            void *new = allocate(size);
            if (new == NULL) {
                return NULL;
            }

            pthread_mutex_lock(&regions_lock);
            struct region_info *region = regions_find(old);
            if (region == NULL) {
                fatal_error("invalid realloc");
            }
            size_t old_guard_size = region->guard_size;
            regions_delete(region);
            pthread_mutex_unlock(&regions_lock);

            if (memory_remap_fixed(old, old_size, new, size)) {
                memcpy(new, old, copy_size);
                deallocate_pages(old, old_size, old_guard_size);
            } else {
                memory_unmap((char *)old - old_guard_size, old_guard_size);
                memory_unmap((char *)old + PAGE_CEILING(old_size), old_guard_size);
            }
            return new;
        }
    }

    void *new = allocate(size);
    if (new == NULL) {
        return NULL;
    }
    size_t copy_size = size < old_size ? size : old_size;
    memcpy(new, old, copy_size);
    deallocate(old);
    return new;
}

static int alloc_aligned(void **memptr, size_t alignment, size_t size, size_t min_alignment) {
    if ((alignment - 1) & alignment || alignment < min_alignment) {
        return EINVAL;
    }

    if (alignment <= PAGE_SIZE) {
        if (size < alignment) {
            size = alignment;
        }

        void *p = allocate(size);
        if (p == NULL) {
            return ENOMEM;
        }
        *memptr = p;
        return 0;
    }

    pthread_mutex_lock(&regions_lock);
    size_t guard_size = get_guard_size(&regions_rng, size);
    pthread_mutex_unlock(&regions_lock);

    void *p = allocate_pages_aligned(size, alignment, guard_size);
    if (p == NULL) {
        return ENOMEM;
    }

    pthread_mutex_lock(&regions_lock);
    if (regions_insert(p, size, guard_size)) {
        pthread_mutex_unlock(&regions_lock);
        deallocate_pages(p, size, guard_size);
        return ENOMEM;
    }
    pthread_mutex_unlock(&regions_lock);

    *memptr = p;
    return 0;
}

static void *alloc_aligned_simple(size_t alignment, size_t size) {
    void *ptr;
    int ret = alloc_aligned(&ptr, alignment, size, 1);
    if (ret) {
        errno = ret;
        return NULL;
    }
    return ptr;
}

EXPORT int h_posix_memalign(void **memptr, size_t alignment, size_t size) {
    init();
    return alloc_aligned(memptr, alignment, size, sizeof(void *));
}

EXPORT void *h_aligned_alloc(size_t alignment, size_t size) {
    if (size % alignment) {
        errno = EINVAL;
        return NULL;
    }
    init();
    return alloc_aligned_simple(alignment, size);
}

EXPORT void *h_memalign(size_t alignment, size_t size) {
    init();
    return alloc_aligned_simple(alignment, size);
}

EXPORT void *h_valloc(size_t size) {
    init();
    return alloc_aligned_simple(PAGE_SIZE, size);
}

EXPORT void *h_pvalloc(size_t size) {
    size_t rounded = PAGE_CEILING(size);
    if (!rounded) {
        errno = ENOMEM;
        return NULL;
    }
    init();
    return alloc_aligned_simple(PAGE_SIZE, rounded);
}

EXPORT void h_free(void *p) {
    if (p == NULL) {
        return;
    }

    enforce_init();
    deallocate(p);
}

EXPORT void h_cfree(void *ptr) ALIAS(h_free);

EXPORT size_t h_malloc_usable_size(void *p) {
    if (p == NULL) {
        return 0;
    }

    enforce_init();

    if (p >= ro.slab_region_start && p < ro.slab_region_end) {
        return slab_usable_size(p);
    }

    pthread_mutex_lock(&regions_lock);
    struct region_info *region = regions_find(p);
    if (p == NULL) {
        fatal_error("invalid malloc_usable_size");
    }
    size_t size = region->size;
    pthread_mutex_unlock(&regions_lock);

    return size;
}

EXPORT size_t h_malloc_object_size(void *p) {
    if (p == NULL || !is_init()) {
        return 0;
    }

    if (p >= ro.slab_region_start && p < ro.slab_region_end) {
        return slab_usable_size(p);
    }

    pthread_mutex_lock(&regions_lock);
    struct region_info *region = regions_find(p);
    size_t size = p == NULL ? SIZE_MAX : region->size;
    pthread_mutex_unlock(&regions_lock);

    return size;
}

EXPORT size_t h_malloc_object_size_fast(void *p) {
    if (p == NULL || !is_init()) {
        return 0;
    }

    if (p >= ro.slab_region_start && p < ro.slab_region_end) {
        return slab_usable_size(p);
    }

    return SIZE_MAX;
}

EXPORT int h_mallopt(UNUSED int param, UNUSED int value) {
    return 0;
}

static const size_t pad_threshold = 16 * 1024 * 1024;

EXPORT int h_malloc_trim(size_t pad) {
    if (pad > pad_threshold) {
        return 0;
    }

    if (!is_init()) {
        return 0;
    }

    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        struct size_class *c = &size_class_metadata[i];
        pthread_mutex_lock(&c->mutex);
        // TODO: purge and memory protect all free slabs
        pthread_mutex_unlock(&c->mutex);
    }

    return 0;
}

EXPORT void h_malloc_stats(void) {}

EXPORT struct mallinfo h_mallinfo(void) {
    return (struct mallinfo){0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
}

EXPORT int h_malloc_info(UNUSED int options, UNUSED FILE *fp) {
    errno = ENOSYS;
    return -1;
}

COLD EXPORT void *h_malloc_get_state(void) {
    return NULL;
}

COLD EXPORT int h_malloc_set_state(UNUSED void *state) {
    return -2;
}
