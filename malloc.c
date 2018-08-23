#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>

#include <malloc.h>

#include "malloc.h"
#include "random.h"
#include "util.h"

static_assert(sizeof(void *) == 8, "64-bit only");

#define PAGE_SHIFT 12
#define PAGE_SIZE ((size_t)1 << PAGE_SHIFT)
#define PAGE_MASK ((size_t)(PAGE_SIZE - 1))
#define PAGE_CEILING(s) (((s) + PAGE_MASK) & ~PAGE_MASK)

#define MIN_ALIGN 16
#define ALIGNMENT_CEILING(s, alignment)	(((s) + (alignment - 1)) & ((~(alignment)) + 1))

static const size_t guard_size = PAGE_SIZE;

// TODO: can be removed once the work is further along
COLD static noreturn void unimplemented(void) {
    fatal_error("unimplemented");
}

static void *memory_map(size_t size) {
    void *p = mmap(NULL, size, PROT_NONE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) {
        return NULL;
    }
    return p;
}

static int memory_unmap(void *ptr, size_t size) {
    int ret = munmap(ptr, size);
    if (ret && errno != ENOMEM) {
        fatal_error("non-ENOMEM munmap failure");
    }
    return ret;
}

static void *allocate_pages(size_t usable_size, bool unprotect) {
    usable_size = PAGE_CEILING(usable_size);

    size_t real_size;
    if (__builtin_add_overflow(usable_size, guard_size * 2, &real_size)) {
        return NULL;
    }
    void *real = memory_map(real_size);
    if (real == NULL) {
        return NULL;
    }
    void *usable = (char *)real + guard_size;
    if (unprotect && mprotect(usable, usable_size, PROT_READ|PROT_WRITE)) {
        memory_unmap(real, real_size);
        return NULL;
    }
    return usable;
}

static void deallocate_pages(void *usable, size_t usable_size) {
    usable_size = PAGE_CEILING(usable_size);

    memory_unmap((char *)usable - guard_size, usable_size + guard_size * 2);
}

static void *allocate_pages_aligned(size_t usable_size, size_t alignment) {
    usable_size = PAGE_CEILING(usable_size);

    size_t alloc_size;
    if (__builtin_add_overflow(usable_size, alignment - PAGE_SIZE, &alloc_size)) {
        return NULL;
    }

    size_t real_alloc_size;
    if (__builtin_add_overflow(alloc_size, guard_size * 2, &real_alloc_size)) {
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

    if (mprotect(base, usable_size, PROT_READ|PROT_WRITE)) {
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
    /* 16 */ 256, 128, 128, 64, 51, 42, 36, 64,
    /* 32 */ 51, 64, 64, 64,
    /* 64 */ 64, 64, 64, 64,
    /* 128 */ 64, 64, 64, 64,
    /* 256 */ 16, 16, 16, 16,
    /* 512 */ 8, 8, 8, 8,
    /* 1024 */ 8, 8, 8, 8,
    /* 2048 */ 5, 6, 4, 4
};

#define N_SIZE_CLASSES (sizeof(size_classes) / sizeof(size_classes[0]))

struct size_info {
    size_t size;
    size_t class;
};

static struct size_info get_size_info(size_t size) {
    for (size_t i = 0; i < N_SIZE_CLASSES; i++) {
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
    void *class_region_start;
    size_t metadata_allocated;
    size_t metadata_count;
    struct slab_metadata *partial_slabs;
    struct slab_metadata *free_slabs;
    struct slab_metadata *slab_info;
    pthread_mutex_t mutex;
} size_class_metadata[N_SIZE_CLASSES];

static const size_t class_region_size = 128ULL * 1024 * 1024 * 1024;
static const size_t real_class_region_size = class_region_size * 2;
static const size_t slab_region_size = real_class_region_size * N_SIZE_CLASSES;
static_assert(PAGE_SIZE == 4096, "bitmap handling will need adjustment for other page sizes");

static size_t get_metadata_max(size_t slab_size) {
    return class_region_size / slab_size;
}

static struct slab_metadata *alloc_metadata(struct size_class *c, size_t slab_size) {
    if (c->metadata_count == c->metadata_allocated) {
        size_t metadata_max = get_metadata_max(slab_size);
        if (c->metadata_count == metadata_max) {
            return NULL;
        }
        size_t allocate = c->metadata_allocated * 2;
        if (allocate > metadata_max) {
            allocate = metadata_max;
        }
        if (mprotect(c->slab_info, allocate * sizeof(struct slab_metadata), PROT_READ|PROT_WRITE)) {
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
    if (slots > 64) return 0; // TODO: implement multi-word bitmaps
    return slots < 64 ? ~0UL << slots : 0;
}

static size_t first_free_slot(size_t slots, struct slab_metadata *metadata) {
    size_t masked = metadata->bitmap | get_mask(slots);
    if (masked == ~0UL) {
        fatal_error("no zero bits");
    }
    return __builtin_ffsl(~masked) - 1;
}

static bool has_free_slots(size_t slots, struct slab_metadata *metadata) {
    size_t masked = metadata->bitmap | get_mask(slots);
    return masked != ~0UL;
}

static bool is_free_slab(struct slab_metadata *metadata) {
    return !metadata->bitmap;
}

static void *get_slab(struct size_class *c, size_t slab_size, struct slab_metadata *metadata) {
    size_t index = metadata - c->slab_info;
    return (char *)c->class_region_start + (index * slab_size);
}

static struct slab_metadata *get_metadata(struct size_class *c, size_t slab_size, void *p) {
    size_t offset = (char *)p - (char *)c->class_region_start;
    size_t index = offset / slab_size;
    return c->slab_info + index;
}

static void *slab_allocate(size_t requested_size) {
    struct size_info info = get_size_info(requested_size);
    size_t size = info.size;
    struct size_class *c = &size_class_metadata[info.class];
    size_t slots = size_class_slots[info.class];
    size_t slab_size = get_slab_size(slots, size);

    pthread_mutex_lock(&c->mutex);

    if (c->partial_slabs == NULL) {
        if (c->free_slabs != NULL) {
            struct slab_metadata *metadata = c->free_slabs;
            c->free_slabs = c->free_slabs->next;
            if (c->free_slabs) {
                c->free_slabs->prev = NULL;
            }

            metadata->next = c->partial_slabs;
            metadata->prev = NULL;

            if (c->partial_slabs) {
                c->partial_slabs->prev = metadata;
            }
            c->partial_slabs = metadata;

            void *slab = get_slab(c, slab_size, metadata);
            set_slot(metadata, 0);
            pthread_mutex_unlock(&c->mutex);
            return slab;
        }

        struct slab_metadata *metadata = alloc_metadata(c, slab_size);
        if (metadata == NULL) {
            pthread_mutex_unlock(&c->mutex);
            return NULL;
        }

        void *slab = get_slab(c, slab_size, metadata);
        if (mprotect(slab, slab_size, PROT_READ|PROT_WRITE)) {
            metadata->next = c->free_slabs;
            if (c->free_slabs) {
                c->free_slabs->prev = metadata;
            }
            c->free_slabs = metadata;

            // TODO: implement memory protected free slabs
            unimplemented();

            pthread_mutex_unlock(&c->mutex);
            return NULL;
        }

        c->partial_slabs = metadata;
        set_slot(metadata, 0);

        pthread_mutex_unlock(&c->mutex);
        return slab;
    }

    struct slab_metadata *metadata = c->partial_slabs;
    size_t slot = first_free_slot(slots, metadata);
    set_slot(metadata, slot);

    if (!has_free_slots(slots, metadata)) {
        c->partial_slabs = c->partial_slabs->next;
        if (c->partial_slabs) {
            c->partial_slabs->prev = NULL;
        }
    }

    void *slab = get_slab(c, slab_size, metadata);
    void *p = (char *)slab + slot * size;

    pthread_mutex_unlock(&c->mutex);
    return p;
}

static size_t slab_size_class(void *p) {
    size_t offset = (char *)p - (char *)ro.slab_region_start;
    return offset / class_region_size;
}

static size_t slab_usable_size(void *p) {
    return size_classes[slab_size_class(p)];
}

static void slab_free(void *p) {
    size_t class = slab_size_class(p);

    struct size_class *c = &size_class_metadata[class];
    size_t size = size_classes[class];
    size_t slots = size_class_slots[class];
    size_t slab_size = get_slab_size(slots, size);

    pthread_mutex_lock(&c->mutex);

    struct slab_metadata *metadata = get_metadata(c, slab_size, p);
    if (!has_free_slots(slots, metadata)) {
        metadata->next = c->partial_slabs;
        metadata->prev = NULL;

        if (c->partial_slabs) {
            c->partial_slabs->prev = metadata;
        }
        c->partial_slabs = metadata;
    }

    void *slab = get_slab(c, slab_size, metadata);
    size_t slot = ((char *)p - (char *)slab) / size;
    if (!get_slot(metadata, slot)) {
        fatal_error("double free");
    }
    clear_slot(metadata, slot);
    memset(p, 0, size);

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

        metadata->next = c->free_slabs;
        metadata->prev = NULL;

        if (c->free_slabs) {
            c->free_slabs->prev = metadata;
        }
        c->free_slabs = metadata;
    }

    pthread_mutex_unlock(&c->mutex);
}

struct region_info {
    void *p;
    size_t size;
};

static const size_t initial_region_table_size = 256;

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

    struct region_info *p = allocate_pages(newsize, true);
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

    deallocate_pages(regions, regions_total * sizeof(struct region_info));
    regions_free = regions_free + regions_total;
    regions_total = newtotal;
    regions = p;
    return 0;
}

static int regions_insert(void *p, size_t size) {
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
    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        if (pthread_mutex_init(&size_class_metadata[i].mutex, NULL)) {
            fatal_error("mutex initialization failed");
        }
    }
}

COLD static void init_slow_path(void) {
    static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

    pthread_mutex_lock(&mutex);

    if (atomic_load_explicit(&ro.initialized, memory_order_acquire)) {
        pthread_mutex_unlock(&mutex);
        return;
    }

    pthread_atfork(pre_fork, post_fork_parent, post_fork_child);

    struct random_state rng;
    random_state_init(&rng);

    regions = allocate_pages(regions_total * sizeof(struct region_info), true);
    if (regions == NULL) {
        fatal_error("failed to set up allocator");
    }

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

        size_t gap = (get_random_size_uniform(&rng, (real_class_region_size - class_region_size) / PAGE_SIZE) + 1) * PAGE_SIZE;
        c->class_region_start = (char *)ro.slab_region_start + class_region_size * i + gap;

        size_t size = size_classes[i];
        size_t slots = size_class_slots[i];
        size_t metadata_max = get_metadata_max(get_slab_size(slots, size));
        c->slab_info = allocate_pages(metadata_max * sizeof(struct slab_metadata), false);
        if (c->slab_info == NULL) {
            fatal_error("failed to allocate slab metadata");
        }
        c->metadata_allocated = 32;
        if (mprotect(c->slab_info, c->metadata_allocated * sizeof(struct slab_metadata), PROT_READ|PROT_WRITE)) {
            fatal_error("failed to allocate initial slab info");
        }
    }

    atomic_store_explicit(&ro.initialized, true, memory_order_release);

    if (mprotect(&ro, sizeof(ro), PROT_READ)) {
        fatal_error("failed to protect allocator data");
    }

    pthread_mutex_unlock(&mutex);
}

static void init(void) {
    if (likely(atomic_load_explicit(&ro.initialized, memory_order_acquire))) {
        return;
    }

    init_slow_path();
}

static void enforce_init(void) {
    if (!atomic_load_explicit(&ro.initialized, memory_order_acquire)) {
        fatal_error("invalid uninitialized allocator usage");
    }
}

static void *allocate(size_t size) {
    if (size <= max_slab_size_class) {
        return slab_allocate(size);
    }

    void *p = allocate_pages(size, true);
    if (p == NULL) {
        return NULL;
    }

    pthread_mutex_lock(&regions_lock);
    if (regions_insert(p, size)) {
        pthread_mutex_unlock(&regions_lock);
        deallocate_pages(p, size);
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
    regions_delete(region);
    pthread_mutex_unlock(&regions_lock);

    deallocate_pages(p, size);
}

EXPORT void *h_malloc(size_t size) {
    init();
    return allocate(size);
}

EXPORT void *h_calloc(size_t nmemb, size_t size) {
    size_t total_size;
    if (__builtin_mul_overflow(nmemb, size, &total_size)) {
        errno = ENOMEM;
        return NULL;
    }
    init();
    return allocate(total_size);
}

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

    void *p = allocate_pages_aligned(size, alignment);
    if (p == NULL) {
        return ENOMEM;
    }
    if (regions_insert(p, size)) {
        deallocate_pages(p, size);
        return ENOMEM;
    }
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

EXPORT void h_cfree(void *ptr) __attribute__((alias("free")));

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

EXPORT int h_mallopt(UNUSED int param, UNUSED int value) {
    return 0;
}

static const size_t pad_threshold = 16 * 1024 * 1024;

EXPORT int h_malloc_trim(size_t pad) {
    if (pad > pad_threshold) {
        return 0;
    }

    if (!atomic_load_explicit(&ro.initialized, memory_order_acquire)) {
        return 0;
    }

    for (unsigned i = 0; i < N_SIZE_CLASSES; i++) {
        struct size_class *c = &size_class_metadata[i];
        pthread_mutex_lock(&c->mutex);
        // TODO: purge and mprotect all free slabs
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
