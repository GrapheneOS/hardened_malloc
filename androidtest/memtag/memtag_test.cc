// needed to uncondionally enable assertions
#undef NDEBUG
#include <assert.h>
#include <malloc.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <map>
#include <string>
#include <unordered_map>

using namespace std;

using u8 = uint8_t;
using uptr = uintptr_t;
using u64 = uint64_t;

const size_t DEFAULT_ALLOC_SIZE = 8;
const size_t CANARY_SIZE = 8;

void do_context_switch() {
    utsname s;
    uname(&s);
}

u8 get_pointer_tag(void *ptr) {
    return (((uptr) ptr) >> 56) & 0xf;
}

void *untag_pointer(void *ptr) {
    const uintptr_t mask = UINTPTR_MAX >> 8;
    return (void *) ((uintptr_t) ptr & mask);
}

// This test checks that slab slot allocation uses tag that is distint from tags of its neighbors
// and from the tag of the previous allocation that used the same slot
void tag_distinctness() {
    // 0 and 15 are reserved
    const int min_tag = 1;
    const int max_tag = 14;

    struct SizeClass {
        int size;
        int slot_cnt;
    };

    // values from size_classes[] and size_class_slots[] in h_malloc.c
    SizeClass size_classes[] = {
        { .size = 16,    .slot_cnt = 256, },
        { .size = 32,    .slot_cnt = 128, },
        // this size class is used by allocations that are made by the addr_tag_map, which breaks
        // tag distinctess checks
        // { .size = 48,    .slot_cnt = 85,  },
        { .size = 64,    .slot_cnt = 64,  },
        { .size = 80,    .slot_cnt = 51,  },
        { .size = 96,    .slot_cnt = 42,  },
        { .size = 112,   .slot_cnt = 36,  },
        { .size = 128,   .slot_cnt = 64,  },
        { .size = 160,   .slot_cnt = 51,  },
        { .size = 192,   .slot_cnt = 64,  },
        { .size = 224,   .slot_cnt = 54,  },
        { .size = 10240, .slot_cnt = 6,   },
        { .size = 20480, .slot_cnt = 1,   },
    };

    int tag_usage[max_tag + 1];

    for (size_t sc_idx = 0; sc_idx < sizeof(size_classes) / sizeof(SizeClass); ++sc_idx) {
        SizeClass &sc = size_classes[sc_idx];

        const size_t full_alloc_size = sc.size;
        const size_t alloc_size = full_alloc_size - CANARY_SIZE;

        // "tdc" is short for "tag distinctness check"
        int left_neighbor_tdc_cnt = 0;
        int right_neighbor_tdc_cnt = 0;
        int prev_alloc_tdc_cnt = 0;

        int iter_cnt = 600;

        unordered_map<uptr, u8> addr_tag_map;
        addr_tag_map.reserve(iter_cnt * sc.slot_cnt);

        u64 seen_tags = 0;

        for (int iter = 0; iter < iter_cnt; ++iter) {
            uptr allocations[256]; // 256 is max slot count

            for (int i = 0; i < sc.slot_cnt; ++i) {
                u8 *p = (u8 *) malloc(alloc_size);
                assert(p);
                uptr addr = (uptr) untag_pointer(p);
                u8 tag = get_pointer_tag(p);

                assert(tag >= min_tag && tag <= max_tag);
                seen_tags |= 1 << tag;
                ++tag_usage[tag];

                // check most recent tags of left and right neighbors

                auto left = addr_tag_map.find(addr - full_alloc_size);
                if (left != addr_tag_map.end()) {
                    assert(left->second != tag);
                    ++left_neighbor_tdc_cnt;
                }

                auto right = addr_tag_map.find(addr + full_alloc_size);
                if (right != addr_tag_map.end()) {
                    assert(right->second != tag);
                    ++right_neighbor_tdc_cnt;
                }

                // check previous tag of this slot
                auto prev = addr_tag_map.find(addr);
                if (prev != addr_tag_map.end()) {
                    assert(prev->second != tag);
                    ++prev_alloc_tdc_cnt;
                    addr_tag_map.erase(addr);
                }

                addr_tag_map.emplace(addr, tag);

                for (size_t j = 0; j < alloc_size; ++j) {
                    // check that slot is zeroed
                    assert(p[j] == 0);
                    // check that slot is readable and writable
                    p[j]++;
                }

                allocations[i] = addr;
            }

            // free some of allocations to allow their slots to be reused
            for (int i = sc.slot_cnt - 1; i >= 0; i -= 2) {
                free((void *) allocations[i]);
            }
        }

        // check that all of the tags were used, except reserved ones
        assert(seen_tags == (0xffff & ~(1 << 0 | 1 << 15)));

        printf("size_class\t%i\t" "tdc_left %i\t" "tdc_right %i\t" "tdc_prev_alloc %i\n",
               sc.size, left_neighbor_tdc_cnt, right_neighbor_tdc_cnt, prev_alloc_tdc_cnt);

        // make sure tag distinctess checks were actually performed
        int min_tdc_cnt = sc.slot_cnt * iter_cnt / 5;

        assert(prev_alloc_tdc_cnt > min_tdc_cnt);

        if (sc.slot_cnt > 1) {
            assert(left_neighbor_tdc_cnt > min_tdc_cnt);
            assert(right_neighbor_tdc_cnt > min_tdc_cnt);
        }

        // async tag check failures are reported on context switch
        do_context_switch();
    }

    printf("\nTag use counters:\n");

    int min = INT_MAX;
    int max = 0;
    double geomean = 0.0;
    for (int i = min_tag; i <= max_tag; ++i) {
        int v = tag_usage[i];
        geomean += log(v);
        min = std::min(min, v);
        max = std::max(max, v);
        printf("%i\t%i\n", i, tag_usage[i]);
    }
    int tag_cnt = 1 + max_tag - min_tag;
    geomean = exp(geomean / tag_cnt);

    double max_deviation = std::max((double) max - geomean, geomean - min);

    printf("geomean: %.2f, max deviation from geomean: %.2f%%\n", geomean, (100.0 * max_deviation) / geomean);
}

u8* alloc_default() {
    u8 *p = (u8 *) malloc(DEFAULT_ALLOC_SIZE);
    assert(p);
    return p;
}

volatile u8 u8_var;

void read_after_free() {
    u8 *p = alloc_default();
    free(p);
    volatile u8 v = p[0];
    (void) v;
}

void write_after_free() {
    u8 *p = alloc_default();
    free(p);
    p[0] = 1;
}

void underflow_read() {
    u8 *p = alloc_default();
    volatile u8 v = p[-1];
    (void) v;
}

void underflow_write() {
    u8 *p = alloc_default();
    p[-1] = 1;
}

void overflow_read() {
    u8 *p = alloc_default();
    volatile u8 v = p[DEFAULT_ALLOC_SIZE + CANARY_SIZE];
    (void) v;
}

void overflow_write() {
    u8 *p = alloc_default();
    p[DEFAULT_ALLOC_SIZE + CANARY_SIZE] = 1;
}

void untagged_read() {
    u8 *p = alloc_default();
    p = (u8 *) untag_pointer(p);
    volatile u8 v = p[0];
    (void) v;
}

void untagged_write() {
    u8 *p = alloc_default();
    p = (u8 *) untag_pointer(p);
    p[0] = 1;
}

map<string, function<void()>> tests = {
#define TEST(s) { #s, s }
    TEST(tag_distinctness),
    TEST(read_after_free),
    TEST(write_after_free),
    TEST(overflow_read),
    TEST(overflow_write),
    TEST(underflow_read),
    TEST(underflow_write),
    TEST(untagged_read),
    TEST(untagged_write),
#undef TEST
};

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    assert(argc == 2);

    auto test_name = string(argv[1]);
    auto test_fn = tests[test_name];
    assert(test_fn != nullptr);

    assert(mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_ASYNC) == 1);

    test_fn();
    do_context_switch();
    
    return 0;
}
