// needed to uncondionally enable assertions
#undef NDEBUG
#include <assert.h>
#include <malloc.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <map>
#include <set>
#include <string>
#include <unordered_map>

#include "../../arm_mte.h"

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

void *set_pointer_tag(void *ptr, u8 tag) {
    return (void *) (((uintptr_t) tag << 56) | (uintptr_t) untag_pointer(ptr));
}

// This test checks that slab slot allocation uses tag that is distint from tags of its neighbors
// and from the tag of the previous allocation that used the same slot
void tag_distinctness() {
    // tag 0 is reserved
    const int min_tag = 1;
    const int max_tag = 0xf;

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

        // check that all of the tags were used, except for the reserved tag 0
        assert(seen_tags == (0xffff & ~(1 << 0)));

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
    const size_t full_alloc_size = DEFAULT_ALLOC_SIZE + CANARY_SIZE;
    set<uptr> addrs;

    // make sure allocation has both left and right neighbors, otherwise overflow/underflow tests
    // will fail when allocation is at the end/beginning of slab
    for (;;) {
        u8 *p = (u8 *) malloc(DEFAULT_ALLOC_SIZE);
        assert(p);

        uptr addr = (uptr) untag_pointer(p);
        uptr left = addr - full_alloc_size;
        if (addrs.find(left) != addrs.end()) {
            uptr right = addr + full_alloc_size;
            if (addrs.find(right) != addrs.end()) {
                return p;
            }
        }

        addrs.emplace(addr);
    }
}

int expected_segv_code;

#define expect_segv(exp, segv_code) ({\
    expected_segv_code = segv_code; \
    volatile auto val = exp; \
    (void) val; \
    do_context_switch(); \
    fprintf(stderr, "didn't receive SEGV code %i", segv_code); \
    exit(1); })

// it's expected that the device is configured to use asymm MTE tag checking mode (sync read checks,
// async write checks)
#define expect_read_segv(exp) expect_segv(exp, SEGV_MTESERR)
#define expect_write_segv(exp) expect_segv(exp, SEGV_MTEAERR)

void read_after_free() {
    u8 *p = alloc_default();
    free(p);
    expect_read_segv(p[0]);
}

void write_after_free() {
    u8 *p = alloc_default();
    free(p);
    expect_write_segv(p[0] = 1);
}

void underflow_read() {
    u8 *p = alloc_default();
    expect_read_segv(p[-1]);
}

void underflow_write() {
    u8 *p = alloc_default();
    expect_write_segv(p[-1] = 1);
}

void overflow_read() {
    u8 *p = alloc_default();
    expect_read_segv(p[DEFAULT_ALLOC_SIZE + CANARY_SIZE]);
}

void overflow_write() {
    u8 *p = alloc_default();
    expect_write_segv(p[DEFAULT_ALLOC_SIZE + CANARY_SIZE] = 1);
}

void untagged_read() {
    u8 *p = alloc_default();
    p = (u8 *) untag_pointer(p);
    expect_read_segv(p[0]);
}

void untagged_write() {
    u8 *p = alloc_default();
    p = (u8 *) untag_pointer(p);
    expect_write_segv(p[0] = 1);
}

// checks that each of memory locations inside the buffer is tagged with expected_tag
void check_tag(void *buf, size_t len, u8 expected_tag) {
    for (size_t i = 0; i < len; ++i) {
        assert(get_pointer_tag(__arm_mte_get_tag((void *) ((uintptr_t) buf + i))) == expected_tag);
    }
}

void madvise_dontneed() {
    const size_t len = 100'000;
    void *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE | PROT_MTE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert(ptr != MAP_FAILED);

    // check that 0 is the initial tag
    check_tag(ptr, len, 0);

    arm_mte_tag_and_clear_mem(set_pointer_tag(ptr, 1), len);
    check_tag(ptr, len, 1);

    memset(set_pointer_tag(ptr, 1), 1, len);

    assert(madvise(ptr, len, MADV_DONTNEED) == 0);
    // check that MADV_DONTNEED resets the tag
    check_tag(ptr, len, 0);

    // check that MADV_DONTNEED clears the memory
    for (size_t i = 0; i < len; ++i) {
        assert(((u8 *) ptr)[i] == 0);
    }

    // check that mistagged read after MADV_DONTNEED fails
    expect_read_segv(*((u8 *) set_pointer_tag(ptr, 1)));
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
    TEST(madvise_dontneed),
#undef TEST
};

void segv_handler(int, siginfo_t *si, void *) {
    if (expected_segv_code == 0 || expected_segv_code != si->si_code) {
        fprintf(stderr, "received unexpected SEGV_CODE %i", si->si_code);
        exit(139); // standard exit code for SIGSEGV
    }

    exit(0);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    assert(argc == 2);

    auto test_name = string(argv[1]);
    auto test_fn = tests[test_name];
    assert(test_fn != nullptr);

    assert(mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_ASYNC) == 1);

    struct sigaction sa = {
        .sa_sigaction = segv_handler,
        .sa_flags = SA_SIGINFO,
    };

    assert(sigaction(SIGSEGV, &sa, nullptr) == 0);

    test_fn();
    do_context_switch();
    
    return 0;
}
