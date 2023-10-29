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

void tag_distinctness() {
    const size_t cnt = 3000;
    const size_t iter_cnt = 5;
    const size_t alloc_cnt = cnt * iter_cnt;

    const int sizes[] = { 16, 160, 10240, 20480 };

    for (size_t size_idx = 0; size_idx < sizeof(sizes) / sizeof(int); ++size_idx) {
        const size_t full_alloc_size = sizes[size_idx];
        const size_t alloc_size = full_alloc_size - CANARY_SIZE;

        unordered_map<uptr, u8> map;
        map.reserve(alloc_cnt);

        for (size_t iter = 0; iter < iter_cnt; ++iter) {
            uptr allocations[cnt];

            for (size_t i = 0; i < cnt; ++i) {
                u8 *p = (u8 *) malloc(alloc_size);
                uptr addr = (uptr) untag_pointer(p);
                u8 tag = get_pointer_tag(p);
                assert(tag >= 1 && tag <= 14);

                // check most recent tags of left and right neighbors

                auto left = map.find(addr - full_alloc_size);
                if (left != map.end()) {
                    assert(left->second != tag);
                }

                auto right = map.find(addr + full_alloc_size);
                if (right != map.end()) {
                    assert(right->second != tag);
                }

                // check previous tag of this slot
                auto prev = map.find(addr);
                if (prev != map.end()) {
                    assert(prev->second != tag);
                    map.erase(addr);
                }

                map.emplace(addr, tag);

                for (size_t j = 0; j < alloc_size; ++j) {
                    // check that slot is zeroed
                    assert(p[j] == 0);
                    // check that slot is readable and writable
                    p[j]++;
                }

                allocations[i] = addr;
                // async tag check failures are reported on context switch
                do_context_switch();
            }

            for (size_t i = 0; i < cnt; ++i) {
                free((void *) allocations[i]);
            }
        }
    }
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
