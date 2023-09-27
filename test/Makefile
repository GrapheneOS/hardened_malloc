CONFIG_SLAB_CANARY := true
CONFIG_EXTENDED_SIZE_CLASSES := true

ifneq ($(VARIANT),)
    $(error testing non-default variants not yet supported)
endif

ifeq (,$(filter $(CONFIG_SLAB_CANARY),true false))
    $(error CONFIG_SLAB_CANARY must be true or false)
endif

dir=$(dir $(realpath $(firstword $(MAKEFILE_LIST))))

CPPFLAGS := \
    -D_GNU_SOURCE \
    -DSLAB_CANARY=$(CONFIG_SLAB_CANARY) \
    -DCONFIG_EXTENDED_SIZE_CLASSES=$(CONFIG_EXTENDED_SIZE_CLASSES)

SHARED_FLAGS := -O3

CFLAGS := -std=c17 $(SHARED_FLAGS) -Wmissing-prototypes
CXXFLAGS := -std=c++17 -fsized-deallocation $(SHARED_FLAGS)
LDFLAGS := -Wl,-L$(dir)../out,-R,$(dir)../out

LDLIBS := -lpthread -lhardened_malloc

EXECUTABLES := \
    offset \
    mallinfo \
    mallinfo2 \
    malloc_info \
    large_array_growth \
    double_free_large \
    double_free_large_delayed \
    double_free_small \
    double_free_small_delayed \
    unaligned_free_large \
    unaligned_free_small \
    read_after_free_large \
    read_after_free_small \
    write_after_free_large \
    write_after_free_large_reuse \
    write_after_free_small \
    write_after_free_small_reuse \
    read_zero_size \
    write_zero_size \
    invalid_free_protected \
    invalid_free_unprotected \
    invalid_free_small_region \
    invalid_free_small_region_far \
    uninitialized_read_small \
    uninitialized_read_large \
    uninitialized_free \
    uninitialized_realloc \
    uninitialized_malloc_usable_size \
    overflow_large_1_byte \
    overflow_large_8_byte \
    overflow_small_1_byte \
    overflow_small_8_byte \
    string_overflow \
    delete_type_size_mismatch \
    unaligned_malloc_usable_size_small \
    invalid_malloc_usable_size_small \
    invalid_malloc_usable_size_small_quarantine \
    malloc_object_size \
    malloc_object_size_offset \
    invalid_malloc_object_size_small \
    invalid_malloc_object_size_small_quarantine \
    impossibly_large_malloc \
    realloc_init

all: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
	rm -fr ./__pycache__
