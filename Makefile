CONFIG_WERROR := true
CONFIG_NATIVE := true
CONFIG_CXX_ALLOCATOR := true
CONFIG_UBSAN := false
CONFIG_SEAL_METADATA := false
CONFIG_ENFORCE_INIT := true
CONFIG_ZERO_ON_FREE := true
CONFIG_WRITE_AFTER_FREE_CHECK := true
CONFIG_SLOT_RANDOMIZE := true
CONFIG_SLAB_CANARY := true
CONFIG_SLAB_QUARANTINE_RANDOM_LENGTH := 1
CONFIG_SLAB_QUARANTINE_QUEUE_LENGTH := 1
CONFIG_EXTENDED_SIZE_CLASSES := true
CONFIG_LARGE_SIZE_CLASSES := true
CONFIG_GUARD_SLABS_INTERVAL := 1
CONFIG_GUARD_SIZE_DIVISOR := 2
CONFIG_REGION_QUARANTINE_RANDOM_LENGTH := 128
CONFIG_REGION_QUARANTINE_QUEUE_LENGTH := 1024
CONFIG_REGION_QUARANTINE_SKIP_THRESHOLD := 33554432 # 32MiB
CONFIG_FREE_SLABS_QUARANTINE_RANDOM_LENGTH := 32
CONFIG_CLASS_REGION_SIZE := 34359738368 # 32GiB
CONFIG_N_ARENA := 4
CONFIG_STATS := false

define safe_flag
$(shell $(CC) $(if $(filter clang,$(CC)),-Werror=unknown-warning-option) -E $1 - </dev/null >/dev/null 2>&1 && echo $1 || echo $2)
endef

CPPFLAGS := $(CPPFLAGS) -D_GNU_SOURCE -I include
SHARED_FLAGS := -O3 -flto -fPIC -fvisibility=hidden $(call safe_flag,-fno-plt) \
    $(call safe_flag,-fstack-clash-protection) -fstack-protector-strong -pipe -Wall -Wextra \
    $(call safe_flag,-Wcast-align=strict,-Wcast-align) -Wcast-qual -Wwrite-strings

ifeq ($(CC),clang)
    SHARED_FLAGS += -Wno-constant-logical-operand
endif

ifeq ($(CONFIG_WERROR),true)
    SHARED_FLAGS += -Werror
endif

ifeq ($(CONFIG_NATIVE),true)
    SHARED_FLAGS += -march=native
endif

CFLAGS := $(CFLAGS) -std=c11 $(SHARED_FLAGS) -Wmissing-prototypes
CXXFLAGS := $(CXXFLAGS) $(call safe_flag,-std=c++17,-std=c++14) $(SHARED_FLAGS)
LDFLAGS := $(LDFLAGS) -Wl,--as-needed,-z,defs,-z,relro,-z,now,-z,nodlopen,-z,text

SOURCES := chacha.c h_malloc.c memory.c pages.c random.c util.c
OBJECTS := $(SOURCES:.c=.o)

ifeq ($(CONFIG_CXX_ALLOCATOR),true)
    # make sure LTO is compatible in case CC and CXX don't match (such as clang and g++)
    CXX := $(CC)
    LDLIBS += -lstdc++ -lgcc_s

    SOURCES += new.cc
    OBJECTS += new.o
endif

ifeq ($(CONFIG_UBSAN),true)
    CFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
    CXXFLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
endif

ifeq (,$(filter $(CONFIG_SEAL_METADATA),true false))
    $(error CONFIG_SEAL_METADATA must be true or false)
endif

ifeq (,$(filter $(CONFIG_ENFORCE_INIT),true false))
    $(error CONFIG_ENFORCE_INIT must be true or false)
endif

ifeq (,$(filter $(CONFIG_ZERO_ON_FREE),true false))
    $(error CONFIG_ZERO_ON_FREE must be true or false)
endif

ifeq (,$(filter $(CONFIG_WRITE_AFTER_FREE_CHECK),true false))
    $(error CONFIG_WRITE_AFTER_FREE_CHECK must be true or false)
endif

ifeq (,$(filter $(CONFIG_SLOT_RANDOMIZE),true false))
    $(error CONFIG_SLOT_RANDOMIZE must be true or false)
endif

ifeq (,$(filter $(CONFIG_SLAB_CANARY),true false))
    $(error CONFIG_SLAB_CANARY must be true or false)
endif

ifeq (,$(filter $(CONFIG_EXTENDED_SIZE_CLASSES),true false))
    $(error CONFIG_EXTENDED_SIZE_CLASSES must be true or false)
endif

ifeq (,$(filter $(CONFIG_LARGE_SIZE_CLASSES),true false))
    $(error CONFIG_LARGE_SIZE_CLASSES must be true or false)
endif

ifeq (,$(filter $(CONFIG_STATS),true false))
    $(error CONFIG_STATS must be true or false)
endif

CPPFLAGS += \
    -DCONFIG_SEAL_METADATA=$(CONFIG_SEAL_METADATA) \
    -DCONFIG_ENFORCE_INIT=$(CONFIG_ENFORCE_INIT) \
    -DZERO_ON_FREE=$(CONFIG_ZERO_ON_FREE) \
    -DWRITE_AFTER_FREE_CHECK=$(CONFIG_WRITE_AFTER_FREE_CHECK) \
    -DSLOT_RANDOMIZE=$(CONFIG_SLOT_RANDOMIZE) \
    -DSLAB_CANARY=$(CONFIG_SLAB_CANARY) \
    -DSLAB_QUARANTINE_RANDOM_LENGTH=$(CONFIG_SLAB_QUARANTINE_RANDOM_LENGTH) \
    -DSLAB_QUARANTINE_QUEUE_LENGTH=$(CONFIG_SLAB_QUARANTINE_QUEUE_LENGTH) \
    -DCONFIG_EXTENDED_SIZE_CLASSES=$(CONFIG_EXTENDED_SIZE_CLASSES) \
    -DCONFIG_LARGE_SIZE_CLASSES=$(CONFIG_LARGE_SIZE_CLASSES) \
    -DGUARD_SLABS_INTERVAL=$(CONFIG_GUARD_SLABS_INTERVAL) \
    -DGUARD_SIZE_DIVISOR=$(CONFIG_GUARD_SIZE_DIVISOR) \
    -DREGION_QUARANTINE_RANDOM_LENGTH=$(CONFIG_REGION_QUARANTINE_RANDOM_LENGTH) \
    -DREGION_QUARANTINE_QUEUE_LENGTH=$(CONFIG_REGION_QUARANTINE_QUEUE_LENGTH) \
    -DREGION_QUARANTINE_SKIP_THRESHOLD=$(CONFIG_REGION_QUARANTINE_SKIP_THRESHOLD) \
    -DFREE_SLABS_QUARANTINE_RANDOM_LENGTH=$(CONFIG_FREE_SLABS_QUARANTINE_RANDOM_LENGTH) \
    -DCONFIG_CLASS_REGION_SIZE=$(CONFIG_CLASS_REGION_SIZE) \
    -DN_ARENA=$(CONFIG_N_ARENA) \
    -DCONFIG_STATS=$(CONFIG_STATS)

libhardened_malloc.so: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ $(LDLIBS) -o $@

chacha.o: chacha.c chacha.h util.h
h_malloc.o: h_malloc.c include/h_malloc.h mutex.h memory.h pages.h random.h util.h
memory.o: memory.c memory.h util.h
new.o: new.cc include/h_malloc.h util.h
pages.o: pages.c pages.h memory.h util.h
random.o: random.c random.h chacha.h util.h
util.o: util.c util.h

check: tidy

tidy:
	clang-tidy $(SOURCES) -- $(CPPFLAGS)

clean:
	rm -f libhardened_malloc.so $(OBJECTS)

test: libhardened_malloc.so
	make -C test/
	-python3 -m unittest discover --start-directory test/

.PHONY: check clean tidy test
