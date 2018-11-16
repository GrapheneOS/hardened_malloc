CONFIG_NATIVE := true
CONFIG_CXX_ALLOCATOR := true
CONFIG_UBSAN := false
CONFIG_SEAL_METADATA := false
CONFIG_WRITE_AFTER_FREE_CHECK := true
CONFIG_SLOT_RANDOMIZE := true
CONFIG_ZERO_ON_FREE := true
CONFIG_SLAB_CANARY := true

define safe_flag
$(shell $(CC) -E $1 - </dev/null >/dev/null 2>&1 && echo $1)
endef

CPPFLAGS := -D_GNU_SOURCE
SHARED_FLAGS := -O3 -flto -fPIC -fvisibility=hidden -fno-plt -pipe -Wall -Wextra $(call safe_flag,-Wcast-align=strict) -Wcast-qual -Wwrite-strings

ifeq ($(CONFIG_NATIVE),true)
    SHARED_FLAGS += -march=native
endif

CFLAGS := -std=c11 $(SHARED_FLAGS) -Wmissing-prototypes
CXXFLAGS := -std=c++14 $(SHARED_FLAGS)
LDFLAGS := -Wl,--as-needed,-z,defs,-z,relro,-z,now,-z,nodlopen,-z,text
TIDY_CHECKS := -checks=bugprone-*,-bugprone-macro-parentheses,cert-*,clang-analyzer-*,readability-*,-readability-inconsistent-declaration-parameter-name,-readability-named-parameter

SOURCES := chacha.c malloc.c memory.c pages.c random.c util.c
OBJECTS := $(SOURCES:.c=.o)

ifeq ($(CONFIG_CXX_ALLOCATOR),true)
    LDLIBS += -lstdc++
    SOURCES += new.cc
    OBJECTS += new.o
endif

ifeq ($(CONFIG_UBSAN),true)
    CFLAGS += -fsanitize=undefined
    CXXFLAGS += -fsanitize=undefined
endif

ifeq ($(CONFIG_SEAL_METADATA),true)
    CPPFLAGS += -DCONFIG_SEAL_METADATA
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

CPPFLAGS += \
    -DZERO_ON_FREE=$(CONFIG_ZERO_ON_FREE) \
    -DWRITE_AFTER_FREE_CHECK=$(CONFIG_WRITE_AFTER_FREE_CHECK) \
    -DSLOT_RANDOMIZE=$(CONFIG_SLOT_RANDOMIZE) \
    -DSLAB_CANARY=$(CONFIG_SLAB_CANARY)

hardened_malloc.so: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ $(LDLIBS) -o $@

chacha.o: chacha.c chacha.h util.h
malloc.o: malloc.c malloc.h config.h mutex.h memory.h pages.h random.h util.h
memory.o: memory.c memory.h util.h
new.o: new.cc malloc.h util.h
pages.o: pages.c pages.h memory.h util.h
random.o: random.c random.h chacha.h util.h
util.o: util.c util.h

tidy:
	clang-tidy $(TIDY_CHECKS) $(SOURCES) -- $(CPPFLAGS)

clean:
	rm -f hardened_malloc.so $(OBJECTS)

.PHONY: clean tidy
