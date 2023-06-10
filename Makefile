VARIANT := default

ifneq ($(VARIANT),)
    CONFIG_FILE := config/$(VARIANT).mk
    include config/$(VARIANT).mk
endif

ifeq ($(VARIANT),default)
    SUFFIX :=
else
    SUFFIX := -$(VARIANT)
endif

OUT := out$(SUFFIX)

define safe_flag
$(shell $(CC) $(if $(filter clang%,$(CC)),-Werror=unknown-warning-option) -E $1 - </dev/null >/dev/null 2>&1 && echo $1 || echo $2)
endef

CPPFLAGS := $(CPPFLAGS) -D_GNU_SOURCE -I include
SHARED_FLAGS := -pipe -O3 -flto -fPIC -fvisibility=hidden -fno-plt \
    -fstack-clash-protection $(call safe_flag,-fcf-protection) -fstack-protector-strong \
    -Wall -Wextra $(call safe_flag,-Wcast-align=strict,-Wcast-align) -Wcast-qual -Wwrite-strings \
    -Wundef

ifeq ($(CONFIG_WERROR),true)
    SHARED_FLAGS += -Werror
endif

ifeq ($(CONFIG_NATIVE),true)
    SHARED_FLAGS += -march=native
endif

ifeq ($(CONFIG_UBSAN),true)
    SHARED_FLAGS += -fsanitize=undefined -fno-sanitize-recover=undefined
endif

CFLAGS := $(CFLAGS) -std=c17 $(SHARED_FLAGS) -Wmissing-prototypes -Wstrict-prototypes
CXXFLAGS := $(CXXFLAGS) -std=c++17 -fsized-deallocation $(SHARED_FLAGS)
LDFLAGS := $(LDFLAGS) -Wl,-O1,--as-needed,-z,defs,-z,relro,-z,now,-z,nodlopen,-z,text

SOURCES := chacha.c h_malloc.c memory.c pages.c random.c util.c
OBJECTS := $(SOURCES:.c=.o)

ifeq ($(CONFIG_CXX_ALLOCATOR),true)
    # make sure LTO is compatible in case CC and CXX don't match (such as clang and g++)
    CXX := $(CC)
    LDLIBS += -lstdc++

    SOURCES += new.cc
    OBJECTS += new.o
endif

OBJECTS := $(addprefix $(OUT)/,$(OBJECTS))

ifeq (,$(filter $(CONFIG_SEAL_METADATA),true false))
    $(error CONFIG_SEAL_METADATA must be true or false)
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

ifeq (,$(filter $(CONFIG_SELF_INIT),true false))
    $(error CONFIG_SELF_INIT must be true or false)
endif

CPPFLAGS += \
    -DCONFIG_SEAL_METADATA=$(CONFIG_SEAL_METADATA) \
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
    -DCONFIG_STATS=$(CONFIG_STATS) \
    -DCONFIG_SELF_INIT=$(CONFIG_SELF_INIT)

$(OUT)/libhardened_malloc$(SUFFIX).so: $(OBJECTS) | $(OUT)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ $(LDLIBS) -o $@

$(OUT):
	mkdir -p $(OUT)

$(OUT)/chacha.o: chacha.c chacha.h util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
$(OUT)/h_malloc.o: h_malloc.c include/h_malloc.h mutex.h memory.h pages.h random.h util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
$(OUT)/memory.o: memory.c memory.h util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
$(OUT)/new.o: new.cc include/h_malloc.h util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.cc) $(OUTPUT_OPTION) $<
$(OUT)/pages.o: pages.c pages.h memory.h util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
$(OUT)/random.o: random.c random.h chacha.h util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.c) $(OUTPUT_OPTION) $<
$(OUT)/util.o: util.c util.h $(CONFIG_FILE) | $(OUT)
	$(COMPILE.c) $(OUTPUT_OPTION) $<

check: tidy

tidy:
	clang-tidy --extra-arg=-std=c17 $(filter %.c,$(SOURCES)) -- $(CPPFLAGS)
	clang-tidy --extra-arg=-std=c++17 $(filter %.cc,$(SOURCES)) -- $(CPPFLAGS)

clean:
	rm -f $(OUT)/libhardened_malloc.so $(OBJECTS)
	$(MAKE) -C test/ clean

test: $(OUT)/libhardened_malloc$(SUFFIX).so
	$(MAKE) -C test/
	python3 -m unittest discover --start-directory test/

.PHONY: check clean tidy test
