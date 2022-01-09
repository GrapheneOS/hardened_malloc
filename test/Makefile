CONFIG_SLAB_CANARY := true
CONFIG_EXTENDED_SIZE_CLASSES := true

ifneq ($(VARIANT),)
    $(error testing non-default variants not yet supported)
endif

ifeq (,$(filter $(CONFIG_SLAB_CANARY),true false))
    $(error CONFIG_SLAB_CANARY must be true or false)
endif

LDLIBS := -lpthread

CPPFLAGS += \
    -DSLAB_CANARY=$(CONFIG_SLAB_CANARY) \
    -DCONFIG_EXTENDED_SIZE_CLASSES=$(CONFIG_EXTENDED_SIZE_CLASSES)

EXECUTABLES := \
    offset \
    mallinfo \
    mallinfo2 \
    malloc_info \
    large_array_growth

all: $(EXECUTABLES)
	make -C simple-memory-corruption

clean:
	rm -f $(EXECUTABLES)
	make -C simple-memory-corruption clean
