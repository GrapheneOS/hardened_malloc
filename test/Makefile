CONFIG_SLAB_CANARY := true

ifeq (,$(filter $(CONFIG_SLAB_CANARY),true false))
    $(error CONFIG_SLAB_CANARY must be true or false)
endif

CPPFLAGS += \
    -DSLAB_CANARY=$(CONFIG_SLAB_CANARY)

EXECUTABLES := \
    offset

all: $(EXECUTABLES)

clean:
	rm -f $(EXECUTABLES)
