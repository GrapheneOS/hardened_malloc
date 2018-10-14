CONFIG_CXX_ALLOCATOR := true

CPPFLAGS := -D_GNU_SOURCE
SHARED_FLAGS := -O2 -flto -fPIC -fvisibility=hidden -fno-plt -pipe -Wall -Wextra
CFLAGS := -std=c11 $(SHARED_FLAGS) -Wmissing-prototypes
CXXFLAGS := -std=c++14 $(SHARED_FLAGS)
LDFLAGS := -Wl,-z,defs,-z,relro,-z,now,-z,nodlopen,-z,text
SOURCES := chacha.c malloc.c memory.c pages.c random.c util.c
OBJECTS := $(SOURCES:.c=.o)

ifeq ($(CONFIG_CXX_ALLOCATOR),true)
    LDLIBS += -lstdc++
    SOURCES += new.cc
    OBJECTS += new.o
endif

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
	clang-tidy $(SOURCES) -- $(CPPFLAGS)

clean:
	rm -f hardened_malloc.so $(OBJECTS)

.PHONY: clean tidy
