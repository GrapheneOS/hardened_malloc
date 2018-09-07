CPPFLAGS := -D_GNU_SOURCE
CFLAGS := -std=c11 -Wall -Wextra -Wmissing-prototypes -O2 -flto -fPIC -fvisibility=hidden -fno-plt
LDFLAGS := -Wl,-z,defs,-z,relro,-z,now,-z,nodlopen,-z,text
OBJECTS := chacha.o malloc.o memory.o pages.o random.o util.o

hardened_malloc.so: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -shared $^ $(LDLIBS) -o $@

chacha.o: chacha.c chacha.h
malloc.o: malloc.c malloc.h config.h memory.h pages.h random.h util.h
memory.o: memory.c memory.h util.h
pages.o: pages.c pages.h memory.h util.h
random.o: random.c random.h chacha.h util.h
util.o: util.c util.h

clean:
	rm -f hardened_malloc.so $(OBJECTS)
