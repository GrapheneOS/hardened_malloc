#include <stdbool.h>
#include <stdlib.h>

#include "test_util.h"

OPTNONE int main(void) {
    char *p = malloc(0);
    for (int i = 0; i < 512; i++) {
	    char *q = malloc(64);
	    if (p == q) {
		    return 1;
	    }
	    free(q);
    }
    return 0;
}
