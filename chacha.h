#ifndef CHACHA_H
#define CHACHA_H

#include "util.h"

#define CHACHA_KEY_SIZE 32
#define CHACHA_IV_SIZE 8

typedef struct {
    u32 input[16];
} chacha_ctx;

void chacha_keysetup(chacha_ctx *x, const u8 *k);
void chacha_ivsetup(chacha_ctx *x, const u8 *iv);
void chacha_keystream_bytes(chacha_ctx *x, u8 *c, u32 bytes);

#endif
