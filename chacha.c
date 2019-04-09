// Based on chacha-merged.c version 20080118
// D. J. Bernstein
// Public domain.

#include "chacha.h"

// ChaCha8
static const unsigned rounds = 8;

#define U8C(v) (v##U)
#define U32C(v) (v##U)

#define U8V(v) ((u8)(v) & U8C(0xFF))
#define U32V(v) ((u32)(v) & U32C(0xFFFFFFFF))

#define ROTL32(v, n) \
    (U32V((v) << (n)) | ((v) >> (32 - (n))))

#define U8TO32_LITTLE(p) \
    (((u32)((p)[0])) | \
     ((u32)((p)[1]) <<  8) | \
     ((u32)((p)[2]) << 16) | \
     ((u32)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
    do { \
        (p)[0] = U8V((v)); \
        (p)[1] = U8V((v) >>  8); \
        (p)[2] = U8V((v) >> 16); \
        (p)[3] = U8V((v) >> 24); \
    } while (0)

#define ROTATE(v, c) (ROTL32(v, c))
#define XOR(v, w) ((v) ^ (w))
#define PLUS(v, w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v), 1))

#define QUARTERROUND(a, b, c, d) \
    a = PLUS(a, b); d = ROTATE(XOR(d, a), 16); \
    c = PLUS(c, d); b = ROTATE(XOR(b, c), 12); \
    a = PLUS(a, b); d = ROTATE(XOR(d, a), 8); \
    c = PLUS(c, d); b = ROTATE(XOR(b, c), 7);

static const char sigma[16] = "expand 32-byte k";

void chacha_keysetup(chacha_ctx *x, const u8 *k) {
    x->input[0] = U8TO32_LITTLE(sigma + 0);
    x->input[1] = U8TO32_LITTLE(sigma + 4);
    x->input[2] = U8TO32_LITTLE(sigma + 8);
    x->input[3] = U8TO32_LITTLE(sigma + 12);
    x->input[4] = U8TO32_LITTLE(k + 0);
    x->input[5] = U8TO32_LITTLE(k + 4);
    x->input[6] = U8TO32_LITTLE(k + 8);
    x->input[7] = U8TO32_LITTLE(k + 12);
    x->input[8] = U8TO32_LITTLE(k + 16);
    x->input[9] = U8TO32_LITTLE(k + 20);
    x->input[10] = U8TO32_LITTLE(k + 24);
    x->input[11] = U8TO32_LITTLE(k + 28);
}

void chacha_ivsetup(chacha_ctx *x, const u8 *iv) {
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = U8TO32_LITTLE(iv + 0);
    x->input[15] = U8TO32_LITTLE(iv + 4);
}

void chacha_keystream_bytes(chacha_ctx *x, u8 *c, u32 bytes) {
    if (!bytes) {
        return;
    }

    u8 *ctarget;
    u8 tmp[64];

    u32 j0 = x->input[0];
    u32 j1 = x->input[1];
    u32 j2 = x->input[2];
    u32 j3 = x->input[3];
    u32 j4 = x->input[4];
    u32 j5 = x->input[5];
    u32 j6 = x->input[6];
    u32 j7 = x->input[7];
    u32 j8 = x->input[8];
    u32 j9 = x->input[9];
    u32 j10 = x->input[10];
    u32 j11 = x->input[11];
    u32 j12 = x->input[12];
    u32 j13 = x->input[13];
    u32 j14 = x->input[14];
    u32 j15 = x->input[15];

    for (;;) {
        if (bytes < 64) {
            ctarget = c;
            c = tmp;
        }
        u32 x0 = j0;
        u32 x1 = j1;
        u32 x2 = j2;
        u32 x3 = j3;
        u32 x4 = j4;
        u32 x5 = j5;
        u32 x6 = j6;
        u32 x7 = j7;
        u32 x8 = j8;
        u32 x9 = j9;
        u32 x10 = j10;
        u32 x11 = j11;
        u32 x12 = j12;
        u32 x13 = j13;
        u32 x14 = j14;
        u32 x15 = j15;
        for (unsigned i = rounds; i > 0; i -= 2) {
            QUARTERROUND(x0, x4, x8, x12)
            QUARTERROUND(x1, x5, x9, x13)
            QUARTERROUND(x2, x6, x10, x14)
            QUARTERROUND(x3, x7, x11, x15)
            QUARTERROUND(x0, x5, x10, x15)
            QUARTERROUND(x1, x6, x11, x12)
            QUARTERROUND(x2, x7, x8, x13)
            QUARTERROUND(x3, x4, x9, x14)
        }
        x0 = PLUS(x0, j0);
        x1 = PLUS(x1, j1);
        x2 = PLUS(x2, j2);
        x3 = PLUS(x3, j3);
        x4 = PLUS(x4, j4);
        x5 = PLUS(x5, j5);
        x6 = PLUS(x6, j6);
        x7 = PLUS(x7, j7);
        x8 = PLUS(x8, j8);
        x9 = PLUS(x9, j9);
        x10 = PLUS(x10, j10);
        x11 = PLUS(x11, j11);
        x12 = PLUS(x12, j12);
        x13 = PLUS(x13, j13);
        x14 = PLUS(x14, j14);
        x15 = PLUS(x15, j15);

        j12 = PLUSONE(j12);
        if (!j12) {
            j13 = PLUSONE(j13);
            // stopping at 2^70 bytes per nonce is user's responsibility
        }

        U32TO8_LITTLE(c + 0, x0);
        U32TO8_LITTLE(c + 4, x1);
        U32TO8_LITTLE(c + 8, x2);
        U32TO8_LITTLE(c + 12, x3);
        U32TO8_LITTLE(c + 16, x4);
        U32TO8_LITTLE(c + 20, x5);
        U32TO8_LITTLE(c + 24, x6);
        U32TO8_LITTLE(c + 28, x7);
        U32TO8_LITTLE(c + 32, x8);
        U32TO8_LITTLE(c + 36, x9);
        U32TO8_LITTLE(c + 40, x10);
        U32TO8_LITTLE(c + 44, x11);
        U32TO8_LITTLE(c + 48, x12);
        U32TO8_LITTLE(c + 52, x13);
        U32TO8_LITTLE(c + 56, x14);
        U32TO8_LITTLE(c + 60, x15);

        if (bytes <= 64) {
            if (bytes < 64) {
                for (unsigned i = 0; i < bytes; ++i) {
                    ctarget[i] = c[i];
                }
            }
            x->input[12] = j12;
            x->input[13] = j13;
            return;
        }
        bytes -= 64;
        c += 64;
    }
}
