// based on chacha20.c and chacha20-ref.c by  Markku-Juhani O. Saarinen <mjos@iki.fi>

#include "chacha20_block.h"
#include <string.h>
#ifdef ARDUINO
#include <c_types.h>
#else
#define ICACHE_RAM_ATTR
#endif

// Rotate 32-bit words left

#ifndef ROTL32
#define ROTL32(x, y)  (((x) << (y)) ^ ((x) >> (32 - (y))))
#endif

// ChaCha Quarter Round unrolled as a macro

#define CHACHA_QR(A, B, C, D) { \
    A += B; D ^= A; D = ROTL32(D, 16);  \
    C += D; B ^= C; B = ROTL32(B, 12);  \
    A += B; D ^= A; D = ROTL32(D, 8);   \
    C += D; B ^= C; B = ROTL32(B, 7);   \
}

// ChaCha permutation -- dr is the number of double rounds

#define chacha_perm(v, dr) { \
    for (uint8_t __i = 0; __i < dr; __i++) { \
        CHACHA_QR( v[ 0], v[ 4], v[ 8], v[12] ); \
        CHACHA_QR( v[ 1], v[ 5], v[ 9], v[13] ); \
        CHACHA_QR( v[ 2], v[ 6], v[10], v[14] ); \
        CHACHA_QR( v[ 3], v[ 7], v[11], v[15] ); \
        CHACHA_QR( v[ 0], v[ 5], v[10], v[15] ); \
        CHACHA_QR( v[ 1], v[ 6], v[11], v[12] ); \
        CHACHA_QR( v[ 2], v[ 7], v[ 8], v[13] ); \
        CHACHA_QR( v[ 3], v[ 4], v[ 9], v[14] ); \
    } \
}



// generate a block of ChaCha20 keystream as per RFC7539


static ICACHE_RAM_ATTR const uint32_t fixed[4] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

ICACHE_RAM_ATTR void chacha20_block(void *block,                // 64 bytes written here
                    const uint8_t key[32],      // 256-bit secret key
                    const uint8_t nonce[12],    // 96-bit nonce
                    uint32_t cnt)               // 32-bit block counter 1, 2..
{
    size_t i;

    uint32_t *pad = block;

    memcpy(pad, fixed, sizeof(uint32_t) * 4);
    memcpy(pad + 4, key, 32);
    pad[12] = cnt;
    memcpy(pad + 13, nonce, 12);

    chacha_perm(pad, 10);             // 10 double-rounds

    for (i = 0; i < 4; i++)
        pad[i] += fixed[i];
    for (i = 0; i < 8; i++)
        pad[i + 4] += ((const uint32_t *) key)[i];
    pad[12] += cnt;
    for (i = 0; i < 3; i++)
        pad[i + 13] += ((const uint32_t *) nonce)[i];
}