#ifndef CHACHA20BLOCK_HEADER
#define CHACHA20BLOCK_HEADER
// based on: chacha.h by Markku-Juhani O. Saarinen <mjos@iki.fi>

#include <stdint.h>
// generate a block of ChaCha20 keystream as per RFC7539
void chacha20_block(void *block,                // 64 bytes written here
                    const uint8_t key[32],      // 256-bit secret key
                    const uint8_t nonce[12],    // 96-bit nonce
                    uint32_t cnt);              // 32-bit block counter 1, 2..
#endif