#ifndef CHACHA20_H
#define CHACHA20_H
#include <stdint.h>
#include <stddef.h>

void chacha20(void *in, void* out, size_t length,      // bytes that will be encrypted
                    const uint8_t key[32],      // 256-bit secret key
                    const uint8_t nonce[12],    // 96-bit nonce
                    uint32_t initial_counter);  // 32-bit initial counter value (incrementer per 512bit block)
#endif