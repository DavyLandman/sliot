// 2019-11-02 Davy Landman : made streaming version of the chacha20 code
#include "chacha20.h"
#include "chacha20_block.h"
#include <string.h>
#ifdef ARDUINO
#include <c_types.h>
#else
#define ICACHE_RAM_ATTR
#endif

#define CHACHA20_STREAM_SIZE 64

ICACHE_RAM_ATTR void chacha20(void *in, void *out, size_t length, const uint8_t key[32], const uint8_t nonce[12], uint32_t initial_counter){
    uint8_t one_time_pad[CHACHA20_STREAM_SIZE];

    uint8_t *target = out;

    uint8_t *source = in;
    uint8_t *end =  source + length;

    uint8_t *otp_stream = one_time_pad;
    uint8_t *otp_stream_end = otp_stream + CHACHA20_STREAM_SIZE;

    otp_stream = otp_stream_end; // deplete the stream
    uint32_t current_counter = initial_counter;
    while (source < end) {
        if (otp_stream == otp_stream_end) {
            // generate new bytes on the pad
            chacha20_block(one_time_pad, key, nonce, current_counter++);
            otp_stream = one_time_pad;
        }
        uint8_t b = *source++;
        *target++ = b ^ *otp_stream++;
    }
}