#ifndef SECURE_IOT_CONNECTION_H
#define SECURE_IOT_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

struct siot_config{
    uint8_t long_term_secret[32];
    uint8_t long_term_public[32];
    uint8_t server_long_term_public[32];
    uint8_t server_mac[6];
};



/*
    Initialize ESP-NOW context on esp8266, you must call this before either starting the handshake or sending a encrypted message
*/
void siot_init_espnow(const struct siot_config *cfg);

/*
    Start a handshake with the server to get a new shared key that can be used for sending messages

    You will get a callback on the done function, either with a new shared key, or with a NULL value, to indicate something went wrong.

    You are responsible for storing the shared_key safely.
*/
void siot_handshake_execute(const struct siot_config *cfg, void (*done)(uint8_t shared_key[32]));

/*
    Send a message to the server via esp-now, encrypted with the key derived from the handshake.

    The counter should be monotonic increasing. Be sure to preform a handshake once in a while, just to flush the key and (start the counter from fresh).

    Data cannot be more than 157 bytes (if length parameter is higher than 157, the function will not send anything).

    Either the send or the fail callback will be called.
*/
void siot_send(const struct siot_config *cfg, uint8_t shared_key[32], uint16_t counter, void* data, size_t length, void (*send)(void), void (*fail)(void));

#endif