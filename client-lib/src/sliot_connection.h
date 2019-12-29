
#ifndef SLIOT_CONNECTION_H 
#define SLIOT_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

struct sliot_config{
    uint8_t long_term_secret[32];
    uint8_t long_term_public[32];
    uint8_t server_long_term_public[32];
    uint8_t server_mac[6];
};

struct sliot_session {
    bool valid_session;
    uint8_t shared_key[32];
    uint16_t sendCounter;
    uint16_t receiveCounter;
};

/*
    Start a handshake with the server to get a new shared key that can be used for sending messages

    You are responsible for sending this message to the server

*/
size_t sliot_handshake_init(const struct sliot_config *cfg, void *message_buffer);


/*
    Handle handshake repsonse, either sets up a session in the session structure, or returns false if it failed for some kind of reason

*/
bool sliot_handshake_finish(const struct sliot_config *cfg, struct sliot_session *session, const void* received_message, size_t message_size);


size_t sliot_send(struct sliot_session *session, void *plaintext, size_t length);

size_t sliot_received(struct sliot_session *session, void *ciphertext, size_t length, void *plaintext);

#endif