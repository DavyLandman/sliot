
#ifndef SLIOT_CONNECTION_H 
#define SLIOT_CONNECTION_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define SLIOT_KEY_SIZE (32)
#define SLIOT_KX_KEY_SIZE (32)

typedef struct sliot_config{
    uint8_t long_term_secret[64];
    uint8_t server_long_term_public[32];
} sliot_config;

typedef struct sliot_handshake {
    uint8_t private_key[SLIOT_KX_KEY_SIZE];
} sliot_handshake;

typedef struct sliot_session {
    bool valid_session;
    uint8_t shared_key[SLIOT_KEY_SIZE];
    uint16_t send_counter;
    uint16_t receive_counter;
} sliot_session;


#define SLIOT_HANDSHAKE_SIZE (1 + 64 + SLIOT_KX_KEY_SIZE)
/*
    Start a handshake with the server to get a new shared key that can be used for sending messages, 

    You are responsible for sending this message to the server

    Reply with the bytes message_buffer.
*/
size_t sliot_handshake_init(const sliot_config *cfg, uint8_t message_buffer[SLIOT_HANDSHAKE_SIZE], sliot_handshake *handshake, uint8_t random_bytes[SLIOT_KX_KEY_SIZE]);


#define SLIOT_OVERHEAD (1 + 2 + 2 + SLIOT_NONCE_SIZE + 16)

/*
    Handle an incoming message, if an handshake is active make sure handshake is not null, else make sure the plaintext buffer has room for at least message_size - SLIOT_OVERHEAD.

    Result of the function:
        - -1: failure
        - 0: successfull handshake or succesfull decryption of emtpy message
        - >0: this many bytes were written into the plaintext buffer, which now contains a valid server side message
*/
size_t sliot_handle_incoming(const sliot_config *cfg, sliot_handshake *handshake, sliot_session *session, const uint8_t* received_message, size_t message_size, uint8_t *plaintext);


#define SLIOT_NONCE_SIZE (12)
/*
    encode a new message in this session, returns the written bytes to the ciphertext pointer, not that ciphertext should have room for length + SLIOT_OVERHEAD

    returns 0 if the session is incorrect
*/
size_t sliot_encrypt(sliot_session *session, const uint8_t *plaintext, uint16_t length, uint8_t* ciphertext, const uint8_t random_bytes[SLIOT_NONCE_SIZE]);

#endif