
#ifndef SLIOT_CONNECTION_H 
#define SLIOT_CONNECTION_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#define SLIOT_KEY_SIZE (32)

typedef struct sliot_config{
    uint8_t long_term_secret[64];
    uint8_t server_long_term_public[32];
} sliot_config;

typedef struct sliot_handshake {
    uint8_t private_key[SLIOT_KEY_SIZE];
} sliot_handshake;

typedef struct sliot_session {
    bool valid_session;
    uint8_t shared_key[32];
    uint16_t send_counter;
    uint16_t receive_counter;
} sliot_session;


#define SLIOT_HANDSHAKE_SIZE (1 + 64 + SLIOT_KEY_SIZE)
/*
    Start a handshake with the server to get a new shared key that can be used for sending messages, 

    You are responsible for sending this message to the server

    Reply with the bytes message_buffer.
*/
size_t sliot_handshake_init(const sliot_config *cfg, uint8_t message_buffer[SLIOT_HANDSHAKE_SIZE], sliot_handshake *handshake, uint8_t random_bytes[SLIOT_KEY_SIZE]);


/*
    Handle handshake repsonse, either sets up a session in the session structure, or returns false if it failed for some kind of reason

*/
bool sliot_handshake_finish(const sliot_config *cfg, sliot_handshake *handshake, sliot_session *session, const uint8_t* received_message, size_t message_size);


#define SLIOT_NONCE_SIZE (12)
#define SLIOT_OVERHEAD (1 + 2 + 2 + SLIOT_NONCE_SIZE + 16)
/*
    encode a new message in this session, returns the written bytes to the ciphertext pointer, not that ciphertext should have room for length + SLIOT_OVERHEAD

    returns 0 if the session is incorrect
*/
size_t sliot_encrypt(sliot_session *session, const uint8_t *plaintext, uint16_t length, uint8_t* ciphertext, const uint8_t random_bytes[SLIOT_NONCE_SIZE]);

/*
    decrypt an incoming message into the plaintext buffer, plain text should hold at least (length - SLIOT_OVERHEAD) room

    returns the size of the data decrypted, 0 if failure for some reason
*/
uint16_t sliot_decrypt(sliot_session *session, const uint8_t *ciphertext, size_t length, uint8_t *plaintext);

#endif