#include "sliot_connection.h"
#include "crypto/portable8439.h"
#include "crypto/compact25519.h"
#ifdef DEBUG
#include <stdio.h>
#endif

#if defined(ESP8266)
extern void system_soft_wdt_feed(void);
#define crypto_feed_watchdog() system_soft_wdt_feed()
#else
#define crypto_feed_watchdog() do { ; } while (0)
#endif

#define CRYPTO_ALIGNMENT __attribute__((aligned(4)))

enum MessageKind {
    INVALID = 0,
    DH_EXCHANGE = 0x01,
    MESSAGE = 0x02
};

static void memcpy_portable(void* target, const void *source, size_t size) {
    const uint8_t* s = source;
    uint8_t* t = target;
    const uint8_t* s_end = s + size;
    while (s != s_end) {
        *t++ = *s++;
    }
}

#ifdef DEBUG
void print_hex_memory(const void *mem, size_t len) {
  const unsigned char *p = mem;
  for (size_t i=0;i<len;i++) {
    if ((i%16==0) && i != 0)
      printf("\n");
    printf("0x%02x ", p[i]);
  }
  printf("\n");
}
#endif


#define __SLIOT_SIGNATURE_SIZE (64)
/*
The following message is send during hand shakes
struct PACKED signed_key_message {
    uint8_t kind; == DH_EXCHANGE
    uint8_t public_key[SLIOT_KEY_SIZE];
    uint8_t signature[__SLIOT_SIGNATURE_SIZE];
};
*/


size_t sliot_handshake_init(const sliot_config *cfg, uint8_t message_buffer[SLIOT_HANDSHAKE_SIZE], sliot_handshake *handshake, uint8_t random_bytes[SLIOT_KEY_SIZE]) {
    if (cfg == NULL || handshake == NULL || random_bytes == NULL) {
        return 0;
    }

    *message_buffer++ = DH_EXCHANGE;

    crypto_feed_watchdog();
    compact_x25519_keygen(handshake->private_key, message_buffer, random_bytes);

    crypto_feed_watchdog();
    compact_ed25519_sign(message_buffer + SLIOT_KEY_SIZE, cfg->long_term_secret, message_buffer, SLIOT_KEY_SIZE);
    crypto_feed_watchdog();

    return SLIOT_HANDSHAKE_SIZE;
}

bool sliot_handshake_finish(const sliot_config *cfg, sliot_handshake *handshake, sliot_session *session, const uint8_t* received_message, size_t message_size) {
    if (received_message == NULL || session == NULL || handshake == NULL) {
        return false;
    }

    if (message_size != SLIOT_HANDSHAKE_SIZE || *received_message++ != DH_EXCHANGE) {
        return false;
    }

    crypto_feed_watchdog();
    if (compact_ed25519_verify(received_message + SLIOT_KEY_SIZE, 
            cfg->server_long_term_public, 
            received_message, SLIOT_KEY_SIZE)) {
        // valid signed DH exchange

        crypto_feed_watchdog();
        uint8_t shared_key[X25519_SHARED_SIZE];
        compact_x25519_shared(shared_key, handshake->private_key, received_message);
        crypto_feed_watchdog();
        
        compact_wipe(handshake->private_key, sizeof(handshake->private_key));

        compact_x25519_derive_encryption_key(session->shared_key, sizeof(session->shared_key),
            shared_key, cfg->server_long_term_public, cfg->long_term_public);
        crypto_feed_watchdog();
        session->valid_session = true;
        session->receive_counter = 0;
        session->send_counter = 0;
        return  true;
    }
    session->valid_session = false;
    return false;
}

#define write_uint16(target, value) \
    (target)[0] = ((uint8_t) ((value) & 0xFF)); \
    (target)[1] = ((uint8_t) (((value) >> 8) & 0xFF));


#define read_uint16(source) \
    (((uint16_t)(source[0])) | ((uint16_t)((source)[1])) << 8)


#define __SLIOT_UINT16_SIZE (2)
/*
Following header comes before a message
struct PACKED message_header {
    uint8_t kind; == MESSAGE
    uint8_t msg_size[__SLIOT_UINT16_SIZE];
    uint8_t counter[__SLIOT_UINT16_SIZE];
    uint8_t nonce[SLIOT_NONCE_SIZE];
};
*/

size_t sliot_encrypt(sliot_session *session, const uint8_t *plaintext, uint16_t length, uint8_t* ciphertext, const uint8_t random_bytes[SLIOT_NONCE_SIZE]) {
    if ((session == NULL) || (plaintext == NULL) | (ciphertext == NULL) || (random_bytes == NULL)) {
        return 0;
    }
    *ciphertext++ = MESSAGE;
    write_uint16(ciphertext, length);
    ciphertext += __SLIOT_UINT16_SIZE;
    uint8_t *ad = ciphertext;
    write_uint16(ciphertext, ++(session->send_counter));
    ciphertext += __SLIOT_UINT16_SIZE;
    memcpy_portable(ciphertext, random_bytes, SLIOT_NONCE_SIZE);
    ciphertext += SLIOT_NONCE_SIZE;

    portable_chacha20_poly1305_encrypt(ciphertext, session->shared_key,
        random_bytes, ad, __SLIOT_UINT16_SIZE, plaintext, length);

    return length + SLIOT_OVERHEAD;
}

uint16_t sliot_decrypt(sliot_session *session, const uint8_t *ciphertext, size_t length, uint8_t *plaintext) {
    if ((session == NULL) || (plaintext == NULL) | (ciphertext == NULL)) {
        return 0;
    }
    if (*ciphertext++ != MESSAGE) {
        return 0;
    }
    uint16_t size = read_uint16(ciphertext);
    if (((size_t)size) + SLIOT_OVERHEAD > length) {
        // size field is to big compared to received bytes
        return 0;
    }
    ciphertext += __SLIOT_UINT16_SIZE;
    const uint8_t *ad = ciphertext;
    uint16_t counter = read_uint16(ciphertext);
    if (counter <= session->receive_counter) {
        return 0;
    }
    ciphertext += __SLIOT_UINT16_SIZE;
    const uint8_t *nonce = ciphertext;
    ciphertext += SLIOT_NONCE_SIZE;
    size_t actual_size = portable_chacha20_poly1305_decrypt(
            plaintext, 
            session->shared_key, nonce, 
            ad, __SLIOT_UINT16_SIZE, 
            ciphertext, ((size_t)size) + RFC_8439_TAG_SIZE
    );
    if (actual_size >= 0) {
        session->receive_counter = counter;
        return (uint16_t)actual_size;
    }
    return 0;
}