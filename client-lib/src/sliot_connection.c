#include "sliot_connection.h"
#include "crypto/portable8439.h"
#include "crypto/compact25519.h"
#include <string.h>
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

#if defined(ESP8266)
static void memcpy_portable(void* target, const void *source, size_t size) {
    
    const uint8_t* s = source;
    uint8_t* t = target;
    const uint8_t* s_end = s + size;
    while (s != s_end) {
        *t++ = *s++;
    }
}
#else
#define memcpy_portable(f,t,s) memcpy(f,t,s)
#endif

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


/*
The following message is send during hand shakes
struct PACKED signed_key_message {
    uint8_t kind; == DH_EXCHANGE
    uint8_t public_key[SLIOT_KX_KEY_SIZE];
    uint8_t signature[ED25519_SIGNATURE_SIZE];
};
*/


size_t sliot_handshake_init(const sliot_config *cfg, uint8_t message_buffer[SLIOT_HANDSHAKE_SIZE], sliot_handshake *handshake, uint8_t random_bytes[SLIOT_KEY_SIZE]) {
    if (cfg == NULL || handshake == NULL || random_bytes == NULL) {
        return 0;
    }

    message_buffer[0] = DH_EXCHANGE;

    crypto_feed_watchdog();
    compact_x25519_keygen(handshake->private_key, &message_buffer[1], random_bytes);

    crypto_feed_watchdog();
    compact_ed25519_sign(&message_buffer[1 + ED25519_PUBLIC_KEY_SIZE], cfg->long_term_secret, &message_buffer[1], ED25519_PUBLIC_KEY_SIZE);
    crypto_feed_watchdog();

    return SLIOT_HANDSHAKE_SIZE;
}

static bool sliot_handshake_finish(const sliot_config *cfg, sliot_handshake *handshake, sliot_session *session, const uint8_t* received_message, size_t message_size) {
    if (received_message == NULL || session == NULL || handshake == NULL) {
        return false;
    }

    if (message_size != SLIOT_HANDSHAKE_SIZE || received_message[0] != DH_EXCHANGE) {
        return false;
    }

    crypto_feed_watchdog();
    if (compact_ed25519_verify(&received_message[1 + SLIOT_KX_KEY_SIZE], 
            cfg->server_long_term_public, 
            &received_message[1], SLIOT_KX_KEY_SIZE)) {
        // valid signed DH exchange

        crypto_feed_watchdog();
        uint8_t shared_key[X25519_SHARED_SIZE];
        compact_x25519_shared(shared_key, handshake->private_key, &(received_message[1]));
        crypto_feed_watchdog();
        
        compact_wipe(handshake->private_key, sizeof(handshake->private_key));

        compact_x25519_derive_encryption_key(session->shared_key, sizeof(session->shared_key),
            shared_key, cfg->server_long_term_public, cfg->long_term_secret + 32);
        crypto_feed_watchdog();
        session->valid_session = true;
        session->receive_counter = 0;
        session->send_counter = 0;
        return  true;
    }
    session->valid_session = false;
    return false;
}

#define write_uint16_at(target, a, b, value) \
    (target)[(a)] = ((uint8_t) ((value) & 0xFF)); \
    (target)[(b)] = ((uint8_t) (((value) >> 8) & 0xFF));

#define read_uint16_at(source, a, b) \
    (((uint16_t)(source[(a)])) | ((uint16_t)((source)[(b)])) << 8)

/*
Following header comes before a message
struct PACKED message_header {
    uint8_t kind; == MESSAGE
    uint8_t msg_size[2];
    uint8_t counter[2];
    uint8_t nonce[SLIOT_NONCE_SIZE];
};
*/

size_t sliot_encrypt(sliot_session *session, const uint8_t *plaintext, uint16_t length, uint8_t* ciphertext, const uint8_t random_bytes[SLIOT_NONCE_SIZE]) {
    if ((session == NULL) || (plaintext == NULL) | (ciphertext == NULL) || (random_bytes == NULL)) {
        return -1;
    }
    session->send_counter++;

    ciphertext[0] = MESSAGE;
    write_uint16_at(ciphertext, 1, 2, length);
    write_uint16_at(ciphertext, 3, 4, session->send_counter);
    memcpy(&(ciphertext[5]), random_bytes, SLIOT_NONCE_SIZE);

    size_t written = portable_chacha20_poly1305_encrypt(
        &(ciphertext[5 + SLIOT_NONCE_SIZE]), 
        session->shared_key,
        random_bytes, 
        &(ciphertext[3]), 2, 
        plaintext, length
    );
    if (written == -1) {
        session->send_counter--;
        return -1;
    }

    return length + SLIOT_OVERHEAD;
}

static size_t sliot_decrypt(sliot_session *session, const uint8_t *ciphertext, size_t length, uint8_t *plaintext) {
    size_t size = read_uint16_at(ciphertext, 1, 2);
    uint16_t counter = read_uint16_at(ciphertext, 3, 4);

    if ((size + SLIOT_OVERHEAD) > length) {
        // size field is to big compared to received bytes
        return -1;
    }
    if (counter <= session->receive_counter) {
        return -1;
    }
    size_t actual_size = portable_chacha20_poly1305_decrypt(
            plaintext, 
            session->shared_key, 
            &(ciphertext[5]),  // nonce
            &(ciphertext[3]), 2,  // ad is the counter
            &(ciphertext[5 + SLIOT_NONCE_SIZE]), size + RFC_8439_TAG_SIZE
    );
    if (actual_size != -1) {
        session->receive_counter = counter;
        return actual_size;
    }
    return -1;
}

size_t sliot_handle_incoming(const sliot_config *cfg, sliot_handshake *handshake, sliot_session *session, const uint8_t* received_message, size_t message_size, uint8_t *plaintext) {
    if (cfg == NULL || session == NULL || received_message == NULL || message_size <= 1) {
        return -1;
    }
    switch (received_message[0]) {
        case MESSAGE:
            if (plaintext == NULL) {
                return -1;
            }
            return sliot_decrypt(session, received_message, message_size, plaintext);
        case DH_EXCHANGE:
            if (handshake == NULL) {
                return -1;
            }
            if (sliot_handshake_finish(cfg, handshake, session, received_message, message_size)) {
                return 0;
            }
            return -1;
        default:
            return -1;
    }

}