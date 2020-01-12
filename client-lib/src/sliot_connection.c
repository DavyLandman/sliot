#include "sliot_connection.h"
#include "monocypher.h"
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
#define PACKED __attribute__((__packed__))

enum MessageKind {
    INVALID = 0,
    DH_EXCHANGE = 0x01,
    MESSAGE = 0x02
};

struct PACKED signed_key_message {
    uint8_t kind;
    uint8_t signature[64];
    uint8_t public_key[32];
};

struct PACKED message_header {
    uint8_t kind;
    uint8_t msg_size[2];
    uint8_t counter[2];
    uint8_t nonce[24];
    uint8_t mac[16];
};

static uint8_t dh_private[32] CRYPTO_ALIGNMENT;
static const struct siot_config *current_config;

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

size_t sliot_handshake_init(const sliot_config *cfg, void *message_buffer, sliot_handshake *handshake, uint8_t random_bytes[32]) {
    if (cfg == NULL || handshake == NULL || random_bytes == NULL) {
        return 0;
    }

    struct signed_key_message *msg = message_buffer;
    msg->kind = DH_EXCHANGE;

    crypto_feed_watchdog();
    memcpy_portable(handshake->private_key, random_bytes, sizeof(handshake->private_key));
    crypto_wipe(random_bytes, 32);
    crypto_key_exchange_public_key(msg->public_key, handshake->private_key);

    crypto_feed_watchdog();
    crypto_sign(msg->signature, cfg->long_term_secret, cfg->long_term_public, msg->public_key, sizeof(msg->public_key));
    crypto_feed_watchdog();

    return sizeof(struct signed_key_message);
}

bool sliot_handshake_finish(const sliot_config *cfg, sliot_handshake *handshake, sliot_session *session, const void* received_message, size_t message_size) {
    if (received_message == NULL || session == NULL || handshake == NULL) {
        return false;
    }
    const struct signed_key_message *msg = received_message;
    if (message_size != sizeof(struct signed_key_message) || msg->kind != DH_EXCHANGE) {
        return false;
    }

    if (crypto_check(msg->signature, cfg->server_long_term_public, msg->public_key, sizeof(msg->public_key)) == 0) {
        // valid signed DH exchange

        crypto_feed_watchdog();
        crypto_key_exchange(session->shared_key, handshake->private_key, msg->public_key);
        crypto_feed_watchdog();

        crypto_wipe(handshake->private_key, sizeof(handshake->private_key));

        crypto_blake2b_ctx ctx;
        crypto_blake2b_general_init(&ctx, sizeof(session->shared_key), NULL, 0);
        crypto_blake2b_update(&ctx, session->shared_key, sizeof(session->shared_key));
        crypto_blake2b_update(&ctx, cfg->server_long_term_public, sizeof(cfg->server_long_term_public));
        crypto_blake2b_update(&ctx, cfg->long_term_public, sizeof(cfg->long_term_public));
        crypto_feed_watchdog();

        crypto_blake2b_final(&ctx, session->shared_key);
        crypto_feed_watchdog();
        session->valid_session = true;
        session->receive_counter = 0;
        session->send_counter = 0;
        return  true;
    }
    session->valid_session = false;
    return false;
}

static void write_uint16(uint8_t target[2], uint16_t value) {
    target[0] = (uint8_t)(value & 0xFF);
    target[1] = (uint8_t)((value >> 8) & 0xFF);
}

static uint16_t read_uint16(const uint8_t source[2]) {
    return ((uint16_t)source[0]) | ((uint16_t)source[1]) << 8;
}


size_t sliot_encrypt(sliot_session *session, const void *plaintext, uint16_t length, void* ciphertext, const uint8_t random_bytes[24]) {
    if (session == NULL || plaintext == NULL | ciphertext == NULL || random_bytes == NULL) {
        return 0;
    }
    struct message_header *header = ciphertext;
    header->kind = MESSAGE;
    write_uint16(header->msg_size, length);
    write_uint16(header->counter, ++(session->send_counter));
    memcpy_portable(header->nonce, random_bytes, sizeof(header->nonce));

    crypto_lock_aead(header->mac, ((uint8_t*)ciphertext) + sizeof(struct message_header), session->shared_key, header->nonce, (const void *) &header->counter, sizeof(header->counter), plaintext, length);

    return length + sizeof(struct message_header);
}

uint16_t sliot_decrypt(sliot_session *session, const void *ciphertext, size_t length, void *plaintext) {
    if (session == NULL || plaintext == NULL | ciphertext == NULL) {
        return 0;
    }
    const struct message_header *header = ciphertext;
    if (header->kind != MESSAGE) {
        return 0;
    }
    uint16_t size = read_uint16(header->msg_size);
    if (((size_t)size) + sizeof(struct message_header) > length) {
        // size field is to big compared to received bytes
        return 0;
    }
    uint16_t counter = read_uint16(header->counter);
    if (counter <= session->receive_counter) {
        return 0;
    }
    if (crypto_unlock_aead(plaintext, session->shared_key, header->nonce, header->mac, header->counter, sizeof(header->counter), ((const uint8_t*)ciphertext) + sizeof(struct message_header), size) == 0) {
        session->receive_counter = counter;
        return size;
    }
    return 0;
}