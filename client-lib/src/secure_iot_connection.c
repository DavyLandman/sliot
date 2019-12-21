#include "secure_iot_connection.h"
#include "osapi.h"
#include "user_interface.h"
#include <espnow.h>
#include <monocypher.h>


#define ESP_OK 0

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

static uint8_t dh_private[32] CRYPTO_ALIGNMENT;
static const struct siot_config *current_config;

static void (*handshake_done)(uint8_t shared_key[32]) = NULL;
static void (*send_success)(void) = NULL;
static void (*send_failure)(void) = NULL;


static void handle_dh_reply(const struct signed_key_message *msg) {
    system_soft_wdt_feed();
    if (crypto_check(msg->signature, current_config->server_long_term_public, msg->public_key, sizeof(msg->public_key)) == 0) {
        system_soft_wdt_feed();

        uint8_t shared_secret[32];
        crypto_key_exchange(shared_secret, dh_private, msg->public_key);
        system_soft_wdt_feed();
        crypto_wipe(dh_private, sizeof(dh_private));

        crypto_blake2b_ctx ctx;
        crypto_blake2b_general_init(&ctx, sizeof(shared_secret), NULL, 0);
        crypto_blake2b_update(&ctx, shared_secret, sizeof(shared_secret));
        crypto_blake2b_update(&ctx, current_config->server_long_term_public, sizeof(current_config->server_long_term_public));
        crypto_blake2b_update(&ctx, current_config->long_term_public, sizeof(current_config->long_term_public));
        system_soft_wdt_feed();
        crypto_blake2b_final(&ctx, shared_secret);

        handshake_done(shared_secret);
        handshake_done = NULL;
        system_soft_wdt_feed();
        crypto_wipe(shared_secret, sizeof(shared_secret));
    }
}

static void receive_handler(u8 *mac_addr, u8 *data, u8 len) {
    if (handshake_done != NULL) {
        // we are in a DH exchange, we dont check the sending mac, as it is to easy to fake
        if (len != sizeof(struct signed_key_message) || current_config == NULL) {
            // incorrect message received, exiting
            return;
        }
        handle_dh_reply((const void*)data);
    }
}

static void send_handler(u8 *mac_addr, u8 status) {
    if (send_success != NULL && send_failure != NULL) {
        if (status == 0) {
            send_success();
        }
        else {
            send_failure();
        }
        send_success = NULL;
        send_failure = NULL;
    }
}


void siot_handshake_execute(const struct siot_config *cfg, void (*done)(uint8_t shared_key[32])) {
    while (os_get_random(dh_private, sizeof(dh_private)) != 0);

    system_soft_wdt_feed();
    struct signed_key_message msg;
    msg.kind = DH_EXCHANGE;
    crypto_key_exchange_public_key(msg.public_key, dh_private);
    system_soft_wdt_feed();
    crypto_sign(msg.signature, cfg->long_term_secret, cfg->long_term_public, msg.public_key, sizeof(msg.public_key));
    system_soft_wdt_feed();

    current_config = cfg;
    handshake_done = done;
    esp_now_send((u8*)cfg->server_mac, ((void*)&msg), sizeof(msg));
}

struct PACKED messageHeader {
    uint8_t kind;
    uint8_t counter[2];
    uint8_t msg_size;
    uint8_t nonce[24];
    uint8_t mac[16];
};

void siot_send(const struct siot_config *cfg, uint8_t shared_key[32], uint16_t counter, void* data, size_t length, void (*send)(void), void (*fail)(void)) {
    uint8_t message[200] CRYPTO_ALIGNMENT; // max message size
    if (length > (sizeof(message) - sizeof(struct messageHeader))) {
        return;
    }
    struct messageHeader *header = (void *)message;
    header->kind = MESSAGE;
    header->counter[0] = counter & 0xFF;
    header->counter[1] = (counter >> 8) & 0xFF;
    header->msg_size = length;

    while (os_get_random(header->nonce, sizeof(header->nonce)) != 0);
    system_soft_wdt_feed();
    crypto_lock_aead(header->mac, message + sizeof(struct messageHeader), shared_key, header->nonce, (const void *) &header->counter, sizeof(header->counter), data, length);
    system_soft_wdt_feed();

    send_success = send;
    send_failure = fail;
    esp_now_send((u8*)cfg->server_mac, message, length + sizeof(struct messageHeader));
}


// TODO: depending on either mode (key exchange or just pure sending) we need to be in a different role, maybe the init should be called from the siot_send and siot_keyexchange code?
void siot_init_espnow(const struct siot_config *cfg) {
    // wakeup WIFI in in receiving mode
    wifi_set_opmode_current(STATIONAP_MODE);
    struct softap_config config;
    config.ssid[0] = '\0';
    config.ssid_len = 0;
    config.password[0] = '\0';
    config.channel = 1;
    config.authmode = AUTH_OPEN;
    wifi_softap_set_config_current(&config);
    wifi_softap_dhcps_stop();

    if (esp_now_init() != ESP_OK) {
        return;
    }
    if (esp_now_set_self_role(ESP_NOW_ROLE_COMBO) != ESP_OK) {
        return;
    }
    if (esp_now_register_recv_cb(&receive_handler) != ESP_OK) {
        return;
    }
    if (esp_now_register_send_cb(&send_handler) != ESP_OK) {
        return;
    }
    if (esp_now_add_peer((u8*)cfg->server_mac, ESP_NOW_ROLE_COMBO, 1, NULL, 0) != ESP_OK) {
        return;
    }
}