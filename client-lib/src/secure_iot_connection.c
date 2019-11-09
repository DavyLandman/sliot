#include "secure_iot_connection.h"
#include "osapi.h"
#include "user_interface.h"
#include <espnow.h>
#include <monocypher.h>


#define ESP_OK 0

#define CRYPTO_ALIGNMENT __attribute__((aligned(4)))
#define PACKED __attribute__((__packed__))


struct PACKED signed_key_message {
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
    if (crypto_check(msg->signature, current_config->server_long_term_public, msg->public_key, sizeof(msg->public_key))) {
        system_soft_wdt_feed();
        uint8_t shared_key[32];
        crypto_key_exchange(shared_key, dh_private, msg->public_key);
        system_soft_wdt_feed();
        memset(dh_private, 0, sizeof(dh_private));
        handshake_done(shared_key);
        handshake_done = NULL;
        system_soft_wdt_feed();
        memset(shared_key, 0, sizeof(dh_private));
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
    crypto_key_exchange_public_key(msg.public_key, dh_private);
    system_soft_wdt_feed();
    crypto_sign(msg.signature, cfg->long_term_secret, cfg->long_term_public, msg.public_key, sizeof(msg.public_key));
    system_soft_wdt_feed();

    current_config = cfg;
    handshake_done = done;
    esp_now_send((u8*)cfg->server_receiving_mac, ((void*)&msg), sizeof(msg));
}

struct PACKED messageHeader {
    uint8_t nonce[24];
    uint8_t mac[16];
    uint16_t counter;
    uint8_t msg_size;
};

void siot_send(const struct siot_config *cfg, uint8_t shared_key[32], uint16_t counter, void* data, size_t length, void (*send)(void), void (*fail)(void)) {
    uint8_t message[200] CRYPTO_ALIGNMENT; // max message size
    if (length > (sizeof(message) - sizeof(struct messageHeader))) {
        return;
    }
    struct messageHeader *header = (void *)message;
    header->counter = counter;
    header->msg_size = length;

    while (os_get_random(header->nonce, sizeof(header->nonce)) != 0);
    system_soft_wdt_feed();
    crypto_lock_aead(header->mac, message + sizeof(struct messageHeader), shared_key, header->nonce, (const void *) &header->counter, sizeof(header->counter), data, length);
    system_soft_wdt_feed();

    send_success = send;
    send_failure = fail;
    esp_now_send((u8*)cfg->server_receiving_mac, message, length + sizeof(struct messageHeader));
}


void siot_init_espnow(const struct siot_config *cfg) {
    // wakeup WIFI in in receiving mode
    wifi_set_opmode_current(SOFTAP_MODE);
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
    if (esp_now_add_peer((u8*)cfg->server_sending_mac, ESP_NOW_ROLE_CONTROLLER, 1, NULL, 0) != ESP_OK) {
        return;
    }
    if (esp_now_add_peer((u8*)cfg->server_receiving_mac, ESP_NOW_ROLE_SLAVE, 1, NULL, 0) != ESP_OK) {
        return;
    }
}