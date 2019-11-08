#include "secure_iot_connection.h"
#include "osapi.h"
#include "user_interface.h"
#include <espnow.h>
#include <monocypher.h>


#define ESP_OK 0

#define CRYPTO_ALIGNMENT __attribute__((aligned(4)))
#define PACKED __attribute__((__packed__))

static uint8_t dh_private[32] CRYPTO_ALIGNMENT;

static void (*handshake_done)(uint8_t shared_key[32]) = NULL;
static void (*sent_success)(void) = NULL;


static void receive_handler(u8 *mac_addr, u8 *data, u8 len) {

}

static void send_handler(u8 *mac_addr, u8 status) {
}


struct PACKED signed_key_message {
    uint8_t signature[64];
    uint8_t public_key[32];
};

void siot_handshake_execute(struct siot_config *cfg, void (*done)(uint8_t shared_key[32])) {
    os_get_random(dh_private, sizeof(dh_private));

    struct signed_key_message msg;
    crypto_key_exchange_public_key(msg.public_key, dh_private);
    crypto_sign(msg.signature, cfg->long_term_secret, cfg->long_term_public, msg.public_key, sizeof(msg.public_key));

    handshake_done = done;
    esp_now_send(cfg->server_receiving_mac, (const u8*)((const void*)&msg), sizeof(msg));
}

void siot_send(struct siot_config *cfg, uint8_t shared_key[32], uint32_t counter, void* data, size_t length, void (*sent)(void));


void siot_init_espnow(struct siot_config *cfg) {
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
    if (esp_now_add_peer(cfg->server_sending_mac, ESP_NOW_ROLE_CONTROLLER, 1, NULL, 0) != ESP_OK) {
        return;
    }
    if (esp_now_add_peer(cfg->server_receiving_mac, ESP_NOW_ROLE_SLAVE, 1, NULL, 0) != ESP_OK) {
        return;
    }
}