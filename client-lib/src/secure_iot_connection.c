#include "secure_iot_connection.h"
#include "chacha20/chacha20.h"
#include "blake2s-ref/blake2s-ref.h"
#include "curve25519-donna/curve25519-donna.h"

#include "osapi.h"
#include "user_interface.h"
#include <espnow.h>

#define ESP_OK 0

static void (*handshake_done)(uint8_t shared_key[32]) = NULL;
static void (*sent_success)(void) = NULL;


static void receive_handler(u8 *mac_addr, u8 *data, u8 len) {

}

static void send_handler(u8 *mac_addr, u8 status) {
}


void siot_handshake_execute(void (*done)(uint8_t shared_key[32])) {
    handshake_done = done;

}

void siot_send(uint8_t shared_key[32], uint32_t counter, void* data, size_t length, void (*sent)(void));


void siot_init_espnow() {
    #ifdef ARDUINO
        #warning "Figure out what to do on the arudino side"
    #else
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
    #endif
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
    if (esp_now_add_peer(SERVER_SENDER_ADDRESS, ESP_NOW_ROLE_CONTROLLER, 1, NULL, 0) != ESP_OK) {
        return;
    }
    if (esp_now_add_peer(SERVER_RECEIVER_ADDRESS, ESP_NOW_ROLE_SLAVE, 1, NULL, 0) != ESP_OK) {
        return;
    }
}