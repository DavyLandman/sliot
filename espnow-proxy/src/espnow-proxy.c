#include "osapi.h"
#include "user_interface.h"
#include "espnow.h"

#define ESP_OK 0
uint32 ICACHE_FLASH_ATTR user_rf_cal_sector_set(void)
{
    switch (system_get_flash_size_map()) {
        case FLASH_SIZE_4M_MAP_256_256:
            return 128 - 5;
        case FLASH_SIZE_8M_MAP_512_512:
            return 256 - 5;

        case FLASH_SIZE_16M_MAP_512_512:
        case FLASH_SIZE_16M_MAP_1024_1024:
            return 512 - 5;

        case FLASH_SIZE_32M_MAP_512_512:
        case FLASH_SIZE_32M_MAP_1024_1024:
            return 1024 - 5;

        case FLASH_SIZE_64M_MAP_1024_1024:
            return 2048 - 5;

        case FLASH_SIZE_128M_MAP_1024_1024:
            return 4096 - 5;
        default:
            return 0;
    }

}

static void receive_handler(u8 *mac_addr, u8 *data, u8 len) {
}

static void send_handler(u8 *mac_addr, u8 status) {
}

void ICACHE_FLASH_ATTR user_init(void) {
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
}