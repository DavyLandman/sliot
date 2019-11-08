#ifndef SECURE_IOT_CONNECTION_H
#define SECURE_IOT_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

struct siot_config{
    uint8_t long_term_secret[32];
    uint8_t long_term_public[32];
    uint8_t server_long_term_public[32];
    uint8_t server_sending_mac[6];
    uint8_t server_receiving_mac[6];
};

void siot_init_espnow(struct siot_config *cfg);

void siot_handshake_execute(struct siot_config *cfg, void (*done)(uint8_t shared_key[32]));

void siot_send(struct siot_config *cfg, uint8_t shared_key[32], uint32_t counter, void* data, size_t length, void (*sent)(void));

#endif