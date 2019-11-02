#ifndef SECURE_IOT_CONNECTION_H
#define SECURE_IOT_CONNECTION_H

#include <stddef.h>
#include <stdint.h>

void siot_init_espnow();

void siot_handshake_execute(void (*done)(uint8_t shared_key[32]));

void siot_send(uint8_t shared_key[32], uint32_t counter, void* data, size_t length, void (*sent)(void));

#endif