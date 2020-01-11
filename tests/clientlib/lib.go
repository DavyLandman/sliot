package clientlib 

// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// // workaround for c files in a different directory:
// #cgo CFLAGS: -I${SRCDIR}/../../client-lib/src
// #include "sliot_connection.c"
// #include "monocypher.c"
// // workaround so that we can import monocypher twice
// #cgo LDFLAGS: -Wl,--allow-multiple-definition

import "C"
import (
	"unsafe"
	"fmt"
	"crypto/rand"
)

type Config struct {
	actual C.sliot_config
}

type Handshake struct {
	config *Config
	actual C.sliot_handshake
}

type Session struct {
	config *Config
	actual C.sliot_session
}

func safeCopy32(target *[32]C.uint8_t, source []byte) error {
	if len(source) != 32 {
		return fmt.Errorf("Incorrect source length: %v", len(source))
	}
	for i := range source {
		target[i] = (C.uint8_t)(source[i])
	}
	return nil
}

func CreateConfig(longTermSecret, longTermPublic, serverLongTermPublic []byte) (*Config, error) {
	var result Config
	err := safeCopy32(&result.actual.long_term_secret, longTermSecret)
	if err != nil {
		return nil, err
	}
	err = safeCopy32(&result.actual.long_term_public, longTermPublic)
	if err != nil {
		return nil, err
	}
	err = safeCopy32(&result.actual.server_long_term_public, serverLongTermPublic)
	return &result, nil
}

func (cfg *Config) HandshakeInit() (*Handshake, []byte) {
	message := make([]byte, C.SLIOT_HANDSHAKE_SIZE)
	var randomBytes [32]byte
	rand.Read(randomBytes[:])
	var result Handshake
	result.config = cfg
	messageSize := C.sliot_handshake_init(&cfg.actual, unsafe.Pointer(&message[0]), &result.actual, (*C.uint8_t)(&randomBytes[0]))
	return &result, message[:messageSize]
}

func (h *Handshake) Finish(response []byte) (*Session) {
	var result Session
	result.config = h.config
	if C.sliot_handshake_finish(&h.config.actual, &h.actual,  &result.actual, unsafe.Pointer(&response[0]), C.size_t(len(response))) {
		return &result
	}
	return nil
}

func (s *Session) Encrypt(plaintext []byte) (ciphertext []byte) {
	result := make([]byte, len(plaintext) + C.SLIOT_OVERHEAD)
	var randomBytes [24]byte
	rand.Read(randomBytes[:])
	encrypted := C.sliot_encrypt(&s.actual, unsafe.Pointer(&plaintext[0]), C.uint16_t(len(plaintext)), unsafe.Pointer(&result[0]), (*C.uint8_t)(&randomBytes[0]))
	if encrypted > 0 {
		return result[:encrypted]
	}
	return nil
}

func (s *Session) Decrypt(ciphertext []byte) (plaintext []byte) {
	result := make([]byte, len(ciphertext))
	decrypted := C.sliot_decrypt(&s.actual, unsafe.Pointer(&ciphertext[0]), C.size_t(len(ciphertext)), unsafe.Pointer(&result[0]))
	if decrypted > 0 {
		return result[:decrypted]
	}
	return nil
}