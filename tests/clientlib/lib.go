package clientlib 

// #cgo CFLAGS: -I${SRCDIR}/../../client-lib/src
// #include "sliot_connection.h"
// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
import "C"
import "unsafe"
import (
	"crypto/rand"
)

type Config struct {
	actual C.sliot_config
}

type HandShake struct {
	actual C.sliot_handshake
}

type Session struct {
	actual C.sliot_session
}

func CreateConfig(longTermSecret, longTermPublic, serverLongTermPublic []byte) *Config {
	var result Config
	C.memcpy(unsafe.Pointer(&result.actual.long_term_secret), unsafe.Pointer(&(longTermSecret[0])), C.size_t(32))
	C.memcpy(unsafe.Pointer(&result.actual.long_term_public), unsafe.Pointer(&(longTermPublic[0])), C.size_t(32))
	C.memcpy(unsafe.Pointer(&result.actual.server_long_term_public), unsafe.Pointer(&(serverLongTermPublic[0])), C.size_t(32))
	return &result
}

func HandshakeInit(cfg *Config) (*HandShake, []byte) {
	message := make([]byte, C.SLIOT_HANDSHAKE_SIZE)
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	var result HandShake
	messageSize := C.sliot_handshake_init(unsafe.Pointer(&cfg.actual), unsafe.Pointer(&message[0]), unsafe.Pointer(&result.actual), unsafe.Pointer(&randomBytes[0]))
	return *result, message[:messageSize]
}