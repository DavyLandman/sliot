package monocypher

// #include "monocypher.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"
import "unsafe"


// TODO wipe copies of all keys before freeing

const (
	PublicKeySize = 32
	AEADKeySize = 32
	PrivateKeySize = 32
	SharedKeySize = 32
	SignatureSize = 64
	NonceSize = 24
	MACSize = 16
)

func UnlockAEAD(ciphertext, nonce, key, mac, ad []byte) (plaintext []byte) {
	CSize := (C.size_t)(len(ciphertext))
	CCipher := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ciphertext)))
	defer C.free(unsafe.Pointer(CCipher))

	CADSize := (C.size_t)(len(ad))
	CAD := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ad)))
	defer C.free(unsafe.Pointer(CAD))

	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:AEADKeySize]))))
	defer clearAndFree(unsafe.Pointer(CKey), AEADKeySize)

	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:NonceSize]))))
	defer C.free(unsafe.Pointer(CNonce))

	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(mac[:MACSize]))))
	defer C.free(unsafe.Pointer(CMac))

	CPlain := (*C.uint8_t)(C.CBytes(make([]uint8, len(ciphertext))))
	defer clearAndFree(unsafe.Pointer(CPlain), len(ciphertext))
	//	C Method call
	if C.crypto_unlock_aead(CPlain, CKey, CNonce, CMac, CAD, CADSize, CCipher, CSize) == C.int(0) {
		return C.GoBytes(unsafe.Pointer(CPlain), C.int(len(ciphertext)))
	}

	return nil 
}

func KeyExchangePublicKey(secretKey []byte) (publicKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:PrivateKeySize]))))
	defer clearAndFree(unsafe.Pointer(CKey), PrivateKeySize)

	CPublic := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, PublicKeySize))))
	defer C.free(unsafe.Pointer(CPublic))

	C.crypto_key_exchange_public_key(CPublic, CKey)
	return C.GoBytes(unsafe.Pointer(CPublic), C.int(PublicKeySize))
}

func KeyExchange(ourSecretKey, theirPublicKey []byte) (sharedKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(ourSecretKey[:PrivateKeySize]))))
	defer clearAndFree(unsafe.Pointer(CKey), PrivateKeySize)

	CTheir := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(theirPublicKey[:PublicKeySize]))))
	defer C.free(unsafe.Pointer(CTheir))

	CShared := (*C.uint8_t)(C.CBytes(make([]uint8, SharedKeySize)))
	defer clearAndFree(unsafe.Pointer(CShared), SharedKeySize)

	if C.crypto_key_exchange(CShared, CKey, CTheir) == C.int(0) {
		return C.GoBytes(unsafe.Pointer(CShared), C.int(SharedKeySize))
	}
	return nil

}

func SignPublicKey(secretKey []byte) (publicKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:PrivateKeySize]))))
	defer clearAndFree(unsafe.Pointer(CKey), PrivateKeySize)

	CPublic := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, PublicKeySize))))
	defer C.free(unsafe.Pointer(CPublic))

	C.crypto_sign_public_key(CPublic, CKey)
	return C.GoBytes(unsafe.Pointer(CPublic), C.int(PublicKeySize))
}

func Sign(secretKey, message []byte) (signature []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:PrivateKeySize]))))
	defer clearAndFree(unsafe.Pointer(CKey), PrivateKeySize)

	CSize := (C.size_t)(len(message))
	CMessage := (*C.uint8_t)(unsafe.Pointer(C.CBytes(message)))
	defer C.free(unsafe.Pointer(CMessage))

	CSignature := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, SignatureSize))))
	defer C.free(unsafe.Pointer(CSignature))

	C.crypto_sign(CSignature, CKey, nil, CMessage, CSize)
	return C.GoBytes(unsafe.Pointer(CSignature), C.int(SignatureSize))
}

func Verify(signature, publicKey, message []byte) bool {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(publicKey[:PublicKeySize]))))
	defer C.free(unsafe.Pointer(CKey))

	CSize := (C.size_t)(len(message))
	CMessage := (*C.uint8_t)(unsafe.Pointer(C.CBytes(message)))
	defer C.free(unsafe.Pointer(CMessage))

	CSignature := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(signature[:SignatureSize]))))
	defer C.free(unsafe.Pointer(CSignature))

	return C.int(1) == C.crypto_check(CSignature, CKey, CMessage, CSize)
}


func clearAndFree(target unsafe.Pointer, size int) {
	C.crypto_wipe(target, C.size_t(size))
	C.free(target)
}