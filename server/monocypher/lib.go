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
	SignatureSize = 64
	NonceSize = 24
	MACSize = 16
)

func UnlockAEAD(ciphertext, nonce, key, mac, ad []byte) (plaintext []byte) {
	/*
			int crypto_unlock_aead(uint8_t       *plain_text,
							const uint8_t  key[32],
							const uint8_t  nonce[24],
							const uint8_t  mac[16],
		                    const uint8_t *ad         , size_t ad_size,
							const uint8_t *cipher_text, size_t text_size);
	*/

	CSize := (C.size_t)(len(ciphertext))
	CCipher := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ciphertext)))
	defer C.free(unsafe.Pointer(CCipher))

	CADSize := (C.size_t)(len(ad))
	CAD := (*C.uint8_t)(unsafe.Pointer(C.CBytes(ad)))
	defer C.free(unsafe.Pointer(CAD))

	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:AEADKeySize]))))
	defer C.free(unsafe.Pointer(CKey))

	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:NonceSize]))))
	defer C.free(unsafe.Pointer(CNonce))

	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(mac[:MACSize]))))
	defer C.free(unsafe.Pointer(CMac))

	CPlain := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(ciphertext)))))
	defer C.free(unsafe.Pointer(CPlain))
	//	C Method call
	if C.crypto_unlock_aead(CPlain, CKey, CNonce, CMac, CAD, CADSize, CCipher, CSize) == 0 {
		return C.GoBytes(unsafe.Pointer(CPlain), C.int(len(ciphertext)))
	}

	return nil 
}

func KeyExchangePublicKey(secretKey []byte) (publicKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:PrivateKeySize]))))
	defer C.free(unsafe.Pointer(CKey))

	CPublic := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, PublicKeySize))))
	defer C.free(unsafe.Pointer(CPublic))

	C.crypto_key_exchange_public_key(CPublic, CKey)
	return C.GoBytes(unsafe.Pointer(CPublic), C.int(PublicKeySize))
}

func KeyExchange(ourSecretKey, theirPublicKey []byte) (sharedKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(ourSecretKey[:PrivateKeySize]))))
	defer C.free(unsafe.Pointer(CKey))

	CTheir := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(theirPublicKey[:PublicKeySize]))))
	defer C.free(unsafe.Pointer(CTheir))

	CShared := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 32))))
	defer C.free(unsafe.Pointer(CShared))

	C.crypto_key_exchange(CShared, CKey, CTheir)

	return C.GoBytes(unsafe.Pointer(CShared), C.int(32))
}

func SignPublicKey(secretKey []byte) (publicKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:PrivateKeySize]))))
	defer C.free(unsafe.Pointer(CKey))

	CPublic := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, PublicKeySize))))
	defer C.free(unsafe.Pointer(CPublic))

	C.crypto_sign_public_key(CPublic, CKey)
	return C.GoBytes(unsafe.Pointer(CPublic), C.int(PublicKeySize))
}

func Sign(secretKey, message []byte) (signature []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:PrivateKeySize]))))
	defer C.free(unsafe.Pointer(CKey))

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
