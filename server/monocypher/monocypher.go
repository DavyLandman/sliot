package monocypher

// #include "monocypher.h"
// #include <stdio.h>
// #include <stdlib.h>
import "C"
import "unsafe"

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

	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(key[:32]))))
	defer C.free(unsafe.Pointer(CKey))

	CNonce := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(nonce[:24]))))
	defer C.free(unsafe.Pointer(CNonce))

	CMac := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(mac[:16]))))
	defer C.free(unsafe.Pointer(CMac))

	CPlain := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, len(ciphertext)))))
	defer C.free(unsafe.Pointer(CPlain))
	//	C Method call
	C.crypto_unlock_aead(CPlain, CKey, CNonce, CMac, CAD, CADSize, CCipher, CSize)
	var GPlain []byte = C.GoBytes(unsafe.Pointer(CPlain), C.int(len(ciphertext)))
	// return Nmac, Ncipher

	return GPlain
}


func KeyExchangePublicKey(secretKey []byte) (publicKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:32]))))
	defer C.free(unsafe.Pointer(CKey))

	CPublic := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 32))))
	defer C.free(unsafe.Pointer(CPublic))

	C.crypto_key_exchange_public_key(CPublic, CKey)
	return C.GoBytes(unsafe.Pointer(CPublic), C.int(32))
}

func KeyExchange(ourSecretKey, theirPublicKey []byte) (sharedKey []byte {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:32]))))
	defer C.free(unsafe.Pointer(CKey))

	CTheir := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(theirPublicKey[:32]))))
	defer C.free(unsafe.Pointer(CTheir))

	CShared := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 32))))
	defer C.free(unsafe.Pointer(CShared))

	C.crypto_key_exchange(CShared, CKey, CTheir)

	return C.GoBytes(unsafe.Pointer(CShared), C.int(32))
}

func SignPublicKey(secretKey []byte) (publicKey []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:32]))))
	defer C.free(unsafe.Pointer(CKey))

	CPublic := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 32))))
	defer C.free(unsafe.Pointer(CPublic))

	C.crypto_sign_public_key(CPublic, CKey)
	return C.GoBytes(unsafe.Pointer(CPublic), C.int(32))
}


func Sign(secretKey, message []byte) (signature []byte) {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(secretKey[:32]))))
	defer C.free(unsafe.Pointer(CKey))

	CSize := (C.size_t)(len(message))
	CMessage := (*C.uint8_t)(unsafe.Pointer(C.CBytes(message)))
	defer C.free(unsafe.Pointer(CMessage))


	CSignature := (*C.uint8_t)(unsafe.Pointer(C.CBytes(make([]uint8, 64))))
	defer C.free(unsafe.Pointer(CSignature))

	C.crypto_sign(CSignature, CKey, C.null(), CMessage, CSize)
	return C.GoBytes(unsafe.Pointer(CSignature), C.int(64))
}


func Verify(signature, publicKey, message []byte) bool {
	CKey := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(publicKey[:32]))))
	defer C.free(unsafe.Pointer(CKey))

	CSize := (C.size_t)(len(message))
	CMessage := (*C.uint8_t)(unsafe.Pointer(C.CBytes(message)))
	defer C.free(unsafe.Pointer(CMessage))

	CSignature := (*C.uint8_t)(unsafe.Pointer(C.CBytes([]uint8(signature[:64]))))
	defer C.free(unsafe.Pointer(CSignature))

	return C.int(1) == C.crypto_check(CSignature, CKey, CMessage, CSize)
}