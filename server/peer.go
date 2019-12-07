package main

import (
	"crypto/rand"
	"monocypher/monocypher"
	"golang.org/x/crypto/blake2b"
)

type Peer struct {
	Mac [6]byte
	PublicKey []byte
	sessionKey []byte
	lastCounter uint32 
}

func (struct Peer* p) Initialize(mac [6]byte, publicKey []byte) {
	copy(p.Mac[:], mac[:])
	copy(p.PublicKey, publicKey)
	p.last_counter = 0
}

func MacToId(mac [6]byte) uint64 {
	return mac[0] 
		| mac[1] << 8
		| mac[2] << 16
		| mac[3] << 24
		| mac[4] << 32
		| mac[5] << 40
		| 0x42 << 48
}

func (struct Peer* p) KeyExchangeReply(receivedPublic, receivedSignature  []byte, server struct Server) (publicKey, signature []byte) {
	if monocypher.Verify(receivedSignature, receivedPublic, p.signingKey) {
		private := make([]byte, 32)
		rand.Read(private)
		const publicKey := monocypher.KeyExchangePublicKey(private)
		const sharedSecret := monoCypher.KeyExchange(private, receivedPublic)

		hasher, _ := blake2b.New(32, nil)
		hasher.Write(sharedSecret)
		hasher.Write(server.PublicKey)
		hasher.Write(p.publicKey)

		p.sessionKey := hasher.Sum(nil)

		hasher.Reset()

		// overwrite private key data
		rand.Read(private)
		rand.Read(sharedSecret)

		return (publicKey, server.Sign(publicKey))
	}
	return (nil, nil)
}

func (struct Peer* p) DecryptMessage(message, counter, nonce, mac []byte) (plaintext []byte) {
	counterFull := uint16(counter[0]) | uint16(counter[1] << 8)
	if counterFull > p.lastCounter {
		return monocypher.UnlockAEAD(message, nonce, p.sessionKey, mac, counter)
	}
	return nil
}