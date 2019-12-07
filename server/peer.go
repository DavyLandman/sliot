package main

import (
	"crypto/rand"
	"monocypher/monocypher"
	"golang.org/x/crypto/blake2b"
)

type Peer struct {
	Mac byte[6]
	PublicKey byte[]
	sessionKey byte[]
	lastCounter uint32 
}

func (struct Peer* p) Initialize(mac byte[6], publicKey byte[]) {
	copy(p.Mac[:], mac[:])
	copy(p.PublicKey, publicKey)
	p.last_counter = 0
}

func (struct Peer *p) GetId() uint64 {
	return p.mac[0] 
		| p.mac[1] << 8
		| p.mac[2] << 16
		| p.mac[3] << 24
		| p.mac[4] << 32
		| p.mac[5] << 40
		| 0x42 << 48
}

func (struct Peer* p) KeyExchangeReply(receivedPublic, receivedSignature  byte[], server struct Server) (publicKey, signature byte[]) {
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