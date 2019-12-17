package peer

import (
	"crypto/rand"
	"siot-server/monocypher"
	"siot-server/server"

	"golang.org/x/crypto/blake2b"
)

type Peer struct {
	Mac         [6]byte
	PublicKey   []byte
	sessionKey  []byte
	lastCounter uint32
}

func (p *Peer) Initialize(mac [6]byte, publicKey []byte) {
	copy(p.Mac[:], mac[:])
	copy(p.PublicKey, publicKey)
	p.lastCounter = 0
}

func MacToId(mac [6]byte) uint64 {
	return uint64(mac[0]) |
		uint64(mac[1])<<8 |
		uint64(mac[2])<<16 |
		uint64(mac[3])<<24 |
		uint64(mac[4])<<32 |
		uint64(mac[5])<<40
}

func (p *Peer) KeyExchangeReply(receivedPublic, receivedSignature []byte, srv *server.Server) (publicKey, signature []byte) {
	if monocypher.Verify(receivedSignature, receivedPublic, p.PublicKey) {
		private := make([]byte, 32)
		rand.Read(private)
		publicKey := monocypher.KeyExchangePublicKey(private)
		sharedSecret := monocypher.KeyExchange(private, receivedPublic)

		hasher, _ := blake2b.New(32, nil)
		hasher.Write(sharedSecret)
		hasher.Write(srv.PublicKey)
		hasher.Write(p.PublicKey)

		p.sessionKey = hasher.Sum(nil)

		hasher.Reset()

		// overwrite private key data
		rand.Read(private)
		rand.Read(sharedSecret)

		return publicKey, srv.Sign(publicKey)
	}
	return nil, nil
}

func (p *Peer) DecryptMessage(message, counter, nonce, mac []byte) (plaintext []byte) {
	counterFull := uint32(counter[0]) | uint32(counter[1])<<8
	if counterFull > p.lastCounter {
		p.lastCounter = counterFull
		return monocypher.UnlockAEAD(message, nonce, p.sessionKey, mac, counter)
	}
	return nil
}
