package peer

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"

	"siot-server/monocypher"
	"siot-server/server"
)

type Peer struct {
	Mac         [6]byte
	PublicKey   []byte
	sessionKey  []byte
	lastCounter uint32
	gobKey      []byte
}

func (p *Peer) Initialize(mac [6]byte, publicKey []byte, gobKey []byte) {
	copy(p.Mac[:], mac[:])
	copy(p.PublicKey, publicKey)
	copy(p.gobKey, gobKey)
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
		result := monocypher.UnlockAEAD(message, nonce, p.sessionKey, mac, counter)
		if result != nil {
			p.lastCounter = counterFull
			return result
		}
	}
	return nil
}

type privatePeerData struct {
	SessionKey  []byte
	LastCounter uint32
}

func (p Peer) SaveSession() ([]byte, error) {
	var rawMessage bytes.Buffer
	err := gob.NewEncoder(&rawMessage).Encode(privatePeerData{p.sessionKey, p.lastCounter})
	if err != nil {
		return nil, err
	}
	cipher, err := chacha20poly1305.NewX(p.sessionKey)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, cipher.NonceSize())
	rand.Read(nonce)

	// we append the nonce with the encrypted data
	return cipher.Seal(nonce, nonce, rawMessage.Bytes(), p.PublicKey)
}

func (p *Peer) RestoreSession(data []byte) error {
	cipher, err := chacha20poly1305.NewX(p.sessionKey)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Open(nil, data[:cipher.NonceSize()], data[cipher.NonceSize():], p.PublicKey)
	if err != nil {
		return err
	}
	var serializedData privatePeerData
	err = gob.NewDecoder(bytes.NewBuffer(decrypted)).Decode(&serializedData)
	if err != nil {
		return err
	}
	p.sessionKey = serializedData.SessionKey
	p.lastCounter = serializedData.LastCounter
	return nil
}
