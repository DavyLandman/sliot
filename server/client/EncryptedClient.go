package client

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"
	"sync/atomic"

	"github.com/DavyLandman/sliot/server/monocypher"
)

const (
	SessionKeySize = chacha20poly1305.KeySize
)

type EncryptedClient struct {
	Mac            [6]byte
	PublicKey      []byte
	sessionKey     []byte
	receiveCounter uint32
	sendCounter    uint32
}

func (p *EncryptedClient) Initialize(mac [6]byte, publicKey []byte) {
	copy(p.Mac[:], mac[:])
	copy(p.PublicKey, publicKey)
	p.receiveCounter = 0
	p.sendCounter = 0
}

func (p *EncryptedClient) KeyExchangeReply(receivedPublic, receivedSignature, serverPublic []byte) (publicKey []byte) {
	if monocypher.Verify(receivedSignature, receivedPublic, p.PublicKey) {
		private := make([]byte, monocypher.PrivateKeySize)
		rand.Read(private)
		publicKey := monocypher.KeyExchangePublicKey(private)
		sharedSecret := monocypher.KeyExchange(private, receivedPublic)

		hasher, _ := blake2b.New(monocypher.AEADKeySize, nil)
		hasher.Write(sharedSecret)
		hasher.Write(serverPublic)
		hasher.Write(p.PublicKey)

		p.sessionKey = hasher.Sum(nil)
		p.receiveCounter = 0
		p.sendCounter = 0

		hasher.Reset()

		// overwrite private key data
		rand.Read(private)
		rand.Read(sharedSecret)

		return publicKey
	}
	return nil
}

func (p *EncryptedClient) DecryptMessage(message, counter, nonce, mac []byte) (plaintext []byte) {
	counterFull := uint32(counter[0]) | uint32(counter[1])<<8
	if counterFull > p.receiveCounter {
		result := monocypher.UnlockAEAD(message, nonce, p.sessionKey, mac, counter)
		if result != nil {
			p.receiveCounter = counterFull
			return result
		}
	}
	return nil
}

func (p *EncryptedClient) EncryptMessage(message []byte) (cipherText, counter, nonce, mac []byte) {
	nextCounter := atomic.AddUint32(&p.sendCounter, 1)
	counter = []byte{byte(nextCounter & 0xFF), byte((nextCounter >> 8) & 0xFF)}
	nonce = make([]byte, monocypher.NonceSize)
	rand.Read(nonce)
	mac, cipherText = monocypher.LockAEAD(cipherText, nonce, p.sessionKey, counter)
	return cipherText, counter, nonce, mac
}

type privatePeerData struct {
	SessionKey     []byte
	ReceiveCounter uint32
	SendCounter    uint32
}

func (p EncryptedClient) SaveSession(target io.Writer, dataKey []byte) error {
	var rawMessage bytes.Buffer
	err := gob.NewEncoder(&rawMessage).Encode(privatePeerData{p.sessionKey, p.receiveCounter, p.sendCounter})
	if err != nil {
		return err
	}
	cipher, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, cipher.NonceSize())
	rand.Read(nonce)
	_, err = target.Write(nonce)
	if err != nil {
		return err
	}

	_, err = target.Write(cipher.Seal(nil, nonce, rawMessage.Bytes(), p.PublicKey))
	return err
}

func (p *EncryptedClient) RestoreSession(source io.Reader, dataKey []byte) error {
	cipher, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		return err
	}

	nonce := make([]byte, cipher.NonceSize())
	_, err = source.Read(nonce)
	if err != nil {
		return err
	}

	var cipherText bytes.Buffer
	_, err = cipherText.ReadFrom(source)
	if err != nil {
		return err
	}

	decrypted, err := cipher.Open(nil, nonce, cipherText.Bytes(), p.PublicKey)
	if err != nil {
		return err
	}

	var serializedData privatePeerData
	err = gob.NewDecoder(bytes.NewBuffer(decrypted)).Decode(&serializedData)
	if err != nil {
		return err
	}
	p.sessionKey = serializedData.SessionKey
	p.receiveCounter = serializedData.ReceiveCounter
	p.sendCounter = serializedData.SendCounter
	return nil
}
