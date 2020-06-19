package client

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"io"
	"sync/atomic"

	"crypto/ed25519"
	"crypto/sha512"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	SessionKeySize = chacha20poly1305.KeySize
)

type EncryptedClient struct {
	Mac            [6]byte
	PublicKey      []byte
	sessionKey     []byte
	sessionCrypto  cipher.AEAD
	receiveCounter uint32
	sendCounter    uint32
}

func (p *EncryptedClient) Initialize(mac [6]byte, publicKey []byte) {
	copy(p.Mac[:], mac[:])
	p.PublicKey = append([]byte(nil), publicKey...)
	p.receiveCounter = 0
	p.sendCounter = 0
}

func (p *EncryptedClient) KeyExchangeReply(receivedPublic, receivedSignature, serverPublic []byte) (publicKey []byte) {
	if ed25519.Verify(p.PublicKey, receivedPublic, receivedSignature) {
		private := make([]byte, curve25519.ScalarSize)
		rand.Read(private)
		publicKey, err := curve25519.X25519(private, curve25519.Basepoint)
		if err != nil {
			return nil
		}
		sharedSecret, err := curve25519.X25519(private, receivedPublic)
		if err != nil {
			return nil
		}

		hasher := sha512.New()
		hasher.Write(sharedSecret)
		hasher.Write(serverPublic)
		hasher.Write(p.PublicKey)

		p.sessionKey = hasher.Sum(nil)[:chacha20poly1305.KeySize]
		sessionCrypto, err := chacha20poly1305.New(p.sessionKey)
		if err != nil {
			return nil
		}
		p.sessionCrypto = sessionCrypto
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
		result, err := p.sessionCrypto.Open(nil, nonce, message, counter)
		if result != nil && err == nil {
			p.receiveCounter = counterFull
			return result
		}
	} else {
		fmt.Printf("Incorrect counter received: %v", counterFull)
	}
	return nil
}

func (p *EncryptedClient) EncryptMessage(message []byte) (cipherText, counter, nonce []byte) {
	nextCounter := atomic.AddUint32(&p.sendCounter, 1)
	counterBytes := new(bytes.Buffer)
	binary.Write(counterBytes, binary.LittleEndian, uint16(nextCounter))
	counter = counterBytes.Bytes()
	nonce = make([]byte, p.sessionCrypto.NonceSize())
	rand.Read(nonce)
	cipherText = p.sessionCrypto.Seal(nil, nonce, message, counter)
	return
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
	p.sessionCrypto, err = chacha20poly1305.New(p.sessionKey)
	if err != nil {
		return err
	}
	p.receiveCounter = serializedData.ReceiveCounter
	p.sendCounter = serializedData.SendCounter
	return nil
}
