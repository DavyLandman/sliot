package client

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
	"io"

	"siot-server/monocypher"
)

type EncryptedClient struct {
	Mac         [6]byte
	PublicKey   []byte
	sessionKey  []byte
	lastCounter uint32
}

func (p *EncryptedClient) Initialize(mac [6]byte, publicKey []byte) {
	copy(p.Mac[:], mac[:])
	copy(p.PublicKey, publicKey)
	p.lastCounter = 0
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

func (p EncryptedClient) SaveSession(target io.Writer, dataKey []byte) error {
	var rawMessage bytes.Buffer
	err := gob.NewEncoder(&rawMessage).Encode(privatePeerData{p.sessionKey, p.lastCounter})
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
	p.lastCounter = serializedData.LastCounter
	return nil
}
