package longterm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"crypto/ed25519"
)

const (
	PrivateKeySize = ed25519.PrivateKeySize
)

func CalculatePublic(privateKey []byte) (publicKey []byte, err error) {
	if len(privateKey) != PrivateKeySize {
		return nil, fmt.Errorf("Incorrect private key size: %v", len(privateKey))
	}
	publicKey = make([]byte, ed25519.PublicKeySize)
	copy(publicKey, privateKey[32:])
	return publicKey, nil
}

func GenerateKeyPair() (longTermPrivate, longTermPublic []byte, err error) {
	return ed25519.GenerateKey(rand.Reader)
}

func KeyToString(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func StringToKey(key string) (result []byte, err error) {
	result, err = base64.StdEncoding.DecodeString(key)
	if err == nil && (len(result) != ed25519.PrivateKeySize || len(result) != ed25519.PublicKeySize) {
		err = fmt.Errorf("Key file not right size: %v", len(result))
	}
	return
}

func ReadPrivateKey(fileName string) (privateKey []byte, err error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return
	}

	privateKey = make([]byte, ed25519.PrivateKeySize)
	n, err := base64.StdEncoding.Decode(privateKey, b)
	if err == nil && n != ed25519.PrivateKeySize {
		err = fmt.Errorf("Key file not right size: %v", n)
	}

	return
}
