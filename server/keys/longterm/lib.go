package longterm

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"

	"github.com/DavyLandman/sliot/server/monocypher"
)

func CalculatePublic(privateKey []byte) []byte {
	return monocypher.SignPublicKey(privateKey)
}

func GenerateKeyPair() (longTermPrivate, longTermPublic []byte) {
	longTermPrivate = make([]byte, monocypher.PrivateKeySize)
	rand.Read(longTermPrivate)

	longTermPublic = CalculatePublic(longTermPrivate)
	return
}

func KeyToString(key []byte) string {
	return base64.StdEncoding.EncodeToString(key)
}

func StringToKey(key string) (result []byte, err error) {
	result, err = base64.StdEncoding.DecodeString(key)
	if err == nil && (len(result) != monocypher.PrivateKeySize || len(result) != monocypher.PublicKeySize) {
		err = fmt.Errorf("Key file not right size: %v", len(result))
	}
	return
}

func ReadPrivateKey(fileName string) (privateKey []byte, err error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return
	}

	privateKey = make([]byte, monocypher.PrivateKeySize)
	n, err := base64.StdEncoding.Decode(privateKey, b)
	if err == nil && n != monocypher.PrivateKeySize {
		err = fmt.Errorf("Key file not right size: %v", n)
	}

	return
}
