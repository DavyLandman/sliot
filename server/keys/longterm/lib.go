package longterm

import (
	"fmt"
	"io/ioutil"

	"github.com/btcsuite/btcutil/bech32"

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

func GenerateKeyPair() (longTermPublic, longTermPrivate []byte, err error) {
	return ed25519.GenerateKey(nil)
}

const publicKeyType = "sliot-public"
const privateKeyType = "sliot-private"

func KeyToString(key []byte) (string, error) {
	keyType := publicKeyType
	if len(key) == ed25519.PrivateKeySize {
		keyType = privateKeyType
		key = key[:32] // we only encode the private key and recover it when reading back
	}
	converted, err := bech32.ConvertBits(key, 8, 5, true)
	if err != nil {
		return "", err
	}
	return bech32.Encode(keyType, converted)
}

func StringToKey(key string) (result []byte, err error) {
	keyType, encodedResult, err := bech32.Decode(key)
	if err != nil {
		return
	}
	result, err = bech32.ConvertBits(encodedResult, 5, 8, false)
	if err == nil {
		if len(result) != 32 {
			err = fmt.Errorf("Key not right size: %v", len(result))
			result = nil
		} else if keyType == publicKeyType {
			return
		} else if keyType == privateKeyType {
			result = ed25519.NewKeyFromSeed(result)
		} else {
			err = fmt.Errorf("Incorrect keytype, expected: %v or %v but got: %v", publicKeyType, privateKeyType, keyType)
			result = nil
		}
	}
	return
}

func ReadPrivateKey(fileName string) (privateKey []byte, err error) {
	b, err := ioutil.ReadFile(fileName)
	if err != nil {
		return
	}
	return StringToKey(string(b))
}
