package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"siot-server/monocypher"
)

func main() {
	var serverKey bool
	var longTermPublicKey string
	var serverMac string

	flag.BoolVar(&serverKey, "generateServer", false, "Generate new server keys instead of a new pair of client keys")
	flag.StringVar(&longTermPublicKey, "serverPublicKey", "", "provide long term public key in base64 format for the server")
	flag.StringVar(&serverMac, "serverMac", "00:00:00:00:00:00", "mac of the server")
	flag.Parse()

	if serverKey {
		generateServerKeys()
	} else {
		if len(longTermPublicKey) == 0 {
			log.Fatalf("Must supply public key")
		}
		serverKey, err := base64.StdEncoding.DecodeString(longTermPublicKey)
		if err != nil {
			log.Fatal("Cannot decode public key: %v", err)
		}
		generateClientKeys(serverKey, serverMac)
	}
}

func generateServerKeys() {
	fmt.Println("Generating new server keys")
	dataKey := make([]byte, chacha20poly1305.KeySize)
	rand.Read(dataKey)

	longTermPrivateKey := make([]byte, monocypher.PrivateKeySize)
	rand.Read(longTermPrivateKey)

	longTermPublicKey := monocypher.SignPublicKey(longTermPrivateKey)

	fmt.Printf("DATA_KEY=\"%v\"\n", base64.StdEncoding.EncodeToString(dataKey))
	fmt.Printf("LONG_TERM_PRIVATE_KEY=\"%v\"\n", base64.StdEncoding.EncodeToString(longTermPrivateKey))
	fmt.Printf("LONG_TERM_PUBLIC_KEY=\"%v\"\n", base64.StdEncoding.EncodeToString(longTermPublicKey))
}

func generateClientKeys(serverKey []byte, serverMac string) {
	fmt.Println("Generating new client keys")
	longTermPrivateKey := make([]byte, monocypher.PrivateKeySize)
	rand.Read(longTermPrivateKey)

	longTermPublicKey := monocypher.SignPublicKey(longTermPrivateKey)

	fmt.Println("For client c code:")
	fmt.Printf("static struct siot_config main_config = {\n\t%v, \n\t%v, \n\t%v, \n\t%v\n}\n",
		byteArray(longTermPrivateKey),
		byteArray(longTermPublicKey),
		byteArray(serverKey),
		macByteArray(serverMac),
	)
	fmt.Println("For config.toml:")
	fmt.Printf("publicKey = \"%v\"\n", base64.StdEncoding.EncodeToString(longTermPublicKey))
}

func byteArray(bytes []byte) string {
	var result strings.Builder
	first := true

	result.WriteString("(uint8_t []){")
	for _, b := range bytes {
		if !first {
			result.WriteString(",")
		}
		result.WriteString(fmt.Sprintf("0x%02x", b))
		first = false
	}
	result.WriteString("}")
	return result.String()
}

func macByteArray(mac string) string {
	asBytes := make([]byte, 6)
	chunks := strings.Split(mac, ":")
	for i := 0; i < 6; i++ {
		macChunk, err := strconv.ParseUint(chunks[i], 16, 8)
		if err != nil {
			log.Fatalf("Error converting mac array: %v", err)
		}
		asBytes[i] = byte(macChunk)
	}
	return byteArray(asBytes)
}
