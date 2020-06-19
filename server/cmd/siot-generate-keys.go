package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/DavyLandman/sliot/server/keys/longterm"
)

func main() {
	var generatePrivateKey, printPublicKey bool
	var longTermPublicKey, privateKeyFile string
	var serverMac string

	flag.BoolVar(&generatePrivateKey, "generatePrivateKey", false, "Generate new long-term server key")
	flag.BoolVar(&printPublicKey, "printPublicKey", false, "Print public key corresponding to private key of server")
	flag.StringVar(&privateKeyFile, "privateKey", "", "private key to extract the public key from")

	flag.StringVar(&longTermPublicKey, "serverPublicKey", "", "provide long term public key in base64 format for the server")
	flag.StringVar(&serverMac, "serverMac", "00:00:00:00:00:00", "mac of the server")
	flag.Parse()

	if generatePrivateKey {
		generateServerKeys()
	} else if printPublicKey {
		printoutPublicKey(privateKeyFile)
	} else {
		if len(longTermPublicKey) == 0 {
			var err error
			encodedKey, err := calculatePublicKey(privateKeyFile)
			if err != nil {
				log.Fatalf("Must supply public key or the private key file")
			} else {
				longTermPublicKey = longterm.KeyToString(encodedKey)
				log.Printf("Calculated public key: %v based on supplied private key\n", longTermPublicKey)
			}
		}
		serverKey, err := longterm.StringToKey(longTermPublicKey)
		if err != nil {
			log.Fatalf("Cannot decode public key: %v", err)
		}
		generateClientKeys(serverKey, serverMac)
	}
}

func generateServerKeys() {
	longTermPrivateKey, _, err := longterm.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Failure to generate server keys: %v", err)
	}
	fmt.Println(longterm.KeyToString(longTermPrivateKey))
}

func printoutPublicKey(privateKeyFile string) {
	publicKey, err := calculatePublicKey(privateKeyFile)
	if err != nil {
		log.Fatalf("Failure to calculate the public key based on %v, error: %v", privateKeyFile, err)
	}
	fmt.Println("** Public key")
	fmt.Printf("* base64: \t%v\n", base64.StdEncoding.EncodeToString(publicKey))
	fmt.Printf("* c bytes:\t%v\n", byteArray(publicKey))
}

func calculatePublicKey(privateKeyFile string) ([]byte, error) {
	privateKey, err := longterm.ReadPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	return longterm.CalculatePublic(privateKey)
}

func generateClientKeys(serverKey []byte, serverMac string) {
	fmt.Println("Generating new client keys")
	longTermPrivateKey, longTermPublicKey, err := longterm.GenerateKeyPair()
	if err != nil {
		log.Fatalf("Could not generate keys: %v", err)
	}

	fmt.Println("For client c code:")
	fmt.Printf("static struct siot_config main_config = {\n\t%v, \n\t%v, \n\t%v, \n\t%v\n}\n",
		byteArray(longTermPrivateKey),
		byteArray(longTermPublicKey),
		byteArray(serverKey),
		macByteArray(serverMac),
	)
	fmt.Println("For config.toml:")
	fmt.Printf("publicKey = \"%v\"\n", longterm.KeyToString(longTermPublicKey))
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
	asBytes, err := parseMacString(mac)
	if err != nil {
		log.Fatalf("Error converting mac array: %v", err)
	}
	return byteArray(asBytes[:])
}

func parseMacString(mac string) ([6]byte, error) {
	var asBytes [6]byte
	chunks := strings.Split(mac, ":")
	if len(chunks) != 6 {
		return asBytes, fmt.Errorf("Incorrect mac: %v", mac)
	}
	for i := 0; i < 6; i++ {
		macChunk, err := strconv.ParseUint(chunks[i], 16, 8)
		if err != nil {
			return asBytes, fmt.Errorf("Error parsing mac: %v (%v)", mac, err)
		}
		asBytes[i] = byte(macChunk)
	}
	return asBytes, nil
}
