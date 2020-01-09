package main

import (
	"io/ioutil"
	"log"

	"github.com/DavyLandman/sliot/server"
	"github.com/DavyLandman/sliot/server/client"
	"github.com/DavyLandman/sliot/server/keys/longterm"
	//"github.com/DavyLandman/sliot/keys/longterm"
	"github.com/DavyLandman/sliot/test/clientlib"
)

func main() {
	dataFolder, err := ioutil.TempDir("", "sliot-test")
	if err != nil {
		log.Fatal(err)
	}

	serverPrivateKey, serverPublicKey := longterm.GenerateKeyPair()
	clientPrivateKey, clientPublicKey := longterm.GenerateKeyPair()

	clientMac := [6]byte{0, 1, 2, 3, 4, 5}
	clientConf := server.ClientConfig{clientMac, clientPublicKey}

	incoming := make(chan client.Message, 200)
	outgoing := make(chan client.Message, 200)
	fakeServer, err := server.Start([]server.ClientConfig{clientConf}, dataFolder, longterm.KeyToString(serverPrivateKey), incoming, outgoing)

	fakeClient := clientlib.CreateConfig(clientPrivateKey, clientPublicKey, serverPublicKey)

}
