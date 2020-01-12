package main

import (
	"io/ioutil"
	"log"

	"github.com/DavyLandman/sliot/server"
	"github.com/DavyLandman/sliot/server/client"
	"github.com/DavyLandman/sliot/server/keys/longterm"
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

	fakeClient, err := clientlib.CreateConfig(clientPrivateKey, clientPublicKey, serverPublicKey)

	log.Println("Got stuff setup")
	log.Printf("Server: %v\n", fakeServer)
	log.Printf("Client: %v\n", fakeClient)

	handshake, msg := fakeClient.HandshakeInit()
	log.Printf("Handshake started from client, msg: %v", msg)
	incoming <- client.Message{Mac: clientMac, Message: msg}
	reply := <-outgoing
	log.Printf("Reply from server: %v", reply)
	session := handshake.Finish(reply.Message)
	if session == nil {
		log.Fatalf("Error in handshake handling")
	} else {
		log.Printf("Session started: %v", session)
	}
	msg = session.Encrypt(clientMac[:])
	if msg == nil {
		log.Fatalf("Error in encrypting message")
	} else {
		log.Printf("Prepared encrypted message: %v", msg)
	}
	incoming <- client.Message{Mac: clientMac, Message: msg}
	recvMessage := <-fakeServer.GetInbox()
	log.Printf("Received encrypted message: %v", recvMessage)

}
