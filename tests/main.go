package main

import (
	"io/ioutil"
	"log"
	"time"

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

	serverPublicKey, serverPrivateKey, err := longterm.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	clientPublicKey, clientPrivateKey, err := longterm.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}

	clientMac := [6]byte{0, 1, 2, 3, 4, 5}
	clientConf := server.ClientConfig{clientMac, clientPublicKey}

	incoming := make(chan client.Message, 200)
	outgoing := make(chan client.Message, 200)
	fakeServer, err := server.Start([]server.ClientConfig{clientConf}, dataFolder, longterm.KeyToString(serverPrivateKey), incoming, outgoing)
	if err != nil {
		log.Fatal(err)
	}

	fakeClient, err := clientlib.CreateConfig(clientPrivateKey, clientPublicKey, serverPublicKey)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Got stuff setup")
	log.Printf("Server: %v\n", fakeServer)
	log.Printf("Client: %v\n", fakeClient)

	handshake, msg := fakeClient.HandshakeInit()
	log.Printf("Handshake started from client, msg: %v", msg)
	incoming <- client.Message{Mac: clientMac, Message: msg}
	reply := readOrFail(outgoing, "handshake server reply")
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
	recvMessage := readOrFail(fakeServer.GetInbox(), "decrypted message in Inbox")
	log.Printf("Received encrypted message: %v", recvMessage)
}

func readOrFail(source <-chan client.Message, failMessage string) *client.Message {
	select {
	case result := <-source:
		return &result
	case <-time.After(5 * time.Second):
		log.Fatal("Error reading: " + failMessage)
		return nil
	}
}
