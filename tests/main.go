package main

import (
	"bytes"
	"crypto/rand"
	"io/ioutil"
	"log"
	"time"

	"github.com/pkg/profile"

	"github.com/DavyLandman/sliot/server"
	"github.com/DavyLandman/sliot/server/data"
	"github.com/DavyLandman/sliot/server/keys/longterm"
	"github.com/DavyLandman/sliot/test/clientlib"
)

func main() {
	defer profile.Start().Stop()
	dataFolder, err := ioutil.TempDir("", "sliot-test")
	if err != nil {
		log.Fatal(err)
	}

	serverPublic, clientPrivate,
		encodedServerPrivate, encodedClientPublic := genKeys()

	clientMac := [6]byte{0, 1, 2, 3, 4, 5}
	clientConf := server.ClientConfig{ClientId: clientMac, PublicKey: encodedClientPublic}
	clientMac2 := [6]byte{0, 1, 2, 3, 4, 5}
	log.Printf("Starting server:\nkey:\t%v\nclient:\t%v", encodedServerPrivate, clientConf)

	incoming := make(chan data.Message, 200)
	outgoing := make(chan data.Message, 200)
	fakeServer, err := server.Start([]server.ClientConfig{clientConf}, dataFolder, encodedServerPrivate, incoming, outgoing)
	if err != nil {
		log.Fatal("Server start: ", err)
	}

	fakeClient, err := clientlib.CreateConfig(clientPrivate, serverPublic)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Got stuff setup")
	log.Printf("Server: \n%v\n", fakeServer)
	log.Printf("Client: \n%v\n", fakeClient)

	handshake, msg := fakeClient.HandshakeInit()
	log.Printf("Handshake started from client, msg: %v", msg)
	incoming <- data.Message{ClientId: clientMac2, Message: msg}
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
	incoming <- data.Message{ClientId: clientMac2, Message: msg}
	recvMessage := readOrFail(fakeServer.GetInbox(), "decrypted message in Inbox")
	log.Printf("Received encrypted message: %v", recvMessage)
	if bytes.Compare(clientMac[:], recvMessage.Message) != 0 {
		log.Fatal("Got: %v expected: %v", clientMac[:], recvMessage.Message)
	}

	// sending it a second time should fail
	incoming <- data.Message{ClientId: clientMac2, Message: msg}
	select {
	case received := <-fakeServer.GetInbox():
		log.Fatalf("Got message that should have been dropped due to replay attack: %v", received)
	case <-time.After(100 * time.Millisecond):
		log.Println("Replay attack prevented")
	}

	msg = session.Encrypt(clientMac[:4])
	if msg == nil {
		log.Fatalf("Error in encrypting second message")
	} else {
		log.Printf("Prepared encrypted second message: %v", msg)
	}
	incoming <- data.Message{ClientId: clientMac2, Message: msg}
	recvMessage = readOrFail(fakeServer.GetInbox(), "decrypted message in Inbox")
	log.Printf("Received second encrypted message: %v", recvMessage)

	if bytes.Compare(clientMac[:4], recvMessage.Message) != 0 {
		log.Fatal("Got: %v expected: %v", clientMac[:4], recvMessage.Message)
	}

	log.Println("Running small benchmark")
	buffer := make([]byte, 2048)
	rand.Read(buffer)
	for j := 0; j < 20; j++ {
		for i := 1; i < len(buffer); i++ {
			msg = session.Encrypt(buffer[:i])
			incoming <- data.Message{ClientId: clientMac2, Message: msg}
			select {
			case handled := <-fakeServer.GetInbox():
				if bytes.Compare(buffer[:i], handled.Message) != 0 {
					log.Fatalf("Failure to receive %v bytes", i)
				}
			case <-time.After(1000 * time.Millisecond):
				log.Fatalf("Message never received: %v at size: %v", msg[:16], i)
			}
		}
	}
	log.Println("Succeeded")

}

func genKeys() (sPublic, cPrivate []byte, esPrivate, ecPublic string) {
	sPublic, sPrivate, err := longterm.GenerateKeyPair()
	if err != nil {
		log.Fatal("Key generation: ", err)
	}
	cPublic, cPrivate, err := longterm.GenerateKeyPair()
	if err != nil {
		log.Fatal("Key generation: ", err)
	}
	esPrivate, err = longterm.KeyToString(sPrivate)
	if err != nil {
		log.Fatal("Key encoding: ", err)
	}
	ecPublic, err = longterm.KeyToString(cPublic)
	if err != nil {
		log.Fatal("Key encoding: ", err)
	}
	return
}

func readOrFail(source <-chan data.Message, failMessage string) *data.Message {
	select {
	case result := <-source:
		return &result
	case <-time.After(5 * time.Second):
		log.Fatalf("Error reading: %s", failMessage)
		return nil
	}
}
