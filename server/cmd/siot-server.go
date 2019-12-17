package main

import (
	"crypto/rand"
	"log"
	"os"
	"siot-server/peer"
	"siot-server/server"
	"time"

	espnow "github.com/DavyLandman/espnow-bridge"
)

func main() {
	br := new(espnow.Bridge)
	defer br.Close()

	peers := make([]peer.Peer, 10)

	mainServer := new(server.Server)
	peerKey := make([]byte, 64)
	rand.Read(peerKey)
	peers[0].Initialize([6]byte{0x84, 0xf3, 0xeb, 0xe3, 0xef, 0xb1}, peerKey)
	log.Println(peers[0].KeyExchangeReply(peerKey, peerKey, mainServer))

	if err := br.Connect(os.Args[1]); err != nil {
		log.Fatal(err)
	}

	br.WaitForConnected(10 * time.Second)
	br.AddPeer([6]byte{0x84, 0xf3, 0xeb, 0xe3, 0xef, 0xb1}, 1)

}
