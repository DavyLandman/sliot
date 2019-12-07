package main

import (
	"log"
	"os"
	"time"

	espnow "github.com/DavyLandman/espnow-bridge"
)

func main() {
	br := new(espnow.Bridge)
	defer br.Close()

	if err := br.Connect(os.Args[1]); err != nil {
		log.Fatal(err)
	}

	br.WaitForConnected(10 * time.Second)
	br.AddPeer([6]byte{0x84, 0xf3, 0xeb, 0xe3, 0xef, 0xb1})

	

}
