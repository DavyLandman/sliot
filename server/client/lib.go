package client

import (
	"bytes"
	"crypto"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	espnow "github.com/DavyLandman/espnow-bridge"
)

type Client struct {
	Mac         [6]byte
	PublicKey   []byte
	WifiChannel int
	sessionFile string
	dataKey     []byte
	encrypted   EncryptedClient
	outbox      chan<- espnow.Message
	dataOutbox  chan<- Message
	signer      crypto.Signer
	saveSession chan bool
}

type Message struct {
	Received time.Time
	Mac      [6]byte
	Message  []byte
}

func NewClient(dataPath string, dataKey []byte, mac [6]byte, publicKey []byte, wifiChannel int, outbox chan<- espnow.Message, dataOutbox chan<- Message, signer crypto.Signer) (*Client, error) {
	var result Client
	result.dataKey = dataKey
	copy(result.Mac[:], mac[:])
	copy(result.PublicKey, publicKey)
	result.WifiChannel = wifiChannel
	result.signer = signer
	result.outbox = outbox
	result.dataOutbox = dataOutbox
	result.saveSession = make(chan bool, 10)

	result.sessionFile = fileName(dataPath, mac)
	result.encrypted.Initialize(mac, publicKey)
	if info, err := os.Stat(result.sessionFile); err == nil && !info.IsDir() {
		data, err := os.Open(result.sessionFile)
		if err != nil {
			return nil, err
		}
		defer data.Close()
		result.encrypted.RestoreSession(data, dataKey)
	}

	go result.periodicSessionBackup()

	return &result, nil
}

func (c *Client) Close() {
	close(c.saveSession)
}

func (c *Client) HandleMessage(when time.Time, data []byte) {
	if len(data) < 2 {
		log.Printf("To short of a message received %v\n", data)
		return
	}
	switch data[0] {
	case 1:
		c.handleKeyExchange(data[1:])
	case 2:
		c.handleNormalMessage(when, data[1:])
	default:
		log.Printf("Strange message received %02x\n", data[0])
	}
}

func (c *Client) handleKeyExchange(data []byte) {
	if len(data) != 64+32 {
		log.Printf("DH: not right sized message recevied %v\n", data)
		return
	}
	theirSignature := data[:64]
	theirPublicKey := data[64:]
	replyPublic := c.encrypted.KeyExchangeReply(theirPublicKey, theirSignature, c.signer.Public().([]byte))
	if replyPublic != nil {
		replySignature, err := c.signer.Sign(nil, replyPublic, crypto.Hash(0))
		if err != nil {
			log.Fatalf("Did not expect signing to fail: %v", err)
		}
		var response bytes.Buffer
		response.WriteByte(0x01)
		response.Write(replySignature)
		response.Write(replyPublic)
		c.outbox <- espnow.Message{
			Mac:  c.encrypted.Mac,
			Data: response.Bytes(),
		}
		c.saveSession <- true
	}
}

func (c *Client) handleNormalMessage(when time.Time, data []byte) {
	reader := bytes.NewBuffer(data)
	counter := reader.Next(2)
	msgSize, _ := reader.ReadByte()
	nonce := reader.Next(24)
	mac := reader.Next(16)
	cipherText := reader.Next(int(uint8(msgSize)))
	if len(cipherText) != int(uint8(msgSize)) {
		log.Printf("Incorrect message received, expected %v but got only %v", uint8(msgSize), len(cipherText))
		return
	}
	plainMessage := c.encrypted.DecryptMessage(cipherText, counter, nonce, mac)
	if plainMessage != nil {
		c.dataOutbox <- Message{
			Received: when,
			Mac:      c.Mac,
			Message:  plainMessage,
		}
	}

}

func (c *Client) GetId() uint64 {
	return MacToId(c.encrypted.Mac)
}

func (c *Client) periodicSessionBackup() {
	for {
		select {
		case _, open := <-c.saveSession:
			if !open {
				return
			}
		case <-time.After(1 * time.Hour):
		}
		data, err := os.Create(c.sessionFile)
		if err == nil {
			err = c.encrypted.SaveSession(data, c.dataKey)
			data.Close()
			if err != nil {
				log.Printf("Error saving session: %v\n", data)
			}
		}
	}

}

func fileName(root string, mac [6]byte) string {
	return path.Join(root,
		fmt.Sprintf("%02x%02x%02x%02x%02x%02x.session",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]))
}

func MacToId(mac [6]byte) uint64 {
	return uint64(mac[0]) |
		uint64(mac[1])<<8 |
		uint64(mac[2])<<16 |
		uint64(mac[3])<<24 |
		uint64(mac[4])<<32 |
		uint64(mac[5])<<40
}
