package client

import (
	"bytes"
	"encoding/binary"
	"fmt"
	espnow "github.com/DavyLandman/espnow-bridge"
	"log"
	"os"
	"path"
	"siot-server/config"
	"siot-server/server"
	"time"
)

type Client struct {
	sessionFile string
	dataKey     []byte
	encrypted   EncryptedClient
	config      *config.Client
	outbox      chan<- espnow.Message
	dataOutbox  chan<- ReceivedData
	server      *server.Server
	saveSession chan bool
}

type ReceivedData struct {
	ID     int
	Value  interface{}
	Client *config.Client
}

func NewClient(dataPath string, dataKey []byte, base *config.Client, outbox chan<- espnow.Message, dataOutbox chan<- ReceivedData, server *server.Server) (*Client, error) {
	var result Client
	result.dataKey = dataKey
	result.config = base
	result.server = server
	result.outbox = outbox
	result.dataOutbox = dataOutbox
	result.saveSession = make(chan bool, 10)

	mac, err := base.GetByteMac()
	if err != nil {
		return nil, err
	}
	result.sessionFile = fileName(dataPath, mac)
	publicKey, err := base.GetBytePublicKey()
	if err != nil {
		return nil, err
	}
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

func (c *Client) HandleMessage(data []byte) {
	if len(data) < 2 {
		log.Printf("To short of a message received %v\n", data)
		return
	}
	switch data[0] {
	case 1:
		c.handleKeyExchange(data[1:])
	case 2:
		c.handleNormalMessage(data[1:])
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
	replyPublic, replySignature := c.encrypted.KeyExchangeReply(theirPublicKey, theirSignature, c.server)
	if replyPublic != nil && replySignature != nil {
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

func (c *Client) handleNormalMessage(data []byte) {
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
		contents := bytes.NewReader(plainMessage)
		for contents.Len() > 0 {
			taggedID, _ := contents.ReadByte()
			tag := int(taggedID & 0x0F)
			id := int(taggedID >> 4)
			switch tag {
			case 1: // int32
				var value int32
				binary.Read(contents, binary.LittleEndian, &value)
				c.dataOutbox <- ReceivedData{
					ID:     id,
					Value:  value,
					Client: c.config,
				}
			case 2: // float32
				var value float32
				binary.Read(contents, binary.LittleEndian, &value)
				c.dataOutbox <- ReceivedData{
					ID:     id,
					Value:  value,
					Client: c.config,
				}
			default:
				log.Fatalf("Received message with unknown tag, wrong version of client library?: %02x (full: %v)", tag, plainMessage)
			}
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
