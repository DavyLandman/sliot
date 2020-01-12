package client

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/DavyLandman/sliot/server/monocypher"
)

type Client struct {
	Mac               [6]byte
	PublicKey         []byte
	sessionFile       string
	dataKey           []byte
	encrypted         EncryptedClient
	outgoingMessages  chan<- Message
	incomingMessages  chan Message
	decryptedMessages chan<- Message
	messagesToEncrypt chan Message
	signer            crypto.Signer
	saveSession       chan bool
}

type Message struct {
	Received time.Time
	Mac      [6]byte
	Message  []byte
}

func NewClient(dataPath string, dataKey []byte, mac [6]byte, publicKey []byte,
	outgoingMessages chan<- Message, decryptedMessages chan<- Message, signer crypto.Signer) (*Client, error) {
	if len(dataKey) != SessionKeySize {
		return nil, fmt.Errorf("Data key of invalid size: %v", len(dataKey))
	}
	if len(publicKey) != monocypher.PublicKeySize {
		return nil, fmt.Errorf("Client public key of invalid size: %v", len(publicKey))
	}
	var result Client
	result.dataKey = dataKey
	copy(result.Mac[:], mac[:])
	result.PublicKey = append([]byte(nil), publicKey...)
	result.signer = signer
	result.incomingMessages = make(chan Message, 1024)
	result.messagesToEncrypt = make(chan Message, 1024)
	result.outgoingMessages = outgoingMessages
	result.decryptedMessages = decryptedMessages
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
	go result.handleMessages()

	return &result, nil
}

func (c *Client) Close() {
	close(c.saveSession)
}

func (c *Client) NewIncomingMessage(msg Message) {
	c.incomingMessages <- msg
}

func (c *Client) NewOutgoingMessage(msg Message) {
	c.messagesToEncrypt <- msg
}

func (c *Client) handleMessages() {
	for {
		select {
		case m, active := <-c.incomingMessages:
			if !active {
				return
			}
			if m.Mac != c.Mac {
				log.Fatalf("Received message not intended for me: %v", m)
			}
			if len(m.Message) < 2 {
				log.Printf("To short of a message received %v\n", m)
				return
			}

			switch m.Message[0] {
			case 1:
				c.handleKeyExchange(m.Message[1:])
			case 2:
				c.handleNormalMessage(m.Received, m.Message[1:])
			default:
				log.Printf("Strange message received %02x\n", m.Message[0])
			}
		case m, active := <-c.messagesToEncrypt:
			if !active {
				return
			}
			if m.Mac != c.Mac {
				log.Fatalf("Received message not intended for me: %v", m)
			}
			newMessage := new(bytes.Buffer)
			newMessage.WriteByte(0x02)
			binary.Write(newMessage, binary.LittleEndian, uint16(len(m.Message)))

			ciphertext, counter, nonce, mac := c.encrypted.EncryptMessage(m.Message)
			newMessage.Write(counter)
			newMessage.Write(nonce)
			newMessage.Write(mac)
			newMessage.Write(ciphertext)
			c.outgoingMessages <- Message{
				Mac:     c.Mac,
				Message: newMessage.Bytes(),
			}
		}
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
		c.outgoingMessages <- Message{
			Mac:     c.Mac,
			Message: response.Bytes(),
		}
		c.saveSession <- true
	} else {
		log.Printf("Invalid key exchange init")
		log.Printf("Received public key: %v", hex.EncodeToString(theirPublicKey))
		log.Printf("Received signature: %v", hex.EncodeToString(theirSignature))
	}
}

func (c *Client) handleNormalMessage(when time.Time, data []byte) {
	reader := bytes.NewBuffer(data)
	var msgSize uint16
	binary.Read(reader, binary.LittleEndian, &msgSize)
	counter := reader.Next(2)
	nonce := reader.Next(24)
	mac := reader.Next(16)
	cipherText := reader.Next(int(uint8(msgSize)))
	if len(cipherText) != int(uint8(msgSize)) {
		log.Printf("Incorrect message received, expected %v but got only %v", uint8(msgSize), len(cipherText))
		return
	}
	plainMessage := c.encrypted.DecryptMessage(cipherText, counter, nonce, mac)
	if plainMessage != nil {
		c.decryptedMessages <- Message{
			Received: when,
			Mac:      c.Mac,
			Message:  plainMessage,
		}
	} else {
		log.Printf("Couldn't decrypt message for %v", c.Mac)
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
