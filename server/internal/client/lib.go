package client

import (
	"bytes"
	"crypto"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path"
	"time"

	"github.com/DavyLandman/sliot/server/data"
)

type Client struct {
	ClientId          interface{}
	sessionFile       string
	sessionCipher     cipher.AEAD
	encrypted         EncryptedClient
	outgoingMessages  chan<- data.Message
	incomingMessages  chan data.Message
	decryptedMessages chan<- data.Message
	messagesToEncrypt chan data.Message
	signer            crypto.Signer
	saveSession       chan bool
}

func NewClient(sessionPath string, sessionCipher cipher.AEAD, clientId interface{}, publicKey []byte,
	outgoingMessages chan<- data.Message, decryptedMessages chan<- data.Message, signer crypto.Signer) (*Client, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Client public key of invalid size: %v", len(publicKey))
	}
	var result Client
	result.ClientId = clientId
	result.signer = signer
	result.incomingMessages = make(chan data.Message, 1024)
	result.messagesToEncrypt = make(chan data.Message, 1024)
	result.outgoingMessages = outgoingMessages
	result.decryptedMessages = decryptedMessages
	result.encrypted.Initialize(publicKey)

	result.saveSession = make(chan bool, 10)
	result.sessionCipher = sessionCipher
	result.sessionFile = fileName(sessionPath, publicKey)

	if info, err := os.Stat(result.sessionFile); err == nil && !info.IsDir() {
		data, err := os.Open(result.sessionFile)
		if err != nil {
			return nil, err
		}
		defer data.Close()
		result.encrypted.RestoreSession(data, sessionCipher)
	}

	go result.periodicSessionBackup()
	go result.handleMessages()

	return &result, nil
}

func (c *Client) Close() {
	close(c.saveSession)
}

func (c *Client) NewIncomingMessage(msg data.Message) {
	c.incomingMessages <- msg
}

func (c *Client) NewOutgoingMessage(msg data.Message) {
	c.messagesToEncrypt <- msg
}

func (c *Client) handleMessages() {
	for {
		select {
		case m, active := <-c.incomingMessages:
			if !active {
				return
			}
			if m.ClientId != c.ClientId {
				log.Fatalf("Received message not intended for me: %v", m)
			}
			if len(m.Message) < 1 {
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
			if m.ClientId != c.ClientId {
				log.Fatalf("Received message not intended for me: %v", m)
			}
			newMessage := new(bytes.Buffer)
			newMessage.WriteByte(0x02)
			binary.Write(newMessage, binary.LittleEndian, uint16(len(m.Message)))

			ciphertext, counter, nonce := c.encrypted.EncryptMessage(m.Message)
			newMessage.Write(counter)
			newMessage.Write(nonce)
			newMessage.Write(ciphertext)
			c.outgoingMessages <- data.Message{
				ClientId: m.ClientId,
				Message:  newMessage.Bytes(),
				Received: m.Received,
			}
		}
	}
}

func (c *Client) handleKeyExchange(incoming []byte) {
	if len(incoming) != 64+32 {
		log.Printf("DH: not right sized message recevied %v\n", incoming)
		return
	}
	theirPublicKey := incoming[:32]
	theirSignature := incoming[32:]
	replyPublic := c.encrypted.KeyExchangeReply(theirPublicKey, theirSignature, c.signer.Public().([]byte))
	if replyPublic != nil {
		replySignature, err := c.signer.Sign(nil, replyPublic, crypto.Hash(0))
		if err != nil {
			log.Fatalf("Did not expect signing to fail: %v", err)
		}
		var response bytes.Buffer
		response.WriteByte(0x01)
		response.Write(replyPublic)
		response.Write(replySignature)
		c.outgoingMessages <- data.Message{
			ClientId: c.ClientId,
			Message:  response.Bytes(),
		}
		c.saveSession <- true
	} else {
		log.Printf("Invalid key exchange init")
		log.Printf("Received public key: %v", hex.EncodeToString(theirPublicKey))
		log.Printf("Received signature: %v", hex.EncodeToString(theirSignature))
	}
}

func (c *Client) handleNormalMessage(when time.Time, incoming []byte) {
	reader := bytes.NewBuffer(incoming)
	var msgSize uint16
	binary.Read(reader, binary.LittleEndian, &msgSize)
	counter := reader.Next(2)
	nonce := reader.Next(12)
	cipherText := reader.Next(int(msgSize) + EncryptionOverhead)
	if len(cipherText) != (int(msgSize) + EncryptionOverhead) {
		log.Printf("Incorrect message received, expected %v but got only %v", int(msgSize)+EncryptionOverhead, len(cipherText))
		return
	}
	plainMessage := c.encrypted.DecryptMessage(cipherText, counter, nonce)
	if plainMessage != nil {
		c.decryptedMessages <- data.Message{
			Received: when,
			ClientId: c.ClientId,
			Message:  plainMessage,
		}
	} else {
		log.Printf("Couldn't decrypt message for %v", c.ClientId)
	}

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
			err = c.encrypted.SaveSession(data, c.sessionCipher)
			data.Close()
			if err != nil {
				log.Printf("Error saving session: %v\n", data)
			}
		}
	}

}

func fileName(root string, publicKey []byte) string {
	return path.Join(root, base64.RawURLEncoding.EncodeToString(publicKey))
}
