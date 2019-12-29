package server

import (
	"crypto"
	"encoding/base64"
	"fmt"
	"github.com/DavyLandman/sliot/server/client"
	"github.com/DavyLandman/sliot/server/monocypher"
	"io"
	"io/ioutil"
	"log"

	"golang.org/x/crypto/blake2b"
)

type Server struct {
	PublicKey        []byte
	privateKey       []byte
	inbox            chan client.Message
	outbox           chan client.Message
	incomingMessages <-chan client.Message
	stopped          chan bool
	clients          map[uint64]*client.Client
}

type ClientConfig struct {
	Mac         [6]byte
	PublicKey   []byte
	WifiChannel int
}

func Start(clients []ClientConfig, dataPath, privateKeyFile string, incomingMessages <-chan client.Message, outgoingMessages chan<- client.Message) (*Server, error) {
	var result Server
	result.incomingMessages = incomingMessages
	dataKey, err := result.calculateKeys(privateKeyFile)
	if err != nil {
		return nil, err
	}
	result.stopped = make(chan bool)
	result.inbox = make(chan client.Message, 1024)
	result.outbox = make(chan client.Message, 1024)

	err = result.load(clients, dataPath, dataKey, outgoingMessages)
	if err != nil {
		result.Close()
		return nil, err
	}

	go result.forwardIncoming()
	return &result, err
}

func (s *Server) calculateKeys(privateKeyFile string) ([]byte, error) {
	privateKey, err := getPrivateKey(privateKeyFile)
	if err != nil {
		return nil, err
	}
	s.privateKey = privateKey
	s.PublicKey = monocypher.SignPublicKey(privateKey)

	// calculate data key: blake2b-256(privateKey + sign value of a static string) (we hash twice to make any kind of bruteforcing a lot more annoying)
	hasher, err := blake2b.New(client.SessionKeySize, nil)
	if err != nil {
		return nil, err
	}
	hasher.Write(s.privateKey)
	signature, err := s.Sign(nil, []byte("some bytes to sign to make the hass less predictable"), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	hasher.Write(signature)
	return hasher.Sum(nil), nil
}

func getPrivateKey(keyFile string) ([]byte, error) {
	b, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	result := make([]byte, monocypher.PrivateKeySize)
	n, err := base64.StdEncoding.Decode(result, b)
	if err != nil {
		return nil, err
	}
	if n != len(result) {
		return nil, fmt.Errorf("Failed to decode private key, only got %v bytes", n)
	}
	return result, nil
}

func (s *Server) Close() {
	close(s.stopped)
	if s.clients != nil {
		for _, c := range s.clients {
			c.Close()
		}
	}
	close(s.inbox)
	close(s.outbox)
}

func (s *Server) GetInbox() chan<- client.Message {
	return s.inbox
}

func (s *Server) GetOutbox() <-chan client.Message {
	return s.outbox
}

func (s *Server) forwardIncoming() {
	for {
		select {
		case _, open := <-s.stopped:
			if !open {
				return
			}
		case m, open := <-s.outbox:
			if !open {
				return
			}
			c := s.clients[client.MacToId(m.Mac)]
			if c != nil {
				c.NewOutgoingMessage(m)
			} else {
				log.Printf("Dropping message from %v (not in client table)\n", m.Mac)
			}

		case m, open := <-s.incomingMessages:
			if !open {
				close(s.stopped)
				return
			}
			c := s.clients[client.MacToId(m.Mac)]
			if c != nil {
				c.NewIncomingMessage(m)
			} else {
				log.Printf("Dropping message from %v (not in client table)\n", m.Mac)
			}
		}
	}
}

func (s *Server) load(clients []ClientConfig, dataPath string, dataKey []byte, outgoingMessages chan<- client.Message) error {
	s.clients = make(map[uint64]*client.Client)
	for _, c := range clients {
		id := client.MacToId(c.Mac)
		newClient, err := client.NewClient(dataPath, dataKey, c.Mac, c.PublicKey, outgoingMessages, s.inbox, s)
		if err != nil {
			return err
		}
		s.clients[id] = newClient
	}

	return nil
}

func (s *Server) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *Server) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return monocypher.Sign(s.privateKey, msg), nil
}
