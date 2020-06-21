package server

import (
	"crypto"
	"crypto/cipher"
	"crypto/ed25519"
	"io"
	"log"

	"github.com/OneOfOne/xxhash"
	"github.com/mitchellh/hashstructure"

	"github.com/DavyLandman/sliot/server/client"
	"github.com/DavyLandman/sliot/server/keys/longterm"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
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
	ClientId  interface{}
	PublicKey []byte
}

func Start(clients []ClientConfig, dataPath, privateKey string, incomingMessages <-chan client.Message, outgoingMessages chan<- client.Message) (*Server, error) {
	var result Server
	result.incomingMessages = incomingMessages
	dataKey, err := result.calculateKeys(privateKey)
	if err != nil {
		return nil, err
	}
	result.stopped = make(chan bool)
	result.inbox = make(chan client.Message, 1024)
	result.outbox = make(chan client.Message, 1024)

	sessionCipher, err := chacha20poly1305.NewX(dataKey)
	if err != nil {
		result.Close()
		return nil, err
	}

	err = result.load(clients, dataPath, sessionCipher, outgoingMessages)
	if err != nil {
		result.Close()
		return nil, err
	}

	go result.forwardIncoming()
	return &result, err
}

func (s *Server) calculateKeys(encodedPrivateKey string) ([]byte, error) {
	privateKey, err := longterm.StringToKey(encodedPrivateKey)
	if err != nil {
		return nil, err
	}
	s.privateKey = privateKey
	s.PublicKey, err = longterm.CalculatePublic(privateKey)
	if err != nil {
		return nil, err
	}

	// calculate data key: blake2b-256(privateKey + sign value of a static string) (we hash twice to make any kind of bruteforcing a lot more annoying)
	hasher, err := blake2b.New(client.SessionKeySize, nil)
	if err != nil {
		return nil, err
	}
	hasher.Write(s.privateKey)
	signature, err := s.Sign(nil, []byte("some bytes to sign to make the hash less predictable"), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	hasher.Write(signature)
	return hasher.Sum(nil), nil
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

func (s *Server) GetInbox() <-chan client.Message {
	return s.inbox
}

func (s *Server) GetOutbox() chan<- client.Message {
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
			c := s.clients[toKey(m.ClientId)]
			if c != nil {
				c.NewOutgoingMessage(m)
			} else {
				log.Printf("Dropping message from %v (not in client table)\n", m.ClientId)
			}

		case m, open := <-s.incomingMessages:
			if !open {
				close(s.stopped)
				return
			}
			c := s.clients[toKey(m.ClientId)]
			if c != nil {
				c.NewIncomingMessage(m)
			} else {
				log.Printf("Dropping message from %v (not in client table)\n", m.ClientId)
			}
		}
	}
}

func (s *Server) load(clients []ClientConfig, sessionPath string, sessionCipher cipher.AEAD, outgoingMessages chan<- client.Message) error {
	s.clients = make(map[uint64]*client.Client)
	for _, c := range clients {
		newClient, err := client.NewClient(sessionPath, sessionCipher, c.ClientId, c.PublicKey, outgoingMessages, s.inbox, s)
		if err != nil {
			return err
		}
		s.clients[toKey(c.ClientId)] = newClient
	}

	return nil
}

func toKey(id interface{}) uint64 {
	result, err := hashstructure.Hash(id, &hashstructure.HashOptions{Hasher: xxhash.New64()})
	if err != nil {
		log.Fatalf("Cannot calculate has for: %v", id)
	}
	return result
}

func (s *Server) Public() crypto.PublicKey {
	return s.PublicKey
}

func (s *Server) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return ed25519.Sign(s.privateKey, msg), nil
}
