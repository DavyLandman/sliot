package server

import (
	"crypto"
	"crypto/cipher"
	"crypto/ed25519"
	"hash"
	"hash/fnv"
	"io"
	"log"

	"github.com/OneOfOne/xxhash"
	"github.com/mitchellh/hashstructure"

	"github.com/DavyLandman/sliot/server/data"
	"github.com/DavyLandman/sliot/server/internal/client"
	"github.com/DavyLandman/sliot/server/keys/longterm"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/chacha20poly1305"
)

type Server struct {
	PublicKey        []byte
	privateKey       []byte
	inbox            chan data.Message
	outbox           chan data.Message
	incomingMessages <-chan data.Message
	stopped          chan bool
	clients          map[uint64]map[uint64]*client.Client
}

type ClientConfig struct {
	ClientId  interface{}
	PublicKey string
}

func Start(clients []ClientConfig, dataPath, privateKey string, incomingMessages <-chan data.Message, outgoingMessages chan<- data.Message) (*Server, error) {
	var result Server
	result.incomingMessages = incomingMessages
	dataKey, err := result.calculateKeys(privateKey)
	if err != nil {
		return nil, err
	}
	result.stopped = make(chan bool)
	result.inbox = make(chan data.Message, 1024)
	result.outbox = make(chan data.Message, 1024)

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
		for _, cmap := range s.clients {
			for _, c := range cmap {
				c.Close()
			}
		}
	}
	close(s.inbox)
	close(s.outbox)
}

func (s *Server) GetInbox() <-chan data.Message {
	return s.inbox
}

func (s *Server) GetOutbox() chan<- data.Message {
	return s.outbox
}

func (s *Server) lookupClient(id interface{}) *client.Client {
	cmap := s.clients[level1Key(id)]
	if cmap != nil {
		if len(cmap) <= 4 {
			// for small maps, we just iterate through them instead of second key lookup
			for _, can := range cmap {
				if can.ClientId == id {
					return can
				}
			}
		} else {
			return cmap[level2Key(id)]
		}
	}
	return nil
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
			c := s.lookupClient(m.ClientId)
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
			c := s.lookupClient(m.ClientId)
			if c != nil {
				c.NewIncomingMessage(m)
			} else {
				log.Printf("Dropping message from %v (not in client table)\n", m.ClientId)
			}
		}
	}
}

func (s *Server) load(clients []ClientConfig, sessionPath string, sessionCipher cipher.AEAD, outgoingMessages chan<- data.Message) error {
	s.clients = make(map[uint64]map[uint64]*client.Client)
	for _, c := range clients {
		decodedKey, err := longterm.StringToKey(c.PublicKey)
		if err != nil {
			return err
		}
		newClient, err := client.NewClient(sessionPath, sessionCipher, c.ClientId, decodedKey, outgoingMessages, s.inbox, s)
		if err != nil {
			return err
		}
		key1 := level1Key(c.ClientId)
		key2 := level2Key(c.ClientId)
		nestedMap := s.clients[key1]
		if nestedMap == nil {
			nestedMap = make(map[uint64]*client.Client)
			s.clients[key1] = nestedMap
		}
		if nestedMap[key2] != nil {
			log.Fatal("Hash collision at second level hash, should not be possible, maybe you can enrich the identifier with some better data?")
		}
		nestedMap[key2] = newClient
	}

	return nil
}

func level1Key(id interface{}) uint64 {
	return calcHash(id, xxhash.New64())
}

func level2Key(id interface{}) uint64 {
	return calcHash(id, fnv.New64a())
}

func calcHash(id interface{}, hasher hash.Hash64) uint64 {
	result, err := hashstructure.Hash(id, &hashstructure.HashOptions{Hasher: hasher})
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
