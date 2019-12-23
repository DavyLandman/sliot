package server

import (
	"crypto"
	"io"
	"log"
	"siot-server/client"
	"siot-server/monocypher"

	espnow "github.com/DavyLandman/espnow-bridge"
)

type Server struct {
	PublicKey  []byte
	privateKey []byte
	inbox      chan client.Message
	stopped    chan bool
	bridge     *espnow.Bridge
	clients    map[uint64]*client.Client
}

type ClientConfig struct {
	Mac         [6]byte
	PublicKey   []byte
	WifiChannel int
}

func Start(clients []ClientConfig, dataPath string, dataKey, privateKey, publicKey []byte, bridge *espnow.Bridge) (*Server, error) {
	var result Server
	result.bridge = bridge
	copy(result.PublicKey, publicKey)
	copy(result.privateKey, privateKey)
	result.stopped = make(chan bool)
	result.inbox = make(chan client.Message, 1024)

	err := result.load(clients, dataPath, dataKey)
	if err != nil {
		result.Close()
		return nil, err
	}

	go result.forwardIncoming()
	return &result, err
}

func (s *Server) Close() {
	close(s.stopped)
	s.bridge.Close()
	if s.clients != nil {
		for _, c := range s.clients {
			c.Close()
		}
	}
	close(s.inbox)
}

func (s *Server) GetInbox() chan<- client.Message {
	return s.inbox
}

func (s *Server) forwardIncoming() {
	for {
		select {
		case _, open := <-s.stopped:
			if !open {
				return
			}
		case m, open := <-s.bridge.Inbox:
			if !open {
				close(s.stopped)
				return
			}
			c := s.clients[client.MacToId(m.Mac)]
			if c != nil {
				c.HandleMessage(m.Data)
			} else {
				log.Printf("Dropping message from %v (not in client table)\n", m.Mac)
			}
		}
	}
}

func (s *Server) load(clients []ClientConfig, dataPath string, dataKey []byte) error {
	s.clients = make(map[uint64]*client.Client)
	for _, c := range clients {
		id := client.MacToId(c.Mac)
		newClient, err := client.NewClient(dataPath, dataKey, c.Mac, c.PublicKey, c.WifiChannel, s.bridge.Outbox, s.inbox, s)
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
