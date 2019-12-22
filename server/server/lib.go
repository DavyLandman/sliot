package server

import (
	"log"
	"os"
	"siot-server/client"
	"siot-server/config"

	espnow "github.com/DavyLandman/espnow-bridge"
	"siot-server/monocypher"
)

type Server struct {
	PublicKey  []byte
	privateKey []byte
	config     *config.ClientConfig
	stopped    chan bool
	bridge     *espnow.Bridge
	newData    chan client.ReceivedData
	clients    map[uint64]*client.Client
}

func Start(configFile, dataPath string, dataKey, privateKey, publicKey []byte, bridge *espnow.Bridge) (*Server, error) {
	var result Server
	result.bridge = bridge
	copy(result.PublicKey, publicKey)
	copy(result.privateKey, privateKey)
	result.stopped = make(chan bool)
	result.newData = make(chan client.ReceivedData, 1024)

	err := result.load(configFile, dataPath, dataKey)
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

func (s *Server) load(configFile, dataPath string, dataKey []byte) error {
	file, err := os.Open(configFile)
	if err != nil {
		return err
	}
	defer file.Close()
	newConfig, err := config.ReadConfig(file)
	if err != nil {
		return err
	}
	s.config = newConfig
	s.clients = make(map[uint64]*client.Client)
	for _, c := range newConfig.Clients {
		mac, err := c.GetByteMac()
		if err != nil {
			return err
		}
		id := client.MacToId(mac)
		newClient, err := client.NewClient(dataPath, dataKey, &c, s.bridge.Outbox, s.newData, s)
		if err != nil {
			return err
		}
		s.clients[id] = newClient
	}

	return nil
}

func (s *Server) Sign(msg []byte) []byte {
	return monocypher.Sign(s.privateKey, msg)
}
