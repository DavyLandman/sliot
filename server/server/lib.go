package server

import (
	"siot-server/monocypher"
)

type Server struct {
	PublicKey  []byte
	privateKey []byte
}

func (s *Server) Sign(msg []byte) []byte {
	return monocypher.Sign(s.privateKey, msg)
}
