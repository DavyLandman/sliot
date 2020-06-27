package data

import "time"

type Message struct {
	Received time.Time
	ClientId interface{}
	Message  []byte
}
