package config

import (
	"encoding/base64"
	"fmt"
	"github.com/BurntSushi/toml"
	"io"
	"strconv"
	"strings"
)

type ClientConfig struct {
	Clients []Client `toml:"client"`
}

type Client struct {
	Mac       string
	Name      string
	PublicKey string

	Mappings []Mapping `toml:"mapping"`
}

type Mapping struct {
	Id    int
	Topic string
}

func ReadConfig(source io.Reader) (*ClientConfig, error) {
	var result ClientConfig
	_, err := toml.DecodeReader(source, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func (s *Client) GetByteMac() ([6]byte, error) {
	return ParseMacString(s.Mac)
}

func (s *Client) GetBytePublicKey() ([]byte, error) {
	return base64.StdEncoding.DecodeString(s.PublicKey)
}

func ParseMacString(mac string) ([6]byte, error) {
	var asBytes [6]byte
	chunks := strings.Split(mac, ":")
	if len(chunks) != 6 {
		return asBytes, fmt.Errorf("Incorrect mac: %v", mac)
	}
	for i := 0; i < 6; i++ {
		macChunk, err := strconv.ParseUint(chunks[i], 16, 8)
		if err != nil {
			return asBytes, fmt.Errorf("Error parsing mac: %v (%v)", mac, err)
		}
		asBytes[i] = byte(macChunk)
	}
	return asBytes, nil
}
