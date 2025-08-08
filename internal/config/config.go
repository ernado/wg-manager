package config

import (
	"net"

	"golang.org/x/crypto/curve25519"
)

type Key [32]byte

func (k Key) PublicKey() Key {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, (*[32]byte)(&k))
	return publicKey
}

type Peer struct {
	AllowedIPs net.IPNet `yaml:"allowedIPs"`
	PrivateKey Key       `yaml:"privateKey"`
}
type Config struct {
	PrivateKey Key    `yaml:"privateKey"`
	Peers      []Peer `yaml:"peers"`
}
