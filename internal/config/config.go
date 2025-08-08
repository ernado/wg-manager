package config

import (
	_ "embed"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

//go:embed _templates/wg0.conf.tmpl
var Template string

type Peer struct {
	AllowedIPs net.IPNet   `yaml:"allowedIPs"`
	PrivateKey wgtypes.Key `yaml:"privateKey"`
}

func (p Peer) PublicKey() wgtypes.Key {
	return p.PrivateKey.PublicKey()
}

type Config struct {
	PrivateKey wgtypes.Key `yaml:"privateKey"`
	Peers      []Peer      `yaml:"peers"`
}
