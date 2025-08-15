package main

import (
	"net"

	"github.com/go-faster/errors"
	"github.com/spf13/cobra"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

type Key [wgtypes.KeyLen]byte

func (k Key) Public() wgtypes.Key {
	return wgtypes.Key(k).PublicKey()
}

func (k Key) MarshalYAML() (interface{}, error) {
	return wgtypes.Key(k).String(), nil
}

func (k *Key) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return errors.Wrap(err, "decode key")
	}
	key, err := wgtypes.ParseKey(str)
	if err != nil {
		return errors.Wrap(err, "parse key")
	}
	copy(k[:], key[:])
	return nil
}

type IPNet net.IPNet

func (n IPNet) MarshalYAML() (interface{}, error) {
	ipNet := net.IPNet(n)
	if ipNet.IP == nil || ipNet.Mask == nil {
		return nil, nil
	}

	return ipNet.String(), nil
}

func (n *IPNet) UnmarshalYAML(value *yaml.Node) error {
	var str string
	if err := value.Decode(&str); err != nil {
		return errors.Wrap(err, "decode IPNet")
	}
	ip, ipNet, err := net.ParseCIDR(str)
	if err != nil {
		return errors.Wrap(err, "parse CIDR")
	}
	n.IP = ip
	n.Mask = ipNet.Mask

	return nil
}

type Peer struct {
	PrivateKey Key   `yaml:"privateKey"`
	Address    IPNet `yaml:"address"`
}

type Config struct {
	PrivateKey   Key    `yaml:"privateKey"`
	Port         int    `yaml:"port"`
	Address      IPNet  `yaml:"address"`
	NATInterface string `yaml:"natInterface,omitempty"`
	Peers        []Peer `yaml:"peers,omitempty"`
}

func ConfigCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Print sample configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			privateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return errors.Wrap(err, "generate private key")
			}

			peerPrivateKey, err := wgtypes.GeneratePrivateKey()
			if err != nil {
				return errors.Wrap(err, "generate peer private key")
			}

			peer := Peer{
				PrivateKey: Key(peerPrivateKey),
				Address: IPNet{
					IP:   net.IPv4(10, 5, 5, 2),
					Mask: net.CIDRMask(32, 32),
				},
			}

			cfg := Config{
				PrivateKey: Key(privateKey),
				Port:       51820,
				Address: IPNet{
					IP:   net.IPv4(10, 5, 5, 1),
					Mask: net.CIDRMask(24, 32),
				},
				NATInterface: "eth0",
				Peers:        []Peer{peer},
			}

			e := yaml.NewEncoder(cmd.OutOrStdout())
			e.SetIndent(2)
			if err := e.Encode(cfg); err != nil {
				return errors.Wrap(err, "encode config")
			}

			return nil
		},
	}

	return cmd
}
