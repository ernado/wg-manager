package main

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/go-faster/errors"
	"github.com/spf13/cobra"
	"gitlab.com/mergetb/tech/rtnl"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/yaml.v3"
)

type Application struct {
	log *slog.Logger
}

func (a *Application) command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	a.log.Info("[#] " + name + " " + strings.Join(args, " "))
	return cmd.Run()
}

func (a *Application) iptables(ctx context.Context, args ...string) error {
	return a.command(ctx, "iptables", args...)
}

func (a *Application) sysctl(ctx context.Context, args ...string) error {
	return a.command(ctx, "sysctl", args...)
}

func (a *Application) deconfigureRouting(ctx context.Context, wgInterface, natInterface string) error {
	/* iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE */
	if err := a.iptables(ctx, "-D", "FORWARD", "-i", wgInterface, "-j", "ACCEPT"); err != nil {
		return errors.Wrap(err, "deconfigure iptables FORWARD")
	}
	if err := a.iptables(ctx, "-t", "nat", "-D", "POSTROUTING", "-o", natInterface, "-j", "MASQUERADE"); err != nil {
		return errors.Wrap(err, "deconfigure iptables POSTROUTING")
	}

	return nil
}

func (a *Application) configureRouting(ctx context.Context, wgInterface, natInterface string) error {
	/*
		iptables -A FORWARD -i wg0 -j ACCEPT
		iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
		sysctl -q -w net.ipv4.ip_forward=1
	*/

	if err := a.iptables(ctx, "-A", "FORWARD", "-i", wgInterface, "-j", "ACCEPT"); err != nil {
		return errors.Wrap(err, "configure iptables FORWARD")
	}
	if err := a.iptables(ctx, "-t", "nat", "-A", "POSTROUTING", "-o", natInterface, "-j", "MASQUERADE"); err != nil {
		return errors.Wrap(err, "configure iptables POSTROUTING")
	}
	if err := a.sysctl(ctx, "-q", "-w", "net.ipv4.ip_forward=1"); err != nil {
		return errors.Wrap(err, "configure sysctl net.ipv4.ip_forward")
	}

	return nil
}

// detectExternalInterface tries to detect the default external network interface and its IPv4 address (Linux only, no awk).
func detectExternalInterface() (iface, ip string, err error) {
	cmd := exec.Command("ip", "route", "show")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", "", err
	}
	if err := cmd.Start(); err != nil {
		return "", "", err
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		// Looking for: default via 192.168.1.1 dev eth0 ...
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "default" {
			for i := 0; i < len(fields)-1; i++ {
				if fields[i] == "dev" {
					iface = fields[i+1]
					break
				}
			}
			if iface != "" {
				break
			}
		}
	}
	err = cmd.Wait()
	if err != nil {
		return "", "", err
	}
	if iface == "" {
		return "", "", errors.New("could not detect default external interface")
	}

	// Now detect the external IP for the interface.
	cmd = exec.Command("ip", "addr", "show", iface)
	stdout, err = cmd.StdoutPipe()
	if err != nil {
		return iface, "", err
	}
	if err := cmd.Start(); err != nil {
		return iface, "", err
	}
	scanner = bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Look for: inet 192.168.1.100/24 ...
		if strings.HasPrefix(line, "inet ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				ip = strings.Split(fields[1], "/")[0]
				break
			}
		}
	}
	err = cmd.Wait()
	if err != nil {
		return iface, "", err
	}
	if ip == "" {
		return iface, "", errors.New("could not detect external IP address")
	}
	return iface, ip, nil
}

func Root() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "wg-manager",
		Short:         "WireGuard manager.",
		Long:          "Manager for WireGuard peers.",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			lg := slog.New(
				slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
					// Drop time key because journald already provides it.
					ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
						if a.Key == slog.TimeKey && len(groups) == 0 {
							return slog.Attr{}
						}
						return a
					},
				}),
			)

			lg.Info("wg-manager started")

			app := &Application{
				log: lg,
			}

			client, err := wgctrl.New()
			if err != nil {
				return errors.Wrap(err, "create client")
			}
			defer func() {
				if err := client.Close(); err != nil {
					slog.Warn("close client", "err", err)
				}
			}()

			// Create WireGuard device.
			rx, err := rtnl.OpenDefaultContext()
			if err != nil {
				return errors.Wrap(err, "open rtnl context")
			}
			defer func() {
				if err := rx.Close(); err != nil {
					lg.Warn("close rtnl context", "err", err)
				}
			}()

			link := rtnl.NewLink()
			link.ApplyType("wireguard")
			link.Info.Name = "wgm0"
			link.Info.Mtu = 1420

			if err := link.Add(rx); err != nil {
				if errors.Is(err, os.ErrExist) {
					lg.Info("wg-manager link already exists")
				} else {
					return errors.Wrap(err, "add wireguard link")
				}
			}

			if err := link.Up(rx); err != nil {
				return errors.Wrap(err, "set link up")
			}

			var hasAddr bool
			{
				addrs, err := link.Addrs(rx)
				if err != nil {
					return errors.Wrap(err, "get link addresses")
				}
				for range addrs {
					hasAddr = true
				}
			}
			if !hasAddr {
				addr := rtnl.NewAddress()
				addr.Info.Address = &net.IPNet{
					IP:   net.IPv4(10, 5, 5, 1),
					Mask: net.CIDRMask(24, 32),
				}
				if err := link.AddAddr(rx, addr); err != nil {
					return errors.Wrap(err, "add address to link")
				}
			} else {
				lg.Info("wg-manager link already has address")
			}

			var config Config
			{
				configData, err := os.ReadFile(configPath)
				if err != nil {
					if os.IsNotExist(err) {
						lg.Info("Generating default configuration", "path", configPath)

						key, err := wgtypes.GeneratePrivateKey()
						if err != nil {
							return errors.Wrap(err, "generate private key")
						}

						config.PrivateKey = Key(key)
						config.Port = 51820

						lg.Info("Generated new key", "public_key", config.PrivateKey.Public())

						// Detect default external interface and IP if not set
						if config.NATInterface == "" {
							iface, ip, err := detectExternalInterface()
							if err != nil {
								return errors.Wrap(err, "detect default external interface")
							}
							config.NATInterface = iface
							config.Endpoint = net.JoinHostPort(ip, "51820")
							lg.Info("Detected default external interface", "interface", iface, "ip", ip)
						}

						configData, err = yaml.Marshal(&config)
						if err != nil {
							return errors.Wrap(err, "marshal default config")
						}

						// Permissions: current user can read and write, others can not read or write.
						const permissions = 0640
						if err := os.WriteFile(configPath, configData, permissions); err != nil {
							return errors.Wrap(err, "write default config")
						}
					}
				} else {
					if err := yaml.Unmarshal(configData, &config); err != nil {
						return errors.Wrap(err, "unmarshal config")
					}
				}
			}

			// Configure device.
			var wgConfig wgtypes.Config
			{
				if config.PrivateKey != (Key{}) {
					k := wgtypes.Key(config.PrivateKey)
					wgConfig.PrivateKey = &(k)
				}
				if config.Port != 0 {
					wgConfig.ListenPort = &config.Port
					wgConfig.FirewallMark = &config.Port
				}
				for _, peer := range config.Peers {
					var peerConfig wgtypes.PeerConfig
					peerConfig.PublicKey = wgtypes.Key(peer.PrivateKey).PublicKey()
					peerConfig.AllowedIPs = []net.IPNet{
						net.IPNet(peer.Address),
					}
					wgConfig.Peers = append(wgConfig.Peers, peerConfig)
				}
			}
			if err := client.ConfigureDevice(link.Info.Name, wgConfig); err != nil {
				return errors.Wrap(err, "configure device")
			}

			if err := app.configureRouting(ctx, link.Info.Name, config.NATInterface); err != nil {
				return errors.Wrap(err, "configure routing")
			} else {
				lg.Info("routing configured")
			}

			<-ctx.Done()
			lg.Info("wg-manager stopped")
			{
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				if err := link.Down(rx); err != nil {
					lg.Warn("set link down", "err", err)
				}

				if err := link.Del(rx); err != nil {
					if errors.Is(err, os.ErrNotExist) {
						lg.Info("wg-manager link already deleted")
					} else {
						lg.Warn("delete wireguard link", "err", err)
					}
				}

				if err := app.deconfigureRouting(ctx, link.Info.Name, config.NATInterface); err != nil {
					lg.Warn("deconfigure routing", "err", err)
				} else {
					lg.Info("routing deconfigured")
				}
			}
			return ctx.Err()
		},
	}

	cmd.AddCommand(
		ConfigCommand(),
		ClientCommand(),
	)

	return cmd
}
