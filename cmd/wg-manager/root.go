package main

import (
	"log/slog"
	"os"

	"github.com/go-faster/errors"
	"github.com/spf13/cobra"
	"gitlab.com/mergetb/tech/rtnl"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func Root() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wg-manager",
		Short: "WireGuard manager.",
		Long:  "Manager for WireGuard peers.",
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

			if err := link.Add(rx); err != nil {
				if errors.Is(err, os.ErrExist) {
					lg.Info("wg-manager already running")
				} else {
					return errors.Wrap(err, "add wireguard link")
				}
			}

			// Configure device.
			if err := client.ConfigureDevice(link.Info.Name, wgtypes.Config{}); err != nil {
				return errors.Wrap(err, "configure device")
			}

			<-ctx.Done()
			lg.Info("wg-manager stopped")
			return ctx.Err()
		},
	}

	return cmd
}
