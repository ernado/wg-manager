package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-faster/errors"
	"gitlab.com/mergetb/tech/rtnl"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func run(ctx context.Context) error {
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
	if err := client.ConfigureDevice("wgm0", wgtypes.Config{}); err != nil {
		return errors.Wrap(err, "configure device")
	}

	<-ctx.Done()
	lg.Info("wg-manager stopped")
	return ctx.Err()
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil && !errors.Is(err, ctx.Err()) {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v+\n", err)
	}
}
