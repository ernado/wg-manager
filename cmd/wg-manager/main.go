package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-faster/errors"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := Root().ExecuteContext(ctx); err != nil && !errors.Is(err, ctx.Err()) {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v+\n", err)
	}
}
