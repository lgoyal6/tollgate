// Command gateway runs the tollgate API gateway.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/lgoyal6/tollgate/internal/config"
	"github.com/lgoyal6/tollgate/internal/gateway"
	"github.com/lgoyal6/tollgate/internal/observability"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "tollgate:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	logger := observability.NewLogger(cfg.LogLevel).With("service", cfg.ServiceName, "version", cfg.Version)

	g, err := gateway.New(context.Background(), cfg, logger)
	if err != nil {
		return err
	}
	return g.Run(context.Background())
}
