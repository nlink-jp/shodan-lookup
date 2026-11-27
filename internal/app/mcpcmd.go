package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/mcp"
)

// notifyContext is signal.NotifyContext; a test stands in for the signal.
var notifyContext = signal.NotifyContext

// runMCP serves the stdio MCP server until stdin closes (every request that
// arrived is answered first) or a signal arrives. SIGINT and SIGTERM cancel the
// server's ctx, so it returns at once and its cleanup runs.
func runMCP(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	var configPath string
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { usage(stderr) }
	fs.StringVar(&configPath, "config", "", "config file path")
	fs.StringVar(&configPath, "c", "", "config file path (shorthand)")
	extra, err := parseInterleaved(fs, args)
	if err != nil {
		return exitError
	}
	if len(extra) > 0 {
		fmt.Fprintf(stderr, "shodan-lookup: mcp takes no arguments (got %q)\n", extra[0])
		return exitError
	}

	cfg, err := config.Load(configPath, 0)
	if err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: %v\n", err)
		return exitError
	}

	// The same engine the CLI commands build, so the two faces cannot give
	// different answers for the same input.
	srv := &mcp.Server{
		Cfg:     cfg,
		Cache:   &cache.Store{Dir: cfg.CacheDir},
		Eng:     NewEngine(cfg, version),
		Version: version,
	}

	ctx, stop := notifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Serve(ctx, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
