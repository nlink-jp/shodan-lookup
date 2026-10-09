package app

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/mcp"
)

// runMCP serves the stdio MCP server until stdin closes. A closing stdin is
// the shutdown signal: an MCP cancellation notification may be ignored by its
// receiver, so nothing here depends on one arriving.
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

	// When the lookup tools land, the server gets the same engine the CLI
	// commands build, so the two faces cannot give different answers.
	srv := &mcp.Server{
		Cfg:     cfg,
		Cache:   &cache.Store{Dir: cfg.CacheDir},
		Version: version,
	}

	if err := srv.Serve(context.Background(), stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
