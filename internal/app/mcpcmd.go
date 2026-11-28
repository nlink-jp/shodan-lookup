package app

import (
	"context"
	"flag"
	"fmt"
	"io"

	"github.com/nlink-jp/mcptool/serve"

	"github.com/nlink-jp/shodan-lookup/internal/cache"
	"github.com/nlink-jp/shodan-lookup/internal/config"
	"github.com/nlink-jp/shodan-lookup/internal/mcp"
)

// runMCP serves the stdio MCP server until stdin closes (every request that
// arrived is answered first) or a signal arrives. mcptool's serve.Run cancels
// the server's ctx on SIGINT and SIGTERM, so it returns at once and its
// cleanup runs (ADR-0002); a test stands in for the signal through
// serve.NotifyContext.
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

	ms, err := srv.Build()
	if err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: mcp: %v\n", err)
		return exitError
	}
	if err := serve.Run(context.Background(), ms, serve.Options{Stdin: stdin, Stdout: stdout}); err != nil {
		fmt.Fprintf(stderr, "shodan-lookup: mcp: %v\n", err)
		return exitError
	}
	return exitOK
}
