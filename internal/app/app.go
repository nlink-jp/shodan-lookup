// Package app implements the shodan-lookup command-line interface: subcommand
// dispatch plus the host / service / count / quota / cache / mcp commands.
// Core logic lives in the config, cache and (as it lands) engine packages;
// this package is the thin I/O shell around them.
package app

import (
	"fmt"
	"io"
	"os"
)

// Exit codes. An IP that is not in Shodan's index and a count of zero are
// answers, so they are distinct from an operational failure.
const (
	exitOK       = 0 // every query was answered (empty answers included)
	exitUpstream = 1 // upstream could not be asked, or not fully
	exitError    = 2 // usage / validation / configuration error
)

// Run dispatches a subcommand and returns a process exit code.
func Run(args []string, version string) int {
	return run(args, version, os.Stdin, os.Stdout, os.Stderr)
}

// run is Run with injected streams, so dispatch, the version banner and the
// command output can be tested without touching the process's own stdio.
func run(args []string, version string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "host", "service", "count", "quota":
		return notImplemented(cmd, stderr)
	case "cache":
		return runCache(rest, stdout, stderr)
	case "mcp":
		return runMCP(rest, version, stdin, stdout, stderr)
	case "version", "--version", "-v":
		printVersion(stdout, version)
		return exitOK
	case "help", "-h", "--help":
		usage(stdout)
		return exitOK
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", cmd)
		usage(stderr)
		return exitError
	}
}

// notImplemented refuses a placeholder command. It must not exit 0: a
// scaffold that answered `host 192.0.2.1` with silence and success would read
// as "nothing exposed".
func notImplemented(cmd string, stderr io.Writer) int {
	fmt.Fprintf(stderr, "shodan-lookup: %s is not implemented yet (it arrives with the engine, Phase 1 of the RFP)\n", cmd)
	return exitError
}

// printVersion is the single source of the version banner. `--version` and the
// `version` subcommand must print byte-identical output: a Homebrew formula's
// `brew test` calls `--version`, while humans type `version`, and a formula
// that tests one while the docs teach the other is how a release ships broken.
func printVersion(w io.Writer, version string) {
	fmt.Fprintln(w, "shodan-lookup "+version)
	fmt.Fprintln(w, "Data source: Shodan REST API (api.shodan.io), with your own API key.")
	fmt.Fprintln(w, "Not affiliated with or endorsed by Shodan, LLC. Queries are attributed to your Shodan account.")
}

func usage(w io.Writer) {
	fmt.Fprint(w, `shodan-lookup — what an IP address exposes to the Internet, read from Shodan

Usage:
  shodan-lookup <command> [flags] [target...]

Commands:
  host <IP>...             Open ports, products, certificates and inferred CVEs of a host
  service <IP> <PORT>      One service of a host in full, section by section
  count <QUERY>            How many services match a Shodan query, with breakdowns
  quota                    Your plan and remaining query credits (always live)
  cache status             Show the result-cache state and the config file read
  cache clear              Clear the result cache
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

host, service, count and quota are not implemented yet; they arrive with the
engine (Phase 1 of the RFP) and exit 2 until then.

Flags (after or before the target):
  --json, -j               complete JSON on stdout
  --config, -c <path>      config file

Exit codes:
  0  every query was answered — "not in Shodan's index" and a count of zero
     are answers
  1  upstream could not be asked, or not fully
  2  error (invalid input, bad configuration, an unimplemented command, ...)

Only a third-party index is read, so no packet reaches the host under
investigation. Every query is attributed to your Shodan account: Shodan learns
which IPs and which search words you looked up. The tool is read-only by
design — Shodan's on-demand scanning is never used.
`)
}
