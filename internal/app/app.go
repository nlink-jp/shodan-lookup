// Package app implements the shodan-lookup command-line interface: subcommand
// dispatch plus the host / service / count / history / tokens / search /
// quota / cache / mcp commands.
// Core logic lives in the ipaddr, shodan, cache, config and engine packages;
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
	case "host":
		return runHost(rest, version, stdout, stderr)
	case "service":
		return runService(rest, version, stdout, stderr)
	case "count":
		return runCount(rest, version, stdout, stderr)
	case "history":
		return runHistory(rest, version, stdout, stderr)
	case "tokens":
		return runTokens(rest, version, stdout, stderr)
	case "search":
		return runSearch(rest, version, stdout, stderr)
	case "quota":
		return runQuota(rest, version, stdout, stderr)
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
  history <IP>             What it exposed over time: per port, when each variant was seen
  tokens <QUERY>           How Shodan reads a query, and what a search would cost (free)
  search <QUERY>           One page of matching services — SPENDS QUERY CREDITS
  quota                    Your plan and remaining query credits (always live)
  cache status             Show the result-cache state and the config file read
  cache clear              Clear the result cache
  mcp                      Run as a local MCP server (stdio)
  version                  Print the version

Flags (after or before the target):
  --json, -j               complete JSON on stdout
  --refresh                bypass the cache and fetch again (not for quota)
  --config, -c <path>      config file; --timeout <seconds>
  host:     --port N (repeatable)  --ports-only  --raw (Shodan's own document)
  service:  --section banner|http_html|http_headers|ssl_cert|ssl_chain|vulns
            --transport tcp|udp  --offset N  --limit N
  count:    --facet NAME[:N] (repeatable, N 1-1000; e.g. --facet ip:20)
  history:  --port N (its observations)  --transport tcp|udp  --offset N  --limit N
            --raw (every historical banner in full)
  search:   --facet NAME[:N] (repeatable)  --page N (1-10)  --raw (every banner)

History is Shodan's latest 1,000 banners: when capped, nothing earlier can be
read, and a port's first sighting is the first inside that window.

search is the only command that spends query credits: 1 when the query uses a
filter or --page is 2 or later, else 0. It refuses to go below [search]
credit_floor, counting every search as 1, and prints what it spent on stderr.
count answers most questions for free; tokens predicts a search's cost.

Counts are in services (banners), not hosts. Filter and facet names are
checked against Shodan's own lists; vuln and tag are refused on a Membership
plan because the restriction comes back as a low count, not an error.

Exit codes:
  0  every query was answered — "not in Shodan's index", "no banner for that
     port" and a count of zero are answers
  1  upstream could not be asked, or not fully
  2  error (invalid input, an internal address, bad configuration, a missing
     or refused API key, ...)

Only a third-party index is read, so no packet reaches the host under
investigation. Every query is attributed to your Shodan account: Shodan learns
which IPs and which search words you looked up. A non-public IP address is
refused wherever it appears in an argument or a query; names cannot be judged
by their spelling and are sent as written. The tool is read-only by design —
Shodan's on-demand scanning is never used.
`)
}
