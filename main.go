// Command shodan-lookup answers what an IP address exposes to the Internet —
// open ports, the product and version behind each, TLS certificates, the
// vulnerabilities Shodan infers from them, and when each was observed — as a
// CLI and a local MCP server. It reads the Shodan REST API with the operator's
// own API key.
//
// Only a third-party index is read, so no packet reaches any party under
// investigation. Every query is attributed to the operator's Shodan account.
//
// The tool is read-only by design: Shodan's on-demand scanning, alerts and
// every other write path are out of scope permanently.
package main

import (
	"os"

	"github.com/nlink-jp/shodan-lookup/internal/app"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(app.Run(os.Args[1:], version))
}
