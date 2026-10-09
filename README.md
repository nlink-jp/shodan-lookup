# shodan-lookup

What an IP address exposes to the Internet — open ports, the product and
version behind each, TLS certificates, the vulnerabilities Shodan infers from
banners, and when each was observed — as a CLI and a local MCP server.

**shodan-lookup is not affiliated with or endorsed by Shodan®, LLC.** It reads
the [Shodan](https://www.shodan.io) REST API with your own API key.

Among the sibling lookup tools, `asn-lookup` and `whois-lookup` answer who owns
an IP, `abuse-lookup`, `tor-exit-lookup` and `icloud-relay-lookup` how it has
been used, and this tool what it exposes. Inferred CVEs continue to
`cve-lookup`.

- **Read-only by design.** Shodan's on-demand scanning — which has Shodan probe
  a target — and every write path (alerts, notifiers, account settings) are
  out of scope permanently.
- **A negative answer is never manufactured.** An IP Shodan has not observed is
  reported as not in Shodan's index, never as "nothing open"; an empty list of
  inferred CVEs is not "no vulnerabilities".
- **Credits are guarded by the tool.** Only the search spends query credits,
  and it refuses to go below a floor you set.

Only a third-party index is read, so **no packet reaches the host under
investigation**. Every query is attributed to your Shodan account: Shodan
learns which IPs and which search words you looked up. Internal addresses are
refused before anything is sent.

## Status

This is the project scaffold. The lookup commands `count`, `host`, `quota`
and `service` are placeholders in this build: they exit 2 with "not
implemented yet".

What works today: `cache status`, `cache clear`, `mcp` and `version`.

On the MCP side, `cache_status` and `get_usage` answer today;
the lookup tools arrive with the engine (Phase 1 of the
[RFP](docs/en/shodan-lookup-rfp.md)).

## Requirements

- A Shodan API key, Membership or above (measured on a Membership key: host
  lookups and counts spend no credits; Membership grants 100 query credits a
  month for searches).
- Network access to `api.shodan.io`.

## Installation

Not released yet. Build from source:

```bash
make build        # → dist/shodan-lookup
```

## Configuration

Copy [config.example.toml](config.example.toml) to
`~/.config/shodan-lookup/config.toml` (mode 0600) and set the key under
`[api]`:

```toml
[api]
key = "YOUR-SHODAN-API-KEY"
```

A key written on its own line outside a section (`api_key = "..."`, the shape
other Shodan tooling uses) is refused with directions to `[api]`. The file is
looked for in `$XDG_CONFIG_HOME/shodan-lookup/`, then
`~/.config/shodan-lookup/`, then (macOS)
`~/Library/Application Support/shodan-lookup/`; `shodan-lookup cache status`
prints which one was read and whether a key is set — never the key itself. A
section or key the tool does not know is an error, and so are a `--config`
path that does not exist, a key set to `""`, and a number out of its range.
`base_url` must be https: the key travels in every request's query string.

Environment variables override the file: `SHODAN_LOOKUP_API_KEY` (or
`SHODAN_API_KEY`), `SHODAN_LOOKUP_BASE_URL`, `SHODAN_LOOKUP_CACHE_DIR`,
`SHODAN_LOOKUP_DEFAULT_SERVICES`, `SHODAN_LOOKUP_DEFAULT_VULNS`,
`SHODAN_LOOKUP_BANNER_BYTES`, `SHODAN_LOOKUP_CREDIT_FLOOR`,
`SHODAN_LOOKUP_HOST_TTL_HOURS`, `SHODAN_LOOKUP_COUNT_TTL_HOURS`,
`SHODAN_LOOKUP_SEARCH_TTL_HOURS`, `SHODAN_LOOKUP_TIMEOUT_SECONDS` and
`SHODAN_LOOKUP_MIN_INTERVAL_MS` — the example file documents every setting. A
TTL of 0 turns caching off for that kind of answer.

## Commands

```
shodan-lookup host <IP>...             Open ports, products, certificates and inferred CVEs of a host
shodan-lookup service <IP> <PORT>      One service of a host in full, section by section
shodan-lookup count <QUERY>            How many services match a Shodan query, with breakdowns
shodan-lookup quota                    Your plan and remaining query credits (always live)
shodan-lookup cache status|clear       Inspect or clear the result cache
shodan-lookup mcp                      Run as a local MCP server (stdio)
shodan-lookup version                  Print the version
```

Counts are in **services (banners), not hosts**: an IP with two matching
services counts twice.

Exit codes: 0 — every query was answered ("not in Shodan's index" and a count
of zero are answers); 1 — upstream could not be asked, or not fully; 2 —
usage, validation or configuration error, or an unimplemented command.

## MCP server

```json
{
  "mcpServers": {
    "shodan-lookup": { "command": "/path/to/shodan-lookup", "args": ["mcp"] }
  }
}
```

Call `get_usage` first: it is the full reference and the error-recovery table.

## Data source and terms

Results are Shodan's data, read under Shodan's
[terms of service](https://static.shodan.io/legal/terms.html). The terms
(§6.7) require that Shodan information included in your own materials — an
incident report, for example — be attributed to Shodan, with Shodan's
ownership and copyright indicated; every result this tool returns names its
source for that reason. Cached responses stay on your machine.

The project's reading of the terms is recorded in the RFP (§7). It is not
legal advice: whether your use of your Shodan plan complies with them is yours
to confirm.

## Documentation

- [RFP (design authority)](docs/en/shodan-lookup-rfp.md) — Japanese original:
  [docs/ja/shodan-lookup-rfp.ja.md](docs/ja/shodan-lookup-rfp.ja.md)

## License

MIT — see [LICENSE](LICENSE). Shodan® is a trademark of Shodan, LLC.
