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
- **Credits are guarded by the tool.** Only `search` spends query credits
  (1 per page with a filter or past page 1; measured). It refuses to go below
  a floor you set, counting every search as 1, and stops if a search ever
  spends other than predicted. Host lookups, history, counts and the quota
  are credit-free (measured).

Only a third-party index is read, so **no packet reaches the host under
investigation**. Every query is attributed to your Shodan account: Shodan
learns which IPs and which search words you looked up. An IP address that is
not public — private, loopback, link-local, documentation ranges, and IPv6
forms that embed them — is refused wherever it appears in an argument or a
query, before anything is sent. Names (`hostname:intranet.example`) cannot be
judged by their spelling and are sent as written.

## Status

Phases 1 and 2 of the [RFP](docs/en/shodan-lookup-rfp.md) are implemented,
with history added: `host`, `service`, `count`, `history`, `tokens`,
`search` and `quota`, and the MCP tools `lookup_host`, `get_service`,
`count_services`, `get_history`, `parse_query`, `search_services` and
`get_quota`. Released; versions are in [CHANGELOG.md](CHANGELOG.md).

## Requirements

- A Shodan API key, Membership or above (measured on a Membership key: host
  lookups and counts spend no credits; Membership grants 100 query credits a
  month for searches).
- Network access to `api.shodan.io`.

## Installation

Homebrew (macOS arm64, Apple-notarized build):

```bash
brew install nlink-jp/tap/shodan-lookup
```

Or download an archive for your platform from the
[releases page](https://github.com/nlink-jp/shodan-lookup/releases)
(darwin-arm64 zip is notarized; linux amd64/arm64 tar.gz; windows amd64 zip).

Or build from source:

```bash
make build        # → dist/shodan-lookup
make test         # offline
make e2e          # live against Shodan with your key; spends no credits, and fails if any moved
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
shodan-lookup history <IP>             What it exposed over time: per port, when each variant was seen
shodan-lookup tokens <QUERY>           How Shodan reads a query, and what a search would cost (free)
shodan-lookup search <QUERY>           One page of matching services — SPENDS QUERY CREDITS
shodan-lookup quota                    Your plan and remaining query credits (always live)
shodan-lookup cache status|clear       Inspect or clear the result cache
shodan-lookup mcp                      Run as a local MCP server (stdio)
shodan-lookup version                  Print the version
```

Every command that reads Shodan takes `--json` (complete JSON) and, except
`quota`, `--refresh` (bypass the cache).

```bash
shodan-lookup host 1.2.3.4                                # what it exposes
shodan-lookup host 1.2.3.4 --port 443 --json              # one port, complete JSON
shodan-lookup host 1.2.3.4 --raw                          # Shodan's own document
shodan-lookup service 1.2.3.4 443 --section ssl_cert      # the whole certificate
shodan-lookup service 1.2.3.4 53 --transport udp --section banner
shodan-lookup count 'port:3389 country:JP' --facet org:5 --facet ip:20
shodan-lookup history 1.2.3.4                             # when ports, products, titles, certificates changed
shodan-lookup history 1.2.3.4 --port 443 --limit 20       # that port's observations, newest first
shodan-lookup tokens 'product:nginx country:JP'           # free: would a search cost a credit?
shodan-lookup search 'product:nginx country:JP' --facet org:5   # 1 credit; prints what it spent on stderr
shodan-lookup quota
```

How to read the answers:

- **Not in Shodan's index** (`not_indexed`) means Shodan has not observed the
  IP — confirmed with a count of zero, never taken from Shodan's 404 alone,
  which also comes back when Shodan fails to return a record it holds. It is
  not evidence that nothing is open.
- **No banner for a port** (`not_observed`) is not evidence that the port is
  closed.
- **Inferred CVEs** come from banner versions; `verified: false` means
  inferred, and an empty list is not "not vulnerable".
- **Counts are in services (banners), not hosts**: an IP with two matching
  services counts twice. Facets list only their top values.
- **Filter and facet names are checked** against Shodan's own lists before
  sending: Shodan would read an unknown filter as text and match nothing, and
  drop an unknown facet silently. `vuln` and `tag` are refused on Membership —
  the restriction comes back as a misleadingly low count, not an error.
- **History is Shodan's latest 1,000 banners.** When capped, nothing earlier
  can be read, and a port's first sighting is the first inside that window,
  not when it opened; one chatty port can fill the window, and the answer
  names it. A history 404 is cross-checked like a host 404 — Shodan does not
  return the history of some large hosts that do have services.
- **`search` spends query credits**: 1 per page when the query uses a filter
  or the page is 2 or later, else 0 (measured; never more than 1 per call).
  Before sending, it reads your remainder and refuses (exit 2,
  `credit_floor`) if a search — counted as 1 whatever the prediction — would
  take it below `[search] credit_floor` (default 20). Afterwards it reads the
  remainder again and prints what was spent on stderr; if a search ever spends
  other than predicted, the process stops searching (`credit_mismatch`). A
  page is cached for 24 hours, so asking again spends nothing; `--refresh`
  spends again. `count` is free and answers most "how many / which ones"
  questions.
- **Times are UTC**; a certificate's `expired` is computed when you ask.
- **Host lookups do not check the API key** (measured): a wrong key still
  returns host records. `quota` and `count` are where it shows.

Exit codes: 0 — every query was answered ("not in Shodan's index", "no banner
for that port" and a count of zero are answers); 1 — upstream could not be
asked, or not fully; 2 — invalid input, an internal address, bad
configuration, a missing or refused API key, a plan-restricted filter
(`plan_restricted`), or a search the credit guard refused (`credit_floor`,
`credit_mismatch`).

## MCP server

```json
{
  "mcpServers": {
    "shodan-lookup": { "command": "/path/to/shodan-lookup", "args": ["mcp"] }
  }
}
```

Tools: `lookup_host`, `get_service`, `count_services`, `get_history`,
`parse_query`, `search_services` (the only one that spends credits), `get_quota`,
`cache_status`, `get_usage`. Call `get_usage` first: it is the full reference
and the error-recovery table. `lookup_host` answers within a response budget
— services, banners and CVEs past the defaults are counted in `omitted`, and
`get_service` reaches every part in full, paged.

Shodan does not hold its fields to one type (measured: an AS number sent as a
number and as a string within one record). A value of a type this tool does
not read is left out of the answer — never turned into 0 or false — and named
in `notes` by its path, for example `data[].http.status (1)`; a service whose
port cannot be read is left out whole rather than shown as port 0.
Everything else is answered, and the CLI's `--raw` still returns Shodan's
document as sent.

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
