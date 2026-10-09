# AGENTS.md — shodan-lookup

## Summary

`shodan-lookup` is a read-only CLI + local MCP server (Go, standard library
only) that answers what an IP address exposes to the Internet, from the Shodan
REST API with the operator's own API key: open ports, products and versions,
TLS certificates, inferred CVEs, observation times. Series:
cybersecurity-series. Module: `github.com/nlink-jp/shodan-lookup`.

**Status: scaffold (RFP §4, Phase 2 of the org process).** Working:
`version` / `--version` / `-v`, `help`, `cache status|clear`, `mcp` with
`cache_status` and `get_usage`. Placeholders that exit 2 with "not implemented
yet": `host`, `service`, `count`, `quota`. Next: RFP §4 Phase 1 (core) —
measure first (the credit-free list in RFP §4), then `ipaddr`, the `shodan`
client, the engine, and the MCP tools `lookup_host` / `get_service` /
`count_services` / `get_quota`.

Design authority: `docs/ja/shodan-lookup-rfp.ja.md` (primary) and
`docs/en/shodan-lookup-rfp.md`.

## Build / test

```bash
make build       # → dist/shodan-lookup, signed when a Developer ID is available
make test        # go test -race -cover ./... ; go vet -tags e2e ./...  (offline)
make lint        # golangci-lint (config in .golangci.yml)
make check       # lint + test + build-all
make package     # archives per the org Release Archive Standard, notarizes darwin
make verify-release
```

Never run `go build` directly. The `e2e` target arrives in RFP Phase 2;
`make e2e` must then fail — not skip — without a key.

## Structure

```
main.go                 CLI entry: main.version → app.Run
source_test.go          no raw control / bidi character in any source file
internal/config/        sectioned-TOML subset + SHODAN_LOOKUP_* (+ SHODAN_API_KEY alias); strict; base_url https-only
internal/cache/         fixed-TTL JSON-file cache; Key = hash over length-prefixed parts; TTL 0 = off
internal/termsafe/      the one list of characters a terminal obeys
internal/mcp/           stdio JSON-RPC 2.0 server; decodeArgs; budget backstops; embedded usage.md
internal/app/           dispatch; cache / mcp commands; placeholders for the lookup commands
scripts/                codesign / notarize / brew — byte-identical copies of nlink-jp/.github/templates
docs/{ja,en}/           RFP
```

Planned (RFP §3): `internal/ipaddr` (pre-network gate for IP arguments and
query tokens), `internal/shodan` (REST client), `internal/engine` (gate →
cache → client → projection, shared by CLI and MCP).

## Where the scaffold came from

Ported 2026-10-09. The source was chosen per package by
`git log -1 --format=%ci -- internal/<pkg>` across the siblings, not by
repository HEAD: the HEADs of every sibling were aligned by the 2026-09-23
archive-xattr sweep and could not tell generations apart. cve-lookup held the
newest generation of every portable package — it already had the closed
schemas and the strict argument decoding the others received in the
2026-09-21 sweeps.

| here | from | changes |
|---|---|---|
| `internal/config` | cve-lookup | keys and env names for Shodan; `[api] key` (presence-read, `""` refused) with `SHODAN_API_KEY` alias; https-only base_url; TTLs in hours with 0 = off; top-level key gets directions |
| `internal/cache` | cve-lookup | `Key` rewritten to cve-lookup's later `engine.key` design (length-prefixed hash, correction 25) and moved into the cache package; inputs no longer readable in filenames; `Get` with TTL ≤ 0 always misses |
| `internal/termsafe` | cve-lookup | doc only |
| `internal/mcp` server.go, budget.go | cve-lookup | no engine yet; `ownCap` is section text only (`Text` / `text`) |
| `internal/mcp` tools.go, usage.md | new (cve-lookup's shape) | scaffold tools only |
| `internal/mcp` usage_test.go | cve-lookup | code packages discovered under `internal/` instead of listed |
| `internal/app` common.go, cachecmd.go, mcpcmd.go, tests | cve-lookup | TTL fields; key state shown as set / not set |
| `Makefile`, `.golangci.yml`, `.gitignore`, `LICENSE`, `source_test.go` | cve-lookup | name, brew description, no e2e target yet |
| `scripts/*` | `nlink-jp/.github/templates` | none (byte-identical) |

## Gotchas

Measured 2026-10-09 on a Membership key with credit-free calls only (17 calls;
credits 100 before and after). The raw figures and their recount are in RFP
§7; the essentials:

- **The key is a query parameter only** (`?key=`; OpenAPI declares no
  security scheme). Every error path must be scrubbed of the URL.
- **401 for a bad key is text/plain HTML-ish, not JSON** (seen on `/api-info`
  only — measure the other endpoints in Phase 1).
- **404 has two meanings**: `{"error": "Invalid IP"}` and
  `{"error": "No information available for that IP."}`. The latter was taken
  on TEST-NET (192.0.2.1), which the tool refuses before sending — measure an
  unindexed global unicast IP in Phase 1.
- **`history=true` returned that same "No information available" 404 for
  8.8.8.8 and 1.1.1.1**, which have data (n=2; cause presumed to be the plan,
  undocumented). Excluded.
- **Counts are services, not hosts**: an `ip` facet value equals the number of
  matching services on that IP.
- **Sizes**: 8.8.8.8 19 KB; 1.1.1.1 316 KB (one service 92 KB — `http.html`
  59 KB, `http.favicon.data` 21 KB); a vulnerable host 991 KB with 138 CVEs,
  the same 225 KB `vulns` dict repeated in two services. `minify=true` returns
  `data: []` (~500 B).
- **Timestamps carry no time-zone suffix** (`2026-10-09T05:01:41.136770`).
  Do not compute ages until UTC is confirmed.
- **No rate-limit headers.** Documented 1 req/s on all plans.
- **Credit-free (measured)**: host lookup, `count` with filters and
  `facets=ip:N`, `tokens`. Search costs 1 credit with a filter or past page 1
  (documented); page-2 accounting is unmeasured (Phase 2, with approval).
- **Terms**: `https://static.shodan.io/legal/terms.html`, read 2026-10-09
  (sha256 and reading in RFP §7). Re-check the hash before each release.
- The config used for the measurements first held a top-level `api_key`;
  this tool refuses that shape with directions to `[api] key`. The operator
  rewrote it to `[api] key` the same day.
