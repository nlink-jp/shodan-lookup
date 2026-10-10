# AGENTS.md — shodan-lookup

## Summary

`shodan-lookup` is a read-only CLI + local MCP server (Go, standard library
only) that answers what an IP address exposes to the Internet, from the Shodan
REST API with the operator's own API key: open ports, products and versions,
TLS certificates, inferred CVEs, observation times. Series:
cybersecurity-series. Module: `github.com/nlink-jp/shodan-lookup`.

**Status: RFP Phase 1 (core) implemented with history added (RFP "Adding
history"), released (versions in CHANGELOG.md).** CLI `host`, `service`, `count`, `history`, `tokens`,
`search`, `quota`, `cache`, `mcp`, `version`; MCP tools `lookup_host`,
`get_service`, `count_services`, `get_history`, `parse_query`,
`search_services`, `get_quota`, `cache_status`, `get_usage`.
Phase 2 implemented: `parse_query` / `search_services` (CLI `tokens` /
`search`) with the credit guard (engine/search.go), and the e2e suite. Every
release so far passed an independent verification before it shipped.

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
make e2e         # live, credit-free; fails without a key and if the remainder moved
make e2e-credits # live, SPENDS ONE CREDIT: a filtered search, predicted vs actual
```

Never run `go build` directly. The e2e suite reads the key from the
operator's config (or `SHODAN_LOOKUP_E2E_CONFIG`), uses its own cache, and
pins the upstream traps the design rests on — a failing pin names the
Gotcha below that is out of date.

## Structure

```
main.go                 CLI entry: main.version → app.Run
source_test.go          no raw control / bidi character in any source file
internal/ipaddr/        pre-network gate: IP arguments and every address literal in a query against a finite class table; query lexer
internal/shodan/        REST client: key in the query only, no URL in any error, redirects refused, pacing, status → codes
internal/engine/        gate → cache → client → OUR projection; 404 cross-check; name lists; sections; shared by CLI + MCP;
                        loose.go reads upstream documents field by field (drift is left out and named, never fatal)
internal/config/        sectioned-TOML subset + SHODAN_LOOKUP_* (+ SHODAN_API_KEY alias); strict; base_url https-only
internal/cache/         fixed-TTL JSON-file cache; Key = hash over length-prefixed parts; TTL 0 = off; a hit is the bytes put
internal/termsafe/      the one list of characters a terminal obeys
internal/mcp/           stdio JSON-RPC 2.0 server; the response budget (lookup.go) and its backstops (budget.go); usage.md
internal/app/           dispatch; host / service / count / history / tokens / search / quota / cache / mcp; text made inert as a whole (forText)
scripts/                codesign / notarize / brew — byte-identical copies of nlink-jp/.github/templates
e2e/                    live tests (tags e2e, e2e_credits): the tool end to end, and the upstream traps pinned
docs/{ja,en}/           RFP
```

Where the budget lives: the engine returns complete views (`--json` prints
them); `internal/mcp/lookup.go` compacts — services to `default_services`,
banners to `banner_bytes` *after JSON escaping*, CVEs to `default_vulns`,
then thins services past a 112 KB soft budget — and counts every drop in
`omitted`. `budget.go` exempts section content (`Text`, `Items`, `Summary`)
from the 1000-character backstop by name.

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
| `internal/mcp` server.go, budget.go | cve-lookup | `ownCap` is section content (`Text`, `Items`, `Summary`) |
| `internal/mcp` tools.go, usage.md | new (cve-lookup's shape) | scaffold tools only |
| `internal/mcp` usage_test.go | cve-lookup | code packages discovered under `internal/` instead of listed |
| `internal/app` common.go, cachecmd.go, mcpcmd.go, tests | cve-lookup | TTL fields; key state shown as set / not set |
| `Makefile`, `.golangci.yml`, `.gitignore`, `LICENSE`, `source_test.go` | cve-lookup | name, brew description, no e2e target yet |
| `scripts/*` | `nlink-jp/.github/templates` | none (byte-identical) |

## Gotchas

Measured 2026-10-09 on a Membership key with credit-free calls only — 17 calls
before the RFP, then 49 before Phase 1 (credits 100 before and after every
run). Recounts and the design consequences are in RFP §7 and "Corrections from
the Phase 1 measurements"; the essentials:

- **The key is a query parameter only** (`?key=`; OpenAPI declares no
  security scheme). Every error path must be scrubbed of the URL.
- **Host lookups do not check the key**: `/shodan/host/{ip}` returned the full
  record with a wrong key and with none (history too). Only `count`, `tokens`
  and `/api-info` answer 401 — text/plain HTML-ish, not JSON.
- **404 has two bodies**: `{"error": "Invalid IP"}` and
  `{"error": "No information available for that IP."}` — and the second also
  comes from upstream failures: `history=true` on 8.8.8.8 / 1.1.1.1 returns it
  reproducibly while `count ip:<addr>` shows 2 / 15 services. A host 404 is
  cross-checked with that free count before it is called `not_indexed`.
  An unindexed global IP gives the same body with count 0 (the e2e fixture
  is an unused address in Google's IPv6 block, 2001:4860:ffff:ffff::5).
- **`history=true` works on Membership** (9.9.9.9, 208.67.222.222, 1.0.0.1:
  200, 1.0–6.4 MB) and is **silently capped at the latest 1,000 banners** —
  one chatty port can fill it (973 of 1,000 on 53/udp, a 2.5-day window).
  Banners come unordered. `get_history` states the window and names a
  dominating port; its 404 is cross-checked like the host 404.
- **Silent no-ops**: an unknown filter becomes free text (200, 0 results;
  `tokens` shows it as `nosuchfilter\:x`); an unknown facet name is dropped
  (200, no `facets` key); an unknown query parameter is ignored. Validate
  names against `/shodan/host/search/filters` and `/facets` (both free).
- **Plan restrictions read as low counts**: `vuln:CVE-2021-44228` → 200,
  total 3. `vuln` and `tag` are refused locally.
- **Syntax errors**: unbalanced quote → count 500 "timed out or your query was
  invalid" (ambiguous), tokens 400 "Invalid search query". Empty query → 400
  "Empty search query". Zero-padded IPv4 → 500 "Unable to fetch information".
- **Counts are services, not hosts**: an `ip` facet value equals the number of
  matching services on that IP. `ip:1000` returned 1,000 entries (39 KB);
  `org:1000` all 663.
- **Scalars are not held to one type** (2026-10-10): one host record carried
  `asn` as `2497` at the top and as both `2497` and `"AS2497"` across its
  services. Strictly typed, that one field failed the whole record, `--raw`
  included, because the same decode gated the cache. Now the gates ask only
  for the document's shape — `validHost`: a JSON object whose `data`, if
  present, is a list; `validSearch`: a numeric total and a list of matches;
  `validCount`: a numeric total — and every projection (host, service,
  history, search, count) reads through `decodeLoose` (loose.go). An
  unreadable value must never become a value, so: a field stays absent
  (pointers, or a string the projection does not show when empty); a list
  element whose identifying field (`loose:"required"`: a service's port and
  transport, a match's `ip_str`, a facet value's count) is missing, null or
  unreadable in its last occurrence — or that is null or not an object — is
  left out whole (a required field must be a leaf); history counts those
  banners in `window.banners` and the cap, since the cap is Shodan's; a map entry keeps its key (a CVE ID) and only its value's
  unreadable parts are absent. `notes` name each path with a count
  (`data[].http.status (1)`), never a value or a key. `get_service` answers
  `decode_error`, not `not_observed`, when a service was left out whole — it
  may be the one asked for. A `verified` that cannot be read reads false,
  which the tool already defines as "not confirmed". Keys resolve in document
  order as in encoding/json (a later duplicate wins). The string fields go
  through `text` so a number is kept rather than left out.
  **Residual:** once any service was left out, `get_service` answers
  `decode_error` for every port with no readable service — also ports that
  service cannot be (when only its transport was unreadable) — and a port
  asked without a transport answers the one readable service rather than
  "more than one service". Both err toward not claiming; the note names the
  left-out entry.
- **Timestamps are UTC** (newest observation 2–30 min before `Date`, 3/3) and
  carry no suffix (`2026-10-09T05:01:41.136770`).
- **IPv6 works**, abbreviated or not, in host lookups and in `ip:` counts
  (unquoted, quoted, unabbreviated and `net:…/128` all returned 2).
- **Restricted names on Shodan's own lists**: filters `vuln`, `tag`,
  `has_vuln`; facets `vuln`, `tag`, `vuln.verified`. All refused locally.
- **`http.headers` exists** in real banners as an object of string values
  (measured on 1.1.1.1), so the `http_headers` section is not empty by
  construction.
- **encoding/json escapes U+2028/U+2029 whatever SetEscapeHTML says** — the
  engine escapes them at fetch so a fresh body and a cache hit are the same
  bytes (doc_id).
- **`ssl.cert.fingerprint:` matches SHA-1 only** — a SHA-256 returns 200
  with 0 results (the same certificate's SHA-1: 17,384). Refused locally.
  `http.favicon.hash:<favicon_hash>` works.
- **Sizes**: 8.8.8.8 19 KB; 1.1.1.1 316 KB (one service 92 KB — `http.html`
  59 KB, `http.favicon.data` 21 KB); a vulnerable host 991 KB with 138 CVEs,
  the same 225 KB `vulns` dict repeated in two services. `minify=true` returns
  `data: []` (~500 B). No host with hundreds of services was found by free
  means — unmeasured.
- **No rate-limit headers** (Cloudflare in front). Documented 1 req/s.
- **Credit-free (measured)**: host lookup (with or without history), `count`
  with filters and facets, `tokens`, the filter and facet lists, and an
  unfiltered search page 1 even with facets.
- **Search costs (measured 2026-10-09, 2 credits spent with approval)**:
  filtered page 1 → 1, filtered page 2 → 1 (not 2). `tokens` predicted all
  three. `query_credits` and `unlocked_left` drop together and show the
  charge at once. A page is up to 9.3 MB (100 banners); `total` moves
  between pages.
- **The guard, live (2026-10-09, 1 more credit)**: an unfiltered search went
  through every step and spent 0 as predicted; a filtered one spent 1 as
  predicted (98 → 97); the repeat came from the cache; with the floor at 98
  nothing was sent (exit 2). The first `make e2e-credits` run spent the
  fourth (97 → 96): all four credits approved for Phase 2 are used, and any
  further spend needs the operator's approval.
- **Residual: concurrent processes can cross the floor.** The floor is
  checked per process against a remainder read before sending; N processes
  sharing the key that read the same remainder at once can each pass the
  check, crossing the floor by up to N−1 credits. Each then sees a spend
  other than predicted and stops searching (credit_mismatch). A shared lock
  across processes was judged not worth its complexity (RFP §2).
- **Terms**: `https://static.shodan.io/legal/terms.html`, read 2026-10-09
  (sha256 and reading in RFP §7). Re-check the hash before each release.
- The config used for the measurements first held a top-level `api_key`;
  this tool refuses that shape with directions to `[api] key`. The operator
  rewrote it to `[api] key` the same day.
