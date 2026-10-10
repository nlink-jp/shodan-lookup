# CLAUDE.md — shodan-lookup

**Organization rules (mandatory): https://github.com/nlink-jp/.github/blob/main/CONVENTIONS.md**

## Purpose

CLI + local MCP server answering **what an IP address exposes to the
Internet** — open ports, products and versions, TLS certificates, the CVEs
Shodan infers from banners, and when each was observed — from the **Shodan
REST API** (`https://api.shodan.io`) with the operator's own key.

In the lookup family it is the "what does it expose" step of IP triage, after
asn / whois (who owns it) and abuse / tor-exit / icloud-relay (how it has been
used). Inferred CVEs go on to `cve-lookup`.

Only a third-party index is read, so **no packet reaches the host under
investigation** — but every query is **attributed to the operator's Shodan
account**.

Design authority: [docs/ja/shodan-lookup-rfp.ja.md](docs/ja/shodan-lookup-rfp.ja.md)
(English translation in docs/en/). **Status: RFP Phases 1 and 2 and history
implemented, verified independently three times, released (versions in
CHANGELOG.md and `git tag`; Homebrew `nlink-jp/tap/shodan-lookup`).**

## Build & test

```bash
make build       # → dist/shodan-lookup  (never `go build` directly — it drops the binary in the repo root)
make test        # go test -race -cover ./... then go vet -tags e2e ./...   (fully offline)
make check       # lint + test + build-all
make e2e         # live against Shodan, credit-free; needs the key; fails if credits moved
make e2e-credits # live, SPENDS ONE QUERY CREDIT
```

Go 1.25+. **No external dependencies — standard library only.**

## Key conventions

- **Read-only, permanently.** No on-demand scanning (`/shodan/scan`,
  `/shodan/scan/internet` have Shodan probe the target), no alerts, notifiers,
  org or account writes. No InternetDB (free only for non-commercial use;
  operator decision). Do not add such paths.
- **The API key never appears on any output surface.** Shodan takes it only in
  the query string, and Go's `*url.Error` quotes the whole URL. The request URL
  must not reach an error message, a log, `provenance`, `details`, a cache key
  or a cache file. Redirects are refused (Go would carry the query on).
  `base_url` is https only (plain http on loopback, for tests), operator config
  only, never a tool argument. `Config.Redacted` for anything that prints
  settings.
- **Internal addresses are never sent.** IP arguments are checked before the
  network (IPv6 allow-list 2000::/3, then the deny table), and so is every
  address literal anywhere in a query — not only `ip:` / `net:` terms. Terms
  are split on ASCII space and tab only; any other space or control
  character refuses the query. Names are the documented residual.
- **Input that is not understood is refused, never ignored.** Unknown config
  sections and keys, keys outside a section (a bare `api_key` gets directions
  to `[api]`), present-but-empty values, out-of-range numbers, a missing
  explicit `--config`, and MCP arguments a tool does not declare
  (`decodeArgs`, every tool, including those that take none).
- **Upstream drift is left out and named, never fatal — and never a value.**
  Shodan does not hold its fields to one type. Gates ask only for the
  document's shape; every projection reads through `decodeLoose` and names
  what it left out in `notes` by path only. An unreadable value stays absent:
  an entry whose identifying field cannot be read (`loose:"required"`) is
  left out whole, never kept with a zero. Do not reintroduce a strict decode
  in front of the cache or `--raw`.
  (The opposite rule holds for the operator's own input, above.)
- **A negative answer is never manufactured.** The 404 "No information
  available for that IP." also comes from upstream failures, so it becomes
  `not_indexed` only after a credit-free `count ip:<addr>` confirms zero; a
  positive count or a failed check is `upstream_error`. `not_observed` (no
  banner for a port) is not "closed". An empty `vulns` is not "no
  vulnerabilities"; `verified: false` is an inference. `history` works on
  Membership but is silently capped at 1,000 banners and 404s for some hosts
  that have data: `get_history` always states its window, never presents a
  first sighting as an opening, and cross-checks the 404.
- **Silent no-ops upstream are refused here.** Unknown filters become free
  text (0 results) and unknown facets are dropped, so names are checked
  against `/shodan/host/search/filters` and `/facets`; `vuln` and `tag` are
  refused (`plan_restricted`) because the restriction reads as a low count.
- **Host lookups do not check the key** (measured). Keep requiring and sending
  it; `get_quota` / `count_services` are where a wrong key shows.
- **Counts are services (banners), not hosts** — measured. Hence
  `count_services` / `search_services`.
- **Credits are guarded by the tool, not by an argument.** Only
  `search_services` / `search` spends them; the floor is checked on every call assuming a
  cost of 1, a failed check means no call, and a prediction/charge mismatch
  stops searching for the process.
- **A tool result must fit a client's budget, and the budget lives at the MCP
  boundary.** The engine returns complete views; the MCP layer compacts.
  Backstops (budget.go): any other string over 1000 characters is shortened
  and named, no result leaves over 128 KB. Section content (`Text`, `Items`,
  `Summary`) is exempt by name — a path that exists to return the whole text
  must. Thinning measures the encoding the ceiling measures (indented, after
  the backstop). The CLI's `--json` stays complete.
- **The cached unit is the upstream body**; every view is derived from it.
  Keys are `cache.Key` (hash over length-prefixed parts; inputs never appear
  in filenames). Never cached: the quota, `not_indexed`, degraded results. A
  TTL of 0 turns a kind's caching off.
- **Pacing is per process; the limit is per key.** Default 2000 ms, half the
  documented 1 req/s.
- **Third-party text travels as data** — banners and HTML are written by the
  investigated host. Tool text states that fact and carries no defensive
  imperatives (a test refuses them). Text output is made inert as a whole
  before rendering, not at each print site.
- **Fixtures are hand-written, never captured.** Do not commit Shodan
  responses, and never the IPs of hosts seen in measurement.
- **Attribution.** Shodan's terms §6.7 require attributing Shodan data
  included in your own materials; every result names its source. The README
  states non-affiliation with Shodan, LLC.
- **The documents are pinned to the code.** `internal/mcp/usage_test.go`
  requires every `Tool*` constant and every `Code*` constant in any package
  under `internal/` in `usage.md`. Which commands are unimplemented is read
  off the program's behaviour, and the usage text, both READMEs, the manual
  and the MCP instructions must say exactly that — in both directions.
- **No raw control or bidi character in any source file** (`source_test.go`).

## Where things are recorded

Measured upstream behaviour is in AGENTS.md (Gotchas) and RFP §7. The RFP
records the design decisions, the independent verification pass and the
reading of Shodan's terms. Versions are in CHANGELOG.md and `git tag`.

## Communication Language

All communication between contributors and Claude Code is conducted in
**Japanese**.
