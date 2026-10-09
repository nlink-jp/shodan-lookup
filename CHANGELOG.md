# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

### Added

- `host`, `service`, `count`, `quota` and the MCP tools `lookup_host`,
  `get_service`, `count_services`, `get_quota` (RFP Phase 1).
- `tokens` / `search` and the MCP tools `parse_query` / `search_services`
  (RFP Phase 2). `search` is the only path that spends query credits, and it
  is guarded by the tool: a cached page sends nothing; Shodan's own reading of
  the query (tokens, free) predicts the cost; the remainder is read and the
  search refused (`credit_floor`) if, counted as one credit whatever the
  prediction, it would cross `[search] credit_floor`; the remainder is read
  again afterwards, and a spend other than predicted — or one that cannot be
  read — stops searching for the process (`credit_mismatch`). The CLI prints
  what was spent on stderr; `search --raw` prints every banner of the page.
- The live e2e suite (`make e2e`): credit-free — the remainder is read
  before and after and any difference fails it — and it fails without a key
  instead of skipping. It pins the upstream traps the design rests on.
  `make e2e-credits` is the one check that spends a credit.
- `history` and the MCP tool `get_history`: per port, the first and last
  sighting and each variant (product, version, page title, certificate
  SHA-1) with when it was seen, inside a stated window — Shodan returns only
  the latest 1,000 banners, and the answer says when that cap was reached
  and which port filled it. A history 404 is cross-checked with a free
  count. `history --raw` prints every historical banner.
  - Internal addresses are refused before anything is sent, in IP arguments
    and in `ip:` / `net:` query values (`internal/ipaddr`).
  - The API key travels only in the query string and never appears in an
    error, a log, provenance or a cache file; redirects are refused.
  - A host 404 "No information available" becomes `not_indexed` only after a
    credit-free count confirms zero services; otherwise it is
    `upstream_error`.
  - Filter and facet names are checked against Shodan's own lists; `vuln`
    and `tag` are refused (`plan_restricted`).
  - Counts are reported in services, not hosts.
  - The certificate pivot is SHA-1: lookup_host reports `sha1`, and a
    SHA-256 given to `ssl.cert.fingerprint:` — which matches nothing without
    an error (measured) — is refused.
  - MCP answers are budgeted (services, banners after escaping, CVEs) with
    every drop counted in `omitted`; `get_service` pages every section in
    full with a `doc_id`.
  - Text output is made inert as a whole: banners are written by the host
    under investigation.
- `version` / `--version` / `-v` (identical output), `help`,
  `cache status` / `cache clear`, `mcp`, and the MCP tools `cache_status` and
  `get_usage`.
- Strict configuration: `[api]` / `[query]` / `[search]` / `[cache]` /
  `[network]` / `[limits]`, `SHODAN_LOOKUP_*` environment overrides and the
  `SHODAN_API_KEY` alias. Unknown sections and keys, keys outside a section
  (with directions for a bare `api_key`), present-but-empty values,
  out-of-range numbers and a missing explicit `--config` are refused by name.
  `base_url` must be https (plain http only on loopback) without credentials,
  query or fragment. A TTL of 0 turns caching off for that kind of answer.
- Cache entry names are a hash over length-prefixed parts, so no two part
  lists collide and investigated IPs and queries do not appear in filenames.
