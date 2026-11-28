# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- **The MCP tools run on the organization's tool-conventions module,
  nlink-jp/mcptool** (ADR-0002, organization ADR-031): arguments are decoded
  before a tool runs, and the server is run by mcptool's `serve.Run`. What an
  MCP client sees (the CLI is unchanged):
  - **Argument errors are `invalid_arguments`, naming the argument in
    `details.argument`**, in place of `invalid_argument` — whether the call
    was refused at decoding (an unknown or wrong-typed argument, now worded
    `unknown argument "…"` / `argument "…" must be …`), by a tool (an empty
    value, a range, a contradicting combination) or by the engine (an
    internal address, an unknown filter or facet, a port that needs
    `transport`). A required argument left out is `missing_argument`. The
    `get_usage` manual's recovery table has both rows.
  - Results are JSON on one line (no indentation), and `<`, `>` and `&` arrive
    unescaped (a banner's `&` no longer arrives as `\u0026`). The values are
    the same.
  - The response budget measures the result as it is sent, so more fits:
    fewer services, rows and facet values are thinned, fewer banners are
    shortened, and a result the 128 KB ceiling withheld may now be returned.
  - With several problems in one call, the first one reported may change
    (unknown → missing → type).

## [0.2.1] - 2026-11-28

### Fixed

- `cache clear` left behind the temp file a write leaves when the process ends part-way (a SIGTERM past the shutdown grace, a crash); it now removes it too, and counts entries only.

## [0.2.0] — 2026-11-28

### Added

- **The MCP server speaks both eras of the protocol** (ADR-0001): the
  2026-07-28 revision, whose clients probe with `server/discover`, as well as
  the earlier `initialize` handshake (2025-11-25, 2025-06-18, 2024-11-05; it was
  fixed at 2024-11-05). The protocol layer is now the organization's shared
  module nlink-jp/mcp (organization ADR-030); the tools, their arguments and
  their results are unchanged.

### Changed

- An unknown tool is now refused by the protocol (-32602) rather than returned
  as an `unknown_tool` tool result (with its hint to call `get_usage`); the code
  leaves the error vocabulary.
- Protocol details now follow the module:
  - `tools/list`, `tools/call` and unknown methods before `initialize` are
    refused with -32602 (an unknown method was -32601);
  - `arguments` that is not an object is refused with -32602;
  - a request with `"id":null` gets -32600 (`initialize`, `ping` and
    `tools/list` used to be answered with a null id), and so does one without
    `"jsonrpc":"2.0"`;
  - a batch gets -32600 (it was a parse error); a parse error is answered
    "parse error" without the decoder's detail;
  - a line over 16 MiB gets -32600 and reading goes on (it ended the server
    with an error);
  - a panic in a tool is answered -32603 and the server goes on (it crashed);
  - up to 256 calls wait behind a running one; more are refused with -32603
    "server busy";
  - `notifications/cancelled` now cancels the call.

  Requests piped in are still all answered before the server exits at end of
  input.

- `make vuln` — and so `make package` — scans every platform in `PLATFORMS`,
  with the environment `build-all` builds each with. It scanned the host's
  build alone, so an advisory in a Linux- or Windows-only package could not
  stop a release.

### Fixed

- An argument spelt in another case (`{"IP": ...}`, `"Ports"`) was accepted as
  the declared one; it is now refused by name.
- SIGINT or SIGTERM ended the MCP server by killing the process; a signal now
  ends it through its context, so its cleanup runs.
- A search whose call was cancelled — by `notifications/cancelled`, or at
  shutdown — no longer halts every later search for the process: the credits
  it spent are read even after the cancellation.

## [0.1.4] — 2026-11-14

### Security

- **Rebuilt with Go 1.27.4, which `go.mod` now requires** (it was `go 1.25.0`).
  No code of the tool changed. v0.1.3 was built with Go 1.27.2; `govulncheck
  -mode binary` finds 2 standard-library advisories in its darwin-arm64 binary,
  in `crypto/x509` and `net/http`: GO-2026-6809, GO-2026-6859. All are fixed by
  Go 1.27.4. Binary mode shows that an affected function is linked into the
  binary, not that the tool calls it; each advisory is described at
  `https://pkg.go.dev/vuln/<ID>`.

### Changed

- `make package` runs `govulncheck ./...` first (`make vuln`) and stops on a
  finding, so a release cannot be built past one.

## [0.1.3] — 2026-10-10

### Fixed

- `get_service` compares a port with what could be read of each service it
  left out. Once any service was left out it answered `decode_error` for
  every port without a readable service; now a service whose port was read
  rules itself out of other ports (`not_observed` is answered as usual), a
  service whose transport was read rules itself out of the other transport,
  and a port asked without a transport that also holds a service whose
  transport could not be read is ambiguous ("pass transport") instead of
  answering the one readable service as if it were the only one.

## [0.1.2] — 2026-10-10

### Fixed

- A value of an unexpected type anywhere in a host record, a history, a
  search page or a count — a status, a CVSS score, a favicon hash, a facet
  count, a list element — no longer fails the whole answer, and the cache
  and `--raw` with it. The value is left out, never turned into a zero, and
  `notes` name its path (`data[].http.status (1)`); `--raw` returns the
  document as sent. An entry whose identifying field cannot be read (a
  service's port or transport, a match's address, a facet value's count) is
  left out whole rather than shown as port 0 or count 0 — whether it is of
  another type, null or missing — and `get_service`
  then answers `decode_error` instead of `not_observed` for a port it may
  hold. A count whose breakdown could not be read was cached and failed for
  the cache's lifetime; it now answers. Still `decode_error`: a body that is
  not a JSON object, a host record whose services or a search answer whose
  matches are not a list, and a search or count without a numeric total. A
  history window and its 1,000-banner cap count every banner Shodan
  returned, the ones left out included. v0.1.1 handled the string fields
  only.

## [0.1.1] — 2026-10-10

### Fixed

- A host record whose `asn` arrived as a number (`2497`) failed as a whole
  with `decode_error` — `--raw` included. Shodan does not hold its scalars to
  one type: the same record carried `2497` and `"AS2497"` (measured). The
  string fields the tool reads (org, isp, asn, country, city, os, product,
  version, HTTP title/server/location/html) now accept a string or a number,
  and a bare AS number is written `AS2497` in the projection (`lookup_host`,
  `--json`); `--raw` keeps Shodan's own value.

## [0.1.0] — 2026-10-09

First release: a read-only CLI and local MCP server answering what an IP
address exposes to the Internet, from the Shodan REST API with the
operator's own key.

### Added

- **Lookups** — `host`, `service`, `count`, `quota` and the MCP tools
  `lookup_host`, `get_service`, `count_services`, `get_quota`.
  - A host 404 "No information available" becomes `not_indexed` only after a
    credit-free count confirms zero services; otherwise it is
    `upstream_error` — Shodan also answers it for records it fails to return.
  - Counts are reported in services (banners), not hosts.
  - Filter and facet names are checked against Shodan's own lists before
    sending (an unknown filter would match nothing, an unknown facet would be
    dropped); `vuln`, `tag`, `has_vuln` and `vuln.verified` are refused
    (`plan_restricted`), since on Membership the restriction reads as a low
    count.
  - The certificate pivot is SHA-1: lookup_host reports `sha1`, and a SHA-256
    given to `ssl.cert.fingerprint:` — which matches nothing without an error
    (measured) — is refused.
- **History** — `history` and the MCP tool `get_history`: per port, the
  first and last sighting and each variant (product, version, page title,
  certificate SHA-1) with when it was seen, inside a stated window — Shodan
  returns only the latest 1,000 banners, and the answer says when that cap
  was reached and which port filled it. A history 404 is cross-checked with a
  free count. `history --raw` prints every historical banner.
- **Search** — `tokens` / `search` and the MCP tools `parse_query` /
  `search_services`. `search` is the only path that spends query credits,
  and the tool guards it: a cached page sends nothing; Shodan's own reading
  of the query (tokens, free) predicts the cost; the remainder is read and
  the search refused (`credit_floor`) if, counted as one credit whatever the
  prediction, it would cross `[search] credit_floor`; the remainder is read
  again afterwards, and a charge other than predicted — or one that cannot be
  read — stops searching for the process (`credit_mismatch`). A failure that
  was not charged does not stop it. The CLI prints what was spent on stderr;
  `search --raw` prints every banner of the page.
- **Safety**
  - A non-public IP address is refused before anything is sent, wherever it
    appears in an argument or a query (IPv6 is an allow-list of 2000::/3;
    embedded IPv4 is judged; terms may be separated by ASCII spaces and tabs
    only). Names cannot be judged and are the documented residual.
  - The API key travels only in the query string and never appears in an
    error, a log, provenance or a cache file; redirects are refused;
    `base_url` must be https (plain http only on loopback).
  - MCP answers are budgeted — services, banners after escaping, CVEs, names,
    facet values and search rows — and every drop is counted in `omitted`;
    `get_service` pages every section in full with a `doc_id`.
  - Text output is made inert as a whole: banners are written by the host
    under investigation.
- **Configuration** — `[api]` / `[query]` / `[search]` / `[cache]` /
  `[network]` / `[limits]`, `SHODAN_LOOKUP_*` environment overrides and the
  `SHODAN_API_KEY` alias. Unknown sections and keys, keys outside a section
  (with directions for a bare `api_key`), repeated keys or sections,
  unclosed quotes, present-but-empty values, out-of-range numbers and a
  missing explicit `--config` are refused by name. A TTL of 0 turns caching
  off for that kind of answer. Cache entry names are hashes, so investigated
  IPs and queries do not appear in filenames.
- **Testing** — the live e2e suite (`make e2e`) is credit-free by proof (the
  remainder is read before and after) and fails without a key instead of
  skipping; it pins the upstream traps the design rests on.
  `make e2e-credits` is the one check that spends a credit.
- `version` / `--version` / `-v` (identical output), `help`,
  `cache status` / `cache clear`, `mcp`, and the MCP tools `cache_status` and
  `get_usage`.
