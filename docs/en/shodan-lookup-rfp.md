# RFP: shodan-lookup

> Generated: 2026-10-09
> Status: Approved (2026-10-09). Revised the same day after the design-freeze independent verification pass;
> see "Revision after the independent verification pass" in the Discussion Log.
> Translation of `docs/ja/shodan-lookup-rfp.ja.md` (the Japanese version is primary)

## 1. Problem Statement

In incident response, a suspicious IP raises one question: what does that host expose to the Internet? That means its open ports, the product and version behind each one, its TLS certificates, its inferred vulnerabilities, and when each was observed. No tool in the lookup fleet answers that. asn and whois return the owner, abuse returns the report history, and rdns and doh return names. None of them describes the services.

Shodan scans continuously and indexes exactly this, and querying it sends no packet to the target. Its official clients, however, are a Python library and CLI. They fit neither the organisation's rule (no community or third-party wrappers) nor the lookup fleet's conventions (single Go binary, CLI plus MCP, structured errors, response budgets).

We therefore implement a **read-only** CLI plus MCP server over the Shodan REST API, in the lookup fleet's style. The target users are the organisation's IR workflows: Claude Code, gem-agent and lagent through mcp-tactics, and the CLI in pipelines. The operator holds a Shodan Membership and also uses it for business when handling incidents.

## 2. Functional Specification

### Commands / API Surface

**MCP tools**:

| Tool | Upstream | Credits | Phase |
|---|---|---|---|
| `lookup_host(ip, ports?, ports_only?, refresh?)` | `GET /shodan/host/{ip}` | none | 1 |
| `get_service(ip, port, transport?, section, offset?, limit?, refresh?)` | same (derived from the host body) | none | 1 |
| `count_services(query, facets?, refresh?)` | `GET /shodan/host/count` | none (measured) | 1 |
| `get_quota()` | `GET /api-info` | none | 1 |
| `parse_query(query)` | `GET /shodan/host/search/tokens` | none (measured) | 2 |
| `search_services(query, facets?, refresh?)` | `GET /shodan/host/search` | 0 or 1 (below) | 2 |
| `cache_status()` | — | — | 1 |
| `get_usage()` | — | — | 1 |

**Counts are in services (banners), not hosts.** One Shodan search result is one banner on one port of one IP, not a host. An IP with two matching services counts as 2, and its `ip` facet value is 2 as well (measured). That is why the tools are named `count_services` and `search_services`. Neither counts nor facets may be read as host counts.

**Default projection of `lookup_host`**: one upstream record measured from 19 KB to 991 KB. The default response is held to tens of KB.

- Host attributes: `ip`, `org`, `isp`, `asn`, `country_code`, `city`, `hostnames`, `domains`, `os`, `tags`, `last_update` and `ports`.
- `services[]`, in ascending port order and then by transport within a port:
  - identity: `port`, `transport`, `module` (`_shodan.module`) and `timestamp`
  - product: `product`, `version` and `cpe23`
  - `http`: status, title, server and location
  - `ssl`: subject CN, issuer CN, not_before, not_after, sha256 and versions. Whether the certificate has expired is **computed at query time**, not taken as the observation-time value, and is returned together with the reference time used.
  - `banner`: the head of `data`, capped in **bytes after escaping** (512 B by default)
  - `favicon_hash`, kept for pivoting; the image data itself is never returned
  - `tags` and `vuln_count`
- `vulns[]`: only the CVE ID, `cvss`, `cvss_version`, `epss` and `verified`. The top N by cvss, descending with ties broken by CVE ID (25 by default), are listed, plus the total. Summaries and references are left out; cve-lookup supplies the details.
- `services` is capped at 50 by default, and `ports` restricts the result to the named ports.
  - A requested port that Shodan has not observed is reported explicitly as not observed, never as an empty list, so it cannot be read as closed.
  - `ports_only` drops services, leaving only the attributes and ports.
- `provenance`: the source (`shodan`), the fetch time, whether the cache answered, and the `doc_id` (below). **It never contains the request URL.**
- Omission counts per section, with a plain-language note, appear only when something was dropped.
- When the result approaches 128 KB, services are reduced and the reduction counted before the whole result would be withheld.

**`get_service`** reaches the full content of one service, section by section with paging.

- The sections are `banner`, `http_html`, `http_headers`, `ssl_chain`, `ssl_cert` and `vulns`. The `vulns` section includes summaries and references, in a fixed CVE ID order.
- Text pages by characters and lists page by items, through `offset` and `limit`.
- The host body is read from the cache and **fetched when absent or past its TTL**. `refresh` forces a refetch.
- The response carries a hash of the body as `doc_id`, so a caller paging through the body can tell from a changed `doc_id` that the base moved (knowledge: mcp-server-design, document ids).
- When a port has both tcp and udp (measured on port 53) and `transport` is omitted, the call fails with `invalid_argument` and lists the candidates.
- The text a section returns is **exempted by name** from the safety net's string shortening (§3). A path that exists to reach the full text must be able to return it.

**`count_services`** returns the total and the facet breakdowns. `facets` is a list of `name[:N]` and may include `ip`.

- The result field names and `get_usage` state that `total` is the number of matching services, and that each facet value is the number of matching services carrying that value (IP or otherwise).
- Facets return **only the top N**. The overall number of IPs is not returned.
- An `ip` facet yields the top IPs by matching services without spending credits, so it is the main pivot path instead of search. It is not called "the full IP list".
- The maximum N is measured in Phase 1.

**`search_services`** (Phase 2) returns one page, at most 100, of the services matching a query. Rows use a compact projection: ip, port, transport, org, product, version, hostnames, timestamp, http title and vuln_count. Credits are handled as follows:

- **The floor is checked on every call, assuming a cost of 1 whatever the prediction.** The tool reads the remaining credits from `/api-info` (no credit). If the remainder minus 1 falls below `credit_floor` (default 20), it refuses with a `credit_floor` error without calling. A wrong prediction from tokens therefore cannot bypass the floor.
- If either the `/api-info` or the tokens query fails, the search is not called (fail-closed).
- One call spends at most one credit. Whether pages 2 and later are supported is decided after Phase 2 measures how they are counted. The documentation does not say whether page 2 of a filtered query costs one credit or two.
- The result carries `credits`, re-read from `/api-info` **after** the call.
- **If the actual decrease after a call disagrees with the tokens prediction**, the process refuses further searches (`credit_mismatch`) and records the discrepancy in the result. It does not keep trusting the prediction.
- Phase 2 measures three things (§4): which field holds the remainder (`query_credits` or `unlocked_left`), how long a charge takes to appear in `/api-info`, and races between processes sharing a key. Whatever stays open after measurement, such as the cross-process race, is written in AGENTS.md as a residual with its reason.

Every upstream-reading tool accepts `refresh?: bool`; `get_quota` always fetches. The CLI equivalent is `--refresh`.

**CLI** (mirrors MCP):

```
shodan-lookup host <IP>... [--port N]... [--ports-only]
shodan-lookup service <IP> <PORT> [--transport tcp|udp] --section S [--offset N] [--limit N]
shodan-lookup count <QUERY> [--facet NAME[:N]]...
shodan-lookup quota
shodan-lookup tokens <QUERY>                       # Phase 2
shodan-lookup search <QUERY> [--facet NAME[:N]]... # Phase 2
shodan-lookup cache status|clear
shodan-lookup mcp
shodan-lookup version
```

Every upstream-reading command except `quota` accepts `--refresh` and `--json` / `--raw`. During implementation, a single matrix maps MCP arguments to CLI flags, and the CLI synopsis and `usage.md` are written from it (the web-fetch / brave-search approach).

### Input / Output

- Input is one query per argument, from one to a few dozen. Bulk lookup (the Corporate-only batch IP lookup) is out of scope.
- **IPs are validated before anything leaves the machine.** IPv4 or IPv6, global unicast only. Refused with `invalid_argument`:
  - private, loopback, link-local, documentation (TEST-NET) and CGNAT addresses
  - non-global addresses embedded in 6to4, NAT64 or Teredo

  Shodan never observes these, so the answer would always be "not indexed". More importantly, **internal addresses are never sent to a third party**, because every query is tied to the account. Upstream answers 404 both for invalid IPs and for unindexed ones (measured), so the distinction is made here.
- **The same gate applies to search queries.** Addresses and CIDRs in the queries of `count_services`, `parse_query` and `search_services`, such as `ip:` and `net:`, are extracted lexically, and a query containing a non-global one is refused before sending. `parse_query` itself sends the query to Shodan, so it is no substitute for the local check. Internal names in `hostname:` or `org:` cannot be detected lexically; `get_usage` states this residual as fact.
- Hostnames are not accepted; resolving a name is doh-lookup's job. Shodan's `/dns/resolve` is not used.
- Human-readable text by default, JSON on stdout with `--json`, and diagnostics on stderr.
- **`--json` is complete; only MCP responses are capped.** `--raw` prints the upstream body unchanged.
- Exit contract: 0 = query completed, 1 = upstream failure or incomplete answer, 2 = usage error.
- MCP tool errors are structured JSON, `{code, message, details?}`. The codes include at least the following.
  - Input: `invalid_argument`, and `bad_request` (a query upstream rejected with 400).
  - Credentials: `missing_api_key` (no key, so configure one) and `auth_failed` (the key was refused, so fix it). They are separate because the recoveries differ.
  - Negative answer: `not_indexed`.
  - Plan and credits: `plan_restricted`, `credit_floor` and `credit_mismatch`.
  - Upstream and transport: `rate_limited`, `endpoint_unavailable`, `upstream_error`, `timeout`, `network_error` and `decode_error`.
  - Other: `response_too_large` and `internal_error`.
- **MCP arguments are decoded strictly.** An undeclared argument is refused by name with `invalid_argument`. A misspelt `ports` that was silently ignored would make every service look like a filtered result.
- **Text output escapes control characters in upstream strings into a visible form.** The escaping runs once over the whole result before rendering, not at each output site (cve-lookup correction 22). Banners and HTML are written by the investigated host itself, so terminal escapes must not pass through.

### Configuration

- `config.toml` (sectioned TOML), overridden by `SHODAN_LOOKUP_*` environment variables. The search order is `$XDG_CONFIG_HOME/shodan-lookup/`, then `~/.config/shodan-lookup/`, then, on macOS only, `~/Library/Application Support/shodan-lookup/`. `cache status` shows the path actually read, or the places searched when none was found.
- Sections:
  - `[api]`: `key` and `base_url`
  - `[query]`: `default_services` (50), `default_vulns` (25) and `banner_bytes` (512)
  - `[search]`: `credit_floor` (20)
  - `[cache]`: `host_ttl_hours` (12), `count_ttl_hours` (1), `search_ttl_hours` (24) and `dir`. A TTL of 0 disables caching for that kind.
  - `[network]`: `timeout_seconds`
  - `[limits]`: `min_interval_ms` (2000)
- The key can be overridden with `SHODAN_LOOKUP_API_KEY`. `SHODAN_API_KEY`, a variable name commonly used by Shodan users, is also accepted as an alias, as gti-lookup accepts `VT_APIKEY`.
- **`base_url` must be https**, with plain http allowed only on loopback for tests. Values carrying userinfo, a query or a fragment are refused, so the key never rides a plaintext channel. `base_url` comes only from the operator's configuration, never from tool arguments.
- **Input the tool does not understand is refused, never ignored.**
  - Unknown sections and keys are errors that name the offender.
  - A key present in the file counts as given, so an empty `""` is refused by name.
  - A missing `--config` path is an error.
  - Numbers are accepted only within range (cve-lookup correction 24).
  - Note: the file placed for the 2026-10-09 measurements uses a top-level `api_key`. The implementation will refuse that form, so the operator should move the value to `key` under `[api]`.
- **Loading succeeds without a key**, so the cache, the MCP handshake and `get_usage` still work. Queries check for the key and answer `missing_api_key` when it is absent.
- **The default pacing is one request per 2000 ms, half the documented limit (1 req/s).** The limit is per key (per account), while pacing is per process: CLI loops and MCP servers in several runtimes draw on the same key without seeing each other (the same point corrected in cve-lookup's verification).
- **The cache stores the upstream body itself.** Its key is a length-prefixed hash of the endpoint and the normalised arguments. Projections, section paging, `--json` and `--raw` are all views derived from it.
- Not cached:
  - `get_quota`, because it is account state (a gti-lookup lesson)
  - `not_indexed` answers
  - degraded results
  - `parse_query`

  `refresh` skips the cache read, refetches and overwrites the entry.
- `search_services` has a long TTL (24 h) so the same question never spends credits twice.

### External Dependencies

- The Shodan REST API (`https://api.shodan.io`) only. Authentication is the `key` query parameter; no other mechanism exists.
- The Go standard library only: no `require` lines in `go.mod`, no MCP SDK and no Shodan library.

## 3. Design Decisions

- **Go with zero dependencies**: the lookup fleet's convention and the organisation's rule. The tool joins the existing signing, notarisation and tap pipeline.
- **Skeleton**: the lookup fleet's mirror layout, `internal/{ipaddr, shodan, cache, config, engine, app, mcp}`.
  - **For each package, compare `git log -1 --format=%ci -- internal/<pkg>` across siblings and take the newest.** Repository HEAD dates are useless for this, because sweeping fix commits align them: as of 2026-09-23, the five siblings and brave-search share the same day.
  - No sibling has `internal/ipaddr`, so it is written new. It starts from the closed table in util-series/web-fetch `internal/guard`, adds the three TEST-NET ranges and addresses embedded in 6to4, NAT64 and Teredo, and is tested row by row.
  - AGENTS.md records which package came from where.
- **Name `shodan-lookup`**: the upstream is mature and the data is unique to Shodan. Like urlscan, otx and gti, the tool carries the source's name.
- **A boundary that keeps the tool's reason to exist** (as in otx-lookup): what only this tool can supply is open ports, banners, CPEs, certificates, inferred CVEs and observation times. Features that collide with other tools are left out.

  | Shodan feature | Owner | Treatment |
  |---|---|---|
  | `/dns/domain`, `/dns/resolve`, `/dns/reverse` | rdns-lookup / doh-lookup | not included |
  | geo, org, ASN | asn-lookup / whois-lookup | shown as host attributes only |
  | CVE details (summary / references) | cve-lookup | ID and scores by default; full text only in the `vulns` section of `get_service` |

- **Neither the API key nor the request URL appears on any output surface.** The key travels only in the query string. The invariant: the request URL appears in no error message, log, `provenance`, `details`, cache key or cache file.
  - Go's `*url.Error` embeds the full URL in its message, so every error the upstream client returns is rewrapped with a redacted URL.
  - **All redirects are refused.** When Go follows a redirect, a Location that keeps the query is sent on as is, even to another host or to http. With the key in the query, there is no reason to follow one.
  - `base_url` must be https (§2).
  - Tests pin that no output surface contains the key on any path: timeout, connection refusal, TLS failure and redirect (knowledge: security, the sections on url.Error and on credentials following redirects).
- **Negative answers are never misread.**
  - 404s are mapped by body shape, not by status.
    - `{"error": "No information available for that IP."}` becomes `not_indexed`, worded as "not in Shodan's index (not observed)", never as "ports are closed" or "safe".
    - `{"error": "Invalid IP"}` becomes `invalid_argument`. That happens when the local gate and upstream disagree, which IPv6 notation could cause.
    - A 404 of neither shape becomes `endpoint_unavailable`.
  - **Why `history` is excluded.** On a Membership key, `history=true` returned that same 404 "No information available" for two IPs that have data (measured, n=2): 8.8.8.8 and 1.1.1.1, both large anycast services. The cause is presumed to be plan entitlement but is unconfirmed by documentation. Together with the rule that untestable features are not shipped (the gti-lookup precedent), the suspicion that a missing entitlement turns into "no records" excludes it.
  - An empty `vulns` does not mean "no vulnerabilities". Shodan infers vulnerabilities from banner versions, and `verified: false` marks an inference; all 138 were false in measurement. `get_usage` states this as fact. Inferred CVEs are not presented as confirmed either: positive answers must not be misread as well.
  - Each service's `timestamp` is an observation time, not the current state, and the projection makes the age since observation explicit. `timestamp` and `last_update` carry no time-zone suffix, however, so no age is computed until UTC is confirmed by documentation or measurement (§4 Phase 1).
  - A bad key yields 401 with a **text/plain, non-JSON** body (measured on `/api-info`). It maps to `auth_failed` and must not turn into a `decode_error` from an attempt to parse JSON. When a search-family endpoint returns 401, the tool re-reads the credit-free `/api-info` to tell a bad key from exhausted credits or a missing entitlement (knowledge: development-process, "overruns may come back as 401").
  - **The mapping of plan restrictions (such as the `vuln` and `tag` filters) and of non-JSON 403s waits until Phase 1 measures their shape.**
    - cve-lookup's "non-JSON 403 means `rate_limited`" came from an upstream behind a WAF. For Shodan it could suggest the wrong recovery, "wait and retry".
    - Once measured, they get codes such as `plan_restricted`, and must read neither as "no results" nor as "wait".
- **The response budget covers the whole response.**
  - The default is a compact projection, and large sections page through `get_service`. Omissions are counted only when they happen.
  - Two safety nets sit behind that (cve-lookup correction 23):
    - Any other string over 1000 characters is shortened with its field name noted. The text returned by `get_service` sections is exempted by name.
    - A result over 128 KB is withheld as `response_too_large`. `lookup_host` first reduces services and counts the reduction.
  - Banners are capped in bytes after escaping: a banner of control characters grows sixfold in JSON, and 50 of them could exceed 128 KB.
  - Nothing is spilled to files on the server side.
- **The budget lives at the MCP boundary, not in the engine.** The engine returns the full projection and section accessors, and the MCP layer applies the caps. This keeps the CLI's `--json` complete.
- **Third-party text is carried as data.**
  - Banners, HTML, certificate subjects and HTTP headers are strings **written by the investigated host itself**, the most adversarial input in the index.
  - They travel only as JSON fields. `get_usage` and `instructions` state the fact that the target wrote them, with no defensive instructions to the model (knowledge: mcp-server-design).
  - Banners are shortened by default for the budget, and the tool does not claim that as a defence.
- **Showing the source supports the operator's obligation.** Terms §6.7 requires that Shodan information included in your own materials be attributed to Shodan, with Shodan's ownership and copyright clearly indicated. Pasting results into an IR report is such a case.
  - Every result's `provenance` therefore always names `Shodan`, and CLI text output carries a source line.
  - README and `get_usage` state the attribution duty as fact.
- **Name and trademark.** Terms §10.2 grants no right to Shodan's marks, and §10.6 forbids uses that confuse ownership. `shodan-lookup` names the service it reads, descriptively, as the urlscan, otx and gti lookups do. The README opens by stating that the tool is not affiliated with or endorsed by Shodan®, LLC.
- **One credit-spending path, guarded by the tool.**
  - Only `search_services` spends credits.
  - The floor is checked on every call without relying on the prediction. A failed lookup means no call, and a mismatch between prediction and actual cost stops searching (§2).
  - A tool-side check, not an argument-level promise, stops a model from autonomously spending the month's 100 credits (knowledge: mcp-server-design, "read-only calls can still have a billing side effect").
- **OpSec**: queries read a third-party index and send no packet to the target. They are, however, **attributed to the operator's Shodan account**, so Shodan learns which IPs and which search terms were investigated. `get_usage` says so. Internal addresses are refused before sending, in IP arguments and inside queries alike (§2).
- **Complementary role.** The IP order in mcp-tactics follows the attribution axis: anonymous lookups are used up first, and account-attributed, metered ones come last.
  - The current order is asn, then tor-exit and icloud-relay, then rdns, then whois, with abuse-lookup last as the only metered one.
  - shodan-lookup is also account-attributed and credit-bearing, so it sits **at the tail beside abuse-lookup**.
  - Inferred CVEs continue to cve-lookup (how bad, whether exploited). Certificate and favicon hashes pivot through `count_services` facets.
- **Explicitly out of scope**:
  - Permanently:
    - Active scanning (`POST /shodan/scan` and `/shodan/scan/internet`), which has Shodan probe the target.
    - Every write feature: alerts, notifiers and organisation members.
    - `/tools/myip` and `/tools/httpheaders`, which describe our own side and serve no investigation.
    - InternetDB, which is free only for non-commercial use and so does not fit business use (operator decision).
  - For now:
    - `history`, a suspected false negative on Membership.
    - The `vuln` and `tag` filters (Small Business and above, and Corporate only).
    - Batch IP lookup (Corporate only).
    - The Streaming, Trends and Exploits APIs, the saved-query directory and dataset downloads.
    - `/dns/*`, per the boundary in §3.

## 4. Development Plan

### Phase 1: Core

- Scaffold mirroring the siblings: `make build`, `test` and `check`, the version and help contract, and exit 2 for unimplemented commands.
- The core packages:
  - the `ipaddr` gate, applied to IP arguments and to query tokens
  - the `shodan` client: key secrecy, redirect refusal, pacing, error classification and non-JSON responses
  - the TTL cache and the strict config
  - the engine: projection, section accessors, `doc_id` and translation of negative answers
- Six MCP tools (`lookup_host`, `get_service`, `count_services`, `get_quota`, `cache_status` and `get_usage`) and the mirroring CLI.
- Offline tests, using httptest with an injected Doer and clock:
  - No output surface contains the key, on any failure path or redirect.
  - All three 404 shapes (not indexed, invalid IP, not API-shaped) and the text/plain 401.
  - A 1 MB host projects within budget; the services cap is applied and counted. Fifty banners of control characters do not get the result withheld.
  - Banners carrying control and bidi characters.
  - Internal addresses are refused, in IP arguments and in query `ip:` / `net:`; undeclared MCP arguments are refused.
  - `get_service`: an ambiguous transport, a port Shodan has not observed, and a `doc_id` that changes while paging.
  - A meta-test pins `usage.md` to the code.
- **Fixtures are hand-written synthetic data only.** No captured responses are committed. Commits to a public repository cannot be withdrawn, and Shodan's redistribution terms are unconfirmed (§7). The IP of the vulnerable host seen in measurement is not recorded either.
- **Credit-free measurements before implementation**, recorded with dates and the provenance of each probe input in AGENTS.md Gotchas:
  - The 404 for a **global unicast IP that is not indexed**. The `not_indexed` body in §7 came from TEST-NET, a range the tool refuses before sending.
  - `history=true` on several IPs that have data, to see whether two observations generalise.
  - The 401 shape on each endpoint: host, count and tokens.
  - The shape of plan-restriction responses (for example `count_services` with `vuln:`), and whether non-JSON 403s occur.
  - How `count` and `facets` handle an invalid filter, an unknown facet name and an unknown argument: 400, or silent ignore?
  - The maximum facet N, and what happens past it.
  - The time zone of `timestamp` and `last_update`: is it UTC?
  - The shape of an IPv6 host, any disagreement between the local gate and upstream, and the size of a host with many services (hundreds of ports).
  - The 429 shape is not measured: that would need deliberately exceeding the documented limit. Only 429 is treated as `rate_limited`.

### Phase 2: Features

- `parse_query`, and `search_services` with the credit check.
- **Credit-spending measurements happen only after the expected cost is stated and approved.** The expectation is **at most 4 credits**: 1 for page 1 of a filtered query, 1–2 for page 2 of a filtered query, and 0–1 for a facets-only search. They confirm:
  - what page 1 of a filtered query costs (expected 1), what page 2 of a filtered query costs, and what a facets-only search costs
  - whether the tokens prediction matches the actual charge
  - which field holds the remainder (`query_credits` or `unlocked_left`), and how long a charge takes to appear in `/api-info`
- Codified e2e behind the `e2e` build tag.
  - The default e2e runs only credit-free queries.
  - Credit-spending e2e sits behind a separate tag and does not run under `make e2e`.
  - **`make e2e` fails without a key, reporting that it did not run.** It must not pass by skipping (knowledge: testing, "a release gate that skips is a gate that passes"; cve-lookup correction 26).

### Phase 3: Release

- README.md and README.ja.md cover:
  - non-affiliation with Shodan®, LLC
  - what Membership can do, and how credits work
  - that counts are in services
  - the duty to attribute results included in your materials (Terms §6.7)
  - that the reading of the terms is not legal advice

  Also CHANGELOG.md and AGENTS.md.
- **Release gate: re-checking the terms of use.** The terms were read on 2026-10-09 (§7), and they can change without notice (§20). Before release, compare the sha256 of `https://static.shodan.io/legal/terms.html` with the value in §7; if it changed, re-read the terms and update §7. If a clause forbidding caching appears, the default TTLs become 0 (the util-series/brave-search precedent, whose terms forbade disk caching).
- Independent verification passes at design freeze and before release.
- `make build-all`, then signing and notarisation, verify-release and homebrew-tap.
- The umbrella (cybersecurity-series) submodule, the org profile and the nlink-web-site cards (EN/JA).
- **Follow-through in mcp-tactics**:
  - Conditional existence: the server exists only where a key exists. The opening of SKILL.md, which says only gti-lookup is conditional, is rewritten for two conditional servers.
  - In the IP order, it sits at the tail beside abuse-lookup (§3, complementary role).
  - A row is added to the references table (playbook); tests/check-fleet.sh enforces it.
  - The description is 1,015 characters, only 9 under the 1,024 limit. Decide what to cut before adding trigger words.
  - The fleet count is redone from the actual repositories.
- Knowledge feedback: no new type. Append the `history` case, as far as Phase 1 confirms its cause, to the existing testing.md section "an external API's vocabulary and visibility change with the licence tier". check-org.sh green.

Each phase can be reviewed independently.

## 5. Required API Scopes / Permissions

- A Shodan API key, Membership or above. No OAuth and no IAM.
- Needed: host lookup and counts (measured to work on Membership), and search within Membership's 100 query credits per month.
- Scan credits are not used, because active scanning is excluded.
- The key carries the operator's account authority, and every query is recorded against that account. The config file is kept at mode 0600, and the repository's `.gitignore` excludes `config.toml`.

## 6. Series Placement

Series: **cybersecurity-series**
Reason: a sibling of the lookup fleet, doing read-only IP enrichment. It joins the series conventions unchanged: CLI plus MCP, structured errors, a TTL cache, `get_usage` and explicit OpSec. It adds exposure to the IP layer's owner, reputation and name.

## 7. External Platform Constraints

Measured on 2026-10-09 (17 credit-free calls) unless stated otherwise; credits were 100 before and after, so none were spent. The independent verification recounted the figures from the raw response files and confirmed them. Re-verify in a year.

- **Plan**: `/api-info` reports `plan: "dev"`, which is Membership: 100 query credits a month, 100 scan credits a month and 16 monitored IPs, matching the pricing page. The logged-in membership page (a PDF the operator supplied on 2026-10-09) confirms it. Under Membership it ticks "IP lookups", gives the API plan as 100 query and 100 scan credits a month, and excludes only the `vuln` and `tag` filters. This is the primary source that Membership can look up hosts; until then the only evidence was secondary, Microsoft's integration docs.
- **Credits**: host lookup, `count` (filtered, `facets=ip:3` included) and `tokens` spent none. Search costs 1 credit when it uses a filter or requests page 2 or later (documented). Credits reset at the start of each month.
- **Unit of counts**: the `count` `ip` facet value was the number of matching services on that IP. An IP with two matching services, on ports 80 and 443, had the value 2.
- **Rate**: 1 req/s on all plans (pricing page). Responses showed no rate-limit headers; headers were not saved, so this rests on the run's printed output.
- **Authentication**: the key goes only in `?key=`; the OpenAPI document declares no securitySchemes. A bad key yields 401 with an HTML-like plain-text body (seen on `/api-info` only).
- **404 carries two meanings**: `{"error": "Invalid IP"}` and `{"error": "No information available for that IP."}`. The latter came from TEST-NET 192.0.2.1; a global unicast IP that is not indexed is unmeasured.
- **`history=true`**: on a Membership key, both 8.8.8.8 and 1.1.1.1, which have data, returned the 404 "No information available" (n=2; cause presumed to be entitlement, unconfirmed by documentation).
- **Response sizes** (bytes after JSON serialisation):
  - 8.8.8.8: 19 KB, 3 services (53/tcp, 53/udp, 443).
  - 1.1.1.1: 316 KB, 16 services on 15 ports, up to 92 KB in one service. The dominant terms are `http.html` (59 KB) and `http.favicon.data` (21 KB).
  - A vulnerable Apache host: 991 KB, 4 services and 138 CVEs. Two services, ports 80 and 443, each carry the same 225 KB `vulns`, 450 KB in total.
  - `minify=true` returns `data: []` at 475–596 B.
- **Vulnerability shape**: the host-level `vulns` is an array of CVE IDs. The in-service `vulns` is a dict keyed by ID, holding cvss, cvss_v2, cvss_version, epss, ranking_epss, references, summary and verified. In one service, 22 summaries exceed 1000 characters, the longest 2,635.
- **API size**: the OpenAPI document has 37 paths and 45 operations.
- **Terms of service**: `https://static.shodan.io/legal/terms.html`, located by the operator and read in full on 2026-10-09. Its sha256 was `baf5949206cbb07d0f296cfc4dded2ba2ba9fa32c98dc2dc4d94d2b33d837102`, with `Last-Modified: Sun, 10 Aug 2025 08:17:01 GMT`. What follows is a reading of the clauses, not legal advice. The text is not redistributed, and no copy goes into the repository.
  - **Caching**: no clause governs storing responses or how long they may be kept. §6.5 forbids reproducing, copying, selling or reselling the Services. A cache that briefly keeps responses on the operator's machine is read as outside that clause. The TTL-bound local cache stays, as does the rule that data lives nowhere but the local cache.
  - **Attribution (§6.7)**: Shodan information included in your own materials must be attributed to Shodan, with its ownership and copyright indicated. As §3 says, results always carry the source.
  - **Commercial use**:
    - The only non-commercial clause covers accounts granted Academic or Research access (§6.8). No clause limits a purchased Membership to non-commercial use.
    - §21.2 calls the Terms the whole agreement. The pricing table's "Commercial Use" listing still disagrees, but the terms contain no wording that forbids business use.
    - This assumes the operator's account is a purchased Membership, not an academic upgrade.
  - **Automated means (§6.3)**: the clause asks users not to access the Services other than through the interface Shodan provides, nor through automated means such as scripts or crawlers. The API is an interface Shodan itself provides, and the membership page invites using it from scripts and tools, so the clause is read as aimed at automated access to the website. The tension in the wording is recorded as a residual.
  - **Limits (§5.5)**: Shodan may set fixed transmission limits at any time. Pacing and the credit floor assume this.
  - **Software licence (§11)**: reverse engineering Shodan-provided software is forbidden. This tool is written from the public API documentation and uses no Shodan software, so the clause does not apply.
- InternetDB (no key) is free only for non-commercial use; commercial use needs an Enterprise licence (official page). It is not adopted, per §3.

---

## Discussion Log

- **Origin**: the operator asked whether we could build an MCP server that reads Shodan data through the Shodan API (2026-10-09).
- **Existing material**: neither memory nor the organisation's repositories had a Shodan precedent or rejection record. The design references were:
  - abuse-lookup: API key and quota.
  - urlscan-lookup: separating active from passive.
  - otx-lookup: the reason-to-exist boundary and the response budget.
  - gti-lookup: trimming features to the tier; account state is never cached.
  - cve-lookup: its full set of post-RFP lessons.
- **Primary sources**: the API reference and OpenAPI document (37 paths, 45 operations), the pricing page, the credits explainer, InternetDB and the Shodan Book. The only source contrasting Membership with a free key was secondary, Microsoft's integration docs.
- **Operator decisions**: Membership is held and also used for business when handling incidents. InternetDB is excluded.
- **Measurement came before the RFP**, applying the rule that a cloud-dependent idea measures availability once before its RFP. Seventeen credit-free calls surfaced:
  - the `history` 404
  - the response sizes and error shapes
  - that `count` facets yield the top IPs without spending credits
- **Search**: three options were offered: include in MCP with limits, CLI only, or not at all. The operator chose to include it in MCP with limits: a `credit_floor` (default 20) and at most one credit per call.
- **Commercial use**: public material could not settle the question. It is kept apart from the design and left in §7 as the operator's item to confirm.
- **Name**: `shodan-lookup`, after the source. Unlike cve-lookup, whose upstream was young and might be swapped (hence a subject name), Shodan is mature.
- **Revision after the independent verification pass (2026-10-09, after approval)**: the design-freeze verification checked the RFP against knowledge, the workspace records, the sibling repositories' rules and the raw measurement files. It returned high 0 / medium 8 / low 9. The author triaged and decided each finding (nothing was applied automatically) and re-checked the key figures against the raw files. By root cause:
  - **Miscounting the unit (M2)**: `count` counts services, not hosts. The tools were renamed `count_services` and `search_services`, and facets are documented as top N only.
  - **The never-send rule covered only IP arguments (M3, M4)**:
    - The gate now also covers `ip:` / `net:` in queries.
    - Key secrecy widened from error strings to every output surface.
    - Redirect refusal and an https-only `base_url` were added.
  - **The credit floor depended on a prediction (M1)**:
    - The floor is now checked on every call assuming a cost of 1.
    - A failed lookup means no call, and a mismatch between prediction and actual cost stops searching.
    - The spending estimate was corrected to at most 4.
  - **Mappings fixed before the upstream shapes were measured (M5, M6)**:
    - The `Invalid IP` 404 maps to `invalid_argument`. The non-JSON 403 mapping waits for measurement. A search-family 401 is diagnosed through `/api-info`. `bad_request` was added.
    - `history` is restated as n=2 with a presumed cause.
    - Phase 1 gained measurement items: an unindexed global IP, the 401 on each endpoint, invalid filters and unknown arguments, and the time zone.
    - Knowledge feedback became an append to an existing section.
  - **`get_service` contradicted itself (M7)**: it now fetches when the cache lacks the body and signals a moved base through `doc_id`. An ambiguous transport is refused, and an unobserved port is reported as such.
  - **Details (L1–L9)**:
    - Porting is compared per package with `git log`, and `ipaddr` starts from web-fetch's table.
    - Section text is exempt from the safety net, and banners are capped in bytes after escaping.
    - Pacing became 2000 ms, a missing key became `missing_api_key`, and `make e2e` fails without a key.
    - The mcp-tactics order now follows the attribution axis, placing this tool at the tail beside abuse-lookup, and the follow-through items were extended.
    - The CLI and MCP mirror was aligned, and the Japanese/English discrepancies were fixed.
  - **M8 resolved by reading the terms (same day)**:
    - The operator located the terms, and they were read in full (§7).
    - No clause forbids caching, and none limits a purchased Membership to non-commercial use.
    - The attribution duty (§6.7) and trademark (§10) were added to §3.
    - The release gate became a check that the terms' sha256 is unchanged.
- **Getting to the terms**: neither the public footer nor the logged-in membership page (a PDF the operator supplied) linked to them. The membership page became the primary source that Membership includes IP lookups and the API (100 / 100 credits).
  - Errors in the RFP itself found by the recount were corrected in §7 and in this log: 18 calls were really 17, and 46 endpoints were really 37 paths and 45 operations. The 225 KB `vulns` is duplicated across two services.
