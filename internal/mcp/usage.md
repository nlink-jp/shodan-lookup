# shodan-lookup MCP server — usage

shodan-lookup answers what an IP address exposes to the Internet, from the
Shodan REST API: open ports, the product and version behind each, TLS
certificates, the vulnerabilities Shodan infers from banners, and when each
was observed.

Only a third-party index is read, so no packet reaches the host under
investigation. Every query is attributed to the operator's Shodan account:
Shodan learns which IPs and which search words were investigated. Internal
addresses — private, loopback, link-local, documentation ranges, and IPv6
forms that embed them — are refused before anything is sent, in IP arguments
and in `ip:` / `net:` query values alike. Names inside `hostname:` or `org:`
cannot be judged that way and are sent as written.

Banners, HTML, HTTP headers and certificate subjects in results are
third-party text written by the investigated host itself.

Arguments are decoded strictly: an argument a tool does not declare is an
`invalid_argument` error naming it, never ignored.

Shodan's data is attributed to Shodan: its terms (§6.7) ask that Shodan
information included in your own materials — an incident report — be
credited to Shodan. Every result names its source in `provenance`.

## Which tool

| question | tool |
|---|---|
| What does this IP expose — ports, products, certificates, inferred CVEs? | `lookup_host` |
| Show me one service of it in full: the banner, the page, the certificate, the CVE summaries | `get_service` |
| How many services match this query, and which IPs / orgs / countries have the most? | `count_services` |
| How many query credits are left, and does the key work? | `get_quota` |

A typical pivot: `lookup_host` → a certificate's `sha1` or a
`favicon_hash` → `count_services` with `ssl.cert.fingerprint:<sha1>` or
`http.favicon.hash:<hash>` and facets `["ip:20"]` → `lookup_host` on those
IPs. The fingerprint filter matches SHA-1 only: a SHA-256 matches nothing
without an error (measured), so it is refused. Inferred CVE IDs continue to
cve-lookup.

## Reading the answers

These mean Shodan has no observation, and none of them is a negative finding:

| you see | it means | it does NOT mean |
|---|---|---|
| `not_indexed` (an error code) | Shodan has not observed the IP; a count for `ip:<address>` confirmed zero services | nothing is open — Shodan's crawl is not exhaustive |
| `not_observed`, or a port in `ports_not_observed` | the host is indexed, but Shodan has no banner for that port | the port is closed |
| an empty `vulns` | Shodan infers no CVE from the banners it holds | the host is not vulnerable |

And these are easy to misread:

- **`verified: false`** on a CVE means *inferred* from a version string, not
  confirmed. Most are.
- **Counts are services (banners), not hosts.** `count_services` `total` is
  the number of matching services; an IP with two matching services counts
  twice, and its `ip` facet value is 2. Each facet lists only its top values.
- **`timestamp` / `observed_hours_ago`** say when Shodan saw the service, in
  UTC. The service may have changed since.
- **`ssl.expired`** is computed when the answer is built (`expired_as_of`),
  not taken from the observation.
- **`omitted`** counts what lookup_host left out to stay within the budget
  (services, banners shortened, CVEs past the top ones). It appears only when
  something was left out; `get_service` reaches all of it.

## Tools

### lookup_host

What one IP exposes. Arguments:

- `ip` (required): IPv4 or IPv6, public addresses only. Hostnames are not
  accepted — resolve them with doh-lookup.
- `ports`: only these ports' services, up to 50. Ports Shodan did not observe
  are listed in `ports_not_observed`.
- `ports_only`: return the host's attributes and port list only; services and
  CVEs are counted in `omitted`, not listed.
- `refresh`: bypass the local cache (host records are cached 12 hours by
  default).

The answer: `ip`, `org`, `isp`, `asn`, `country_code`, `city`, `hostnames`,
`domains`, `os`, `tags`, `last_update`, `ports`, `service_count`,
`services[]`, `vuln_count`, `vulns[]`, `provenance`, `notes`, and `omitted`
when anything was left out.

Each service: `port`, `transport`, `module`, `timestamp`,
`observed_hours_ago`, `product`, `version`, `cpe23`, `http` (`status`,
`title`, `server`, `location`, `html_chars`), `ssl` (`subject_cn`,
`issuer_cn`, `not_before`, `not_after`, `expired`, `expired_as_of`, `sha1`
— the value `ssl.cert.fingerprint:` matches — `sha256`, `versions`), `banner` (shortened to 512 bytes by default), `banner_chars` (the
full length), `favicon_hash`, `tags`, `vuln_count`, and `sections` — the name
and size of each part `get_service` can return.

Each CVE: `id`, `cvss`, `cvss_version`, `epss`, `verified`, and the `ports`
it was inferred on. At most 25 are listed by default, highest CVSS first.

### get_service

One section of one service, in full, paged. Arguments:

- `ip`, `port` (required).
- `transport`: `tcp` or `udp`; required when the port has both (DNS on 53
  often does).
- `section` (required): `banner`, `http_html` or `ssl_cert` (text, paged by
  characters), or `http_headers`, `ssl_chain` or `vulns` (lists, paged by
  items). `vulns` carries each CVE's summary and references, sorted by ID.
- `offset`: characters or items to skip; `next_offset` in the answer
  continues, and is absent on the last page.
- `limit`: 1-16000 characters (default 4000), or 1-50 items (default 20).
- `refresh`: fetch the host record again.

Every page carries `provenance.doc_id`, a hash of the host record it was
read from. If it changes between two pages, the record was refetched
underneath and the pages may not line up.

### count_services

How many services match a query. Spends no query credits (measured).
Arguments:

- `query` (required): Shodan search syntax, e.g. `port:3389 country:JP`.
  Filter names are checked against Shodan's own list before sending — an
  unknown one is refused, because Shodan would read it as free text and match
  nothing. `vuln` and `tag` are refused as `plan_restricted`. Quote text that
  contains a colon. At most 1000 characters.
- `facets`: breakdowns as `"name"` or `"name:N"`, N 1-100 (default 10), e.g.
  `"org:5"`, `"ip:20"`. Names are checked against Shodan's facet list —
  Shodan drops an unknown one without saying so.
- `refresh`: bypass the local cache (counts are cached 1 hour by default).

The answer: `query`, `unit` (always `services`), `total`, `facets[]` (each
`name`, `requested`, `values[]` of `value` and `count`), `provenance`,
`notes`.

### get_quota

The key's `plan` (`dev` is Membership), `plan_name`, `query_credits`,
`scan_credits`, `monitored_ips` and `usage_limits`, read live. Takes no
arguments. Because host lookups do not check the key, this is where a wrong
key shows (`auth_failed`).

### cache_status

The local result cache: `dir`, `entries`, `bytes`, and the three freshness
windows in hours — `host_ttl_hours`, `count_ttl_hours`, `search_ttl_hours`.
A window of 0 means that kind of answer is not cached at all. Windows are
applied when an entry is read, so lowering one in the config expires entries
already on disk.

Takes no arguments.

### get_usage

This manual. Takes no arguments.

## Errors

Every tool error is a result with `isError: true` whose text is
`{"code": ..., "message": ...}`. Branch on `code`; the message is for people.

| code | meaning | what to do |
|---|---|---|
| `invalid_argument` | an argument is missing, malformed, out of range, or not declared by the tool; or an address or query was refused before sending (internal address, unknown filter or facet name, unbalanced quote) | fix the call; the message names what was refused |
| `not_indexed` | Shodan has not observed the IP: its record was absent and a count for `ip:<address>` confirmed zero services | an answer, not a failure — but not evidence that nothing is open; Shodan's crawl is not exhaustive |
| `not_observed` | the host is indexed, but Shodan has no banner for that port (and transport) | an answer — not evidence that the port is closed; the message lists the ports Shodan did observe |
| `plan_restricted` | the query uses `vuln` or `tag`, which Shodan withholds from a Membership plan; refused before sending because the restriction does not come back as an error, only as a misleadingly low count | rephrase without that filter or facet (for CVEs, look the host up and read its inferred CVEs) |
| `missing_api_key` | no Shodan API key is configured; nothing was sent | the operator sets `key` under `[api]` in the config file, or `SHODAN_LOOKUP_API_KEY` |
| `auth_failed` | Shodan refused the key (401). Host lookups do not check the key, so a wrong key shows up here, on counts and quota | the operator checks the key; retrying will not help |
| `bad_request` | Shodan rejected the query (400); `message` carries Shodan's reason | fix the query |
| `rate_limited` | Shodan's limit of one request per second per key was reached (429); other processes may be using the same key | wait a few seconds, then retry once |
| `endpoint_unavailable` | the exchange did not reach the API as this tool knows it: a 404 with no reading for this endpoint, or a redirect (refused — the key travels in the URL) | not about your target; the operator checks `base_url`, or the API has moved |
| `upstream_error` | Shodan failed or answered with something that is not an answer (5xx, an unmapped status, a body over 32 MiB) — including a host Shodan holds services for but would not return | retry later; if it persists, it is upstream's. It is never a negative answer |
| `network_error` | Shodan could not be reached | check connectivity, then retry |
| `timeout` | the exchange did not finish in time, or was cancelled | retry; the operator can raise `timeout_seconds` |
| `decode_error` | Shodan answered success with a body that is not the JSON this tool expects | retry once; if it persists, the API has changed |
| `unknown_tool` | no tool has that name | call `get_usage` for the list |
| `response_too_large` | the result crossed the server's 128 KB ceiling and was withheld whole | ask for less: fewer ports, a smaller limit, or one section at a time |
| `internal_error` | a failure nothing classified | report it; retrying the same call is unlikely to help |
