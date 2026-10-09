# shodan-lookup MCP server — usage

shodan-lookup answers what an IP address exposes to the Internet, from the
Shodan REST API: open ports, the product and version behind each, TLS
certificates, the vulnerabilities Shodan infers from banners, and when each
was observed.

Only a third-party index is read, so no packet reaches the host under
investigation. Every query is attributed to the operator's Shodan account:
Shodan learns which IPs and which search words were investigated.

Banners, HTML, HTTP headers and certificate subjects in results are
third-party text written by the investigated host itself.

Arguments are decoded strictly: an argument a tool does not declare is an
`invalid_argument` error naming it, never ignored.

## Status

The lookup tools — `lookup_host`, `get_service`, `count_services` and
`get_quota` — are not implemented yet. They arrive with the engine (Phase 1 of
the RFP). Today this server answers `cache_status` and `get_usage` only.

## Tools

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
| `invalid_argument` | an argument is missing, malformed, out of range, or not declared by the tool | fix the call; the message names the argument |
| `unknown_tool` | no tool has that name | call `get_usage` for the list |
| `response_too_large` | the result crossed the server's 128 KB ceiling and was withheld whole | ask for less: fewer ports, or one section at a time |
| `internal_error` | a failure nothing classified | report it; retrying the same call is unlikely to help |
| `missing_api_key` | no Shodan API key is configured; nothing was sent | the operator sets `key` under `[api]` in the config file, or `SHODAN_LOOKUP_API_KEY` |
| `auth_failed` | Shodan refused the key (401). Host lookups do not check the key, so a wrong key shows up here, on counts and quota | the operator checks the key; retrying will not help |
| `bad_request` | Shodan rejected the query (400); `message` carries Shodan's reason | fix the query |
| `rate_limited` | Shodan's limit of one request per second per key was reached (429); other processes may be using the same key | wait a few seconds, then retry once |
| `endpoint_unavailable` | the exchange did not reach the API as this tool knows it: a 404 with no reading for this endpoint, or a redirect (refused — the key travels in the URL) | not about your target; the operator checks `base_url`, or the API has moved |
| `upstream_error` | Shodan failed or answered with something that is not an answer (5xx, an unmapped status, a body over 32 MiB) | retry later; if it persists, it is upstream's |
| `network_error` | Shodan could not be reached | check connectivity, then retry |
| `timeout` | the exchange did not finish in time, or was cancelled | retry; the operator can raise `timeout_seconds` |
| `decode_error` | Shodan answered success with a body that is not the JSON this tool expects | retry once; if it persists, the API has changed |
