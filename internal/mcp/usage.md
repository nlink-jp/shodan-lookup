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
