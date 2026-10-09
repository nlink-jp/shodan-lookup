# Changelog

All notable changes to this project are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

### Added

- Project scaffold (Phase 2 of the RFP): `version` / `--version` / `-v`
  (identical output), `help`, `cache status` / `cache clear`, and `mcp` with
  `cache_status` and `get_usage`. The lookup commands `host`, `service`,
  `count` and `quota` are placeholders that exit 2 with "not implemented yet".
- Strict configuration: `[api]` / `[query]` / `[search]` / `[cache]` /
  `[network]` / `[limits]`, `SHODAN_LOOKUP_*` environment overrides and the
  `SHODAN_API_KEY` alias. Unknown sections and keys, keys outside a section
  (with directions for a bare `api_key`), present-but-empty values,
  out-of-range numbers and a missing explicit `--config` are refused by name.
  `base_url` must be https (plain http only on loopback) without credentials,
  query or fragment. A TTL of 0 turns caching off for that kind of answer.
- Cache entry names are a hash over length-prefixed parts, so no two part
  lists collide and investigated IPs and queries do not appear in filenames.
