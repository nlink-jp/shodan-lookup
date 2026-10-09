// Package cache is a fixed-TTL JSON-file cache with atomic writes, shared by
// the CLI and the MCP server.
//
// The TTL is applied at read time rather than at write time, so changing a
// *_ttl_hours value in the config takes effect on entries already on disk.
// Which TTL applies is the caller's decision: host records age on HostTTL,
// counts on CountTTL, search pages on SearchTTL. A TTL of 0 turns a kind's
// caching off — Get always misses — which is how a change in the upstream's
// terms would be met without a code change.
//
// The unit stored is the upstream body itself; every view (the compact
// projection, a section of it, --json, --raw) is derived from it, so no view
// has a slot of its own. Never cached: account state (the quota), "not
// indexed" answers, and degraded results — a lookup that fell back because an
// upstream call failed would otherwise freeze an incomplete answer in place
// for the whole TTL, and the analyst would have no way to tell.
//
// Shodan's lists of filter and facet names are cached for a fixed 24 hours
// whatever the TTLs say: they are the API's vocabulary, not data about any
// host, and every refused name fetches the list again once before refusing.
//
// Entry names are hashes of what determined the answer (Key), so the IPs and
// queries that were investigated do not sit readable in a directory listing.
// The bodies themselves are Shodan's data and stay on this machine.
package cache
