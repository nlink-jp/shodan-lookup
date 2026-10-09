// Package config resolves settings from, in decreasing precedence: command
// line flags, environment variables, the config file, and built-in defaults.
//
// The file is the sectioned-TOML subset used across the series ([api],
// [query], [search], [cache], [network], [limits]). It is looked for, in
// order, in $XDG_CONFIG_HOME/shodan-lookup/, ~/.config/shodan-lookup/ and, on
// macOS, ~/Library/Application Support/shodan-lookup/; the first file found is
// read and its path is recorded in Config.Path so a diagnostic can say which
// it was. ~/.config is searched even when XDG_CONFIG_HOME is set: a file that
// exists and is silently not read is worse than no file.
//
// Input that is not understood is refused, never ignored: an unknown section
// or key, a key outside any section, a key present with an empty value, a
// number outside its range, and a config path the caller named that does not
// exist are all errors that name the offender.
//
// The API key is the one credential. It travels in the query string of every
// request (Shodan accepts no other way), so it is never rendered — Redacted
// exists for anything that prints settings — and base_url, which names the
// host every request and therefore the key goes to, is read from the
// operator's configuration only and refused unless it is https (plain http
// only on loopback, for tests) without credentials, query or fragment.
//
// Loading succeeds without a key, so the cache commands, the MCP handshake and
// get_usage work on a fresh machine; a query checks HasKey and reports
// missing_api_key.
package config
