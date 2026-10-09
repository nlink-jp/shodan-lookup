// Package e2e holds live tests against the real Shodan REST API, behind the
// `e2e` build tag (network and an API key required; run via `make e2e`,
// which builds the binary first). `make test` does not run them, but it
// type-checks them.
//
// The default suite spends no query credits, and proves it: the remainder is
// read before and after the run, and any difference fails it. A missing key
// fails the run too — a release gate that skips is a gate that passes.
//
// Besides proving the tool works end to end — the engine, and the built
// binary through both of its faces — the suite pins the upstream behaviours
// the design rests on, several of them traps the code exists to defuse: host
// lookups do not check the key; an unknown filter matches nothing without an
// error; vuln: answers a misleadingly low count; a SHA-256 fingerprint
// matches nothing; some hosts' history answers "no information" although they
// have services; history stops at 1,000 banners. When one of them changes,
// the failing test names the Gotcha in AGENTS.md that is out of date.
//
// The credit-spending check (one filtered search, predicted against actual)
// is behind the additional `e2e_credits` tag and runs only through
// `make e2e-credits`, which says what it spends first.
package e2e
