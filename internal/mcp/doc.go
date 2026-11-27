// Package mcp serves the shared engine as MCP tools over stdio. The protocol
// itself — both eras (the legacy initialize handshake and the 2026-07-28
// revision), framing, versions, cancellation — is the organization's module
// nlink-jp/mcp (organization ADR-030, ADR-0001); this package holds the tools.
//
// This package is where the response budget lives. The engine returns complete
// views; what one tool result may cost in a client's context is decided here:
// compact by default, large parts paged from the same cached upstream body,
// what was dropped counted — and only when something was dropped. Two
// backstops sit behind the per-field caps (budget.go): any other string over
// 1000 characters is shortened and named, and no result leaves over 128 KB.
// Nothing is spilled to a file.
//
// get_usage is canonical: the mcp-tactics skill deliberately documents no
// parameters, so the embedded manual is what an agent reads before its first
// call. Tool errors are structured JSON ({code, message}), returned as results
// rather than protocol errors so that the model sees them. Tool text states
// triggers, contracts and provenance; it carries no defensive instructions —
// that layer belongs to the runtime.
//
// Arguments are decoded strictly (decodeArgs): an undeclared argument is
// refused by name, for every tool including those that take none.
//
// At EOF of stdin every request that arrived is answered, then the server
// ends. notifications/cancelled cancels the call's ctx: what must survive a
// cancellation — reading the credits a search spent — runs without it.
package mcp
