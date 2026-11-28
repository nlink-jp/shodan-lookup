// Package mcp serves the shared engine as MCP tools over stdio. The protocol
// itself — both eras (the legacy initialize handshake and the 2026-07-28
// revision), framing, versions, cancellation — is the organization's module
// nlink-jp/mcp (organization ADR-030, ADR-0001); the tool conventions —
// argument decoding, structured errors, results, serving — are
// nlink-jp/mcptool's (organization ADR-031, ADR-0002). This package holds the
// tools, their schemas, the error code it adds and the response budget.
//
// This package is where the response budget lives. The engine returns complete
// views; what one tool result may cost in a client's context is decided here:
// compact by default, large parts paged from the same cached upstream body,
// what was dropped counted — and only when something was dropped. Two
// backstops sit behind the per-field caps (budget.go): any other string over
// 1000 characters is shortened and named, and no result leaves over 128 KB.
// Every budget measures the result as it is sent (wire). Nothing is spilled
// to a file.
//
// get_usage is canonical: the mcp-tactics skill deliberately documents no
// parameters, so the embedded manual is what an agent reads before its first
// call. Tool errors are structured JSON ({code, message, details}), returned as
// results rather than protocol errors so that the model sees them. Tool text states
// triggers, contracts and provenance; it carries no defensive instructions —
// that layer belongs to the runtime.
//
// Arguments are decoded by mcptool before a handler runs: an undeclared
// argument, one in another case or of the wrong type is refused by name
// (invalid_arguments), for every tool including those that take none, and a
// missing required one is missing_argument. A handler's and the engine's own
// argument checks answer invalid_arguments too, naming the argument.
//
// At EOF of stdin every request that arrived is answered, then the server
// ends. notifications/cancelled cancels the call's ctx: what must survive a
// cancellation — reading the credits a search spent — runs without it.
package mcp
