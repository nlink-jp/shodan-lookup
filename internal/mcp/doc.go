// Package mcp is a dependency-free stdio JSON-RPC 2.0 MCP server over the
// shared engine. In the scaffold it answers cache_status and get_usage; the
// lookup tools (lookup_host, get_service, count_services, get_quota, and in
// Phase 2 parse_query and search_services) arrive with the engine.
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
// A closing stdin is the shutdown signal. An MCP cancellation notification may
// be ignored by its receiver, so nothing here depends on one arriving.
package mcp
