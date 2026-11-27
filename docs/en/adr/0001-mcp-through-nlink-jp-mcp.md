# ADR-0001: The MCP protocol layer becomes nlink-jp/mcp — both eras

| Field | Value |
|-------|-------|
| Status | **Accepted** (2026-11-27) |
| Date | 2026-11-27 |
| Binds | shodan-lookup |
| Decision makers | nlink-jp maintainers |
| Triggered by | Organization ADR-030 (every MCP implementation speaks both eras and takes its protocol layer only from nlink-jp/mcp); issue nlink-jp/shodan-lookup#1 |

## Context

`internal/mcp/server.go` was a hand-written stdio MCP server, fixed at version 2024-11-05 and speaking the legacy
era only (the `initialize` handshake), so a modern-only client of the 2026-07-28 revision could not reach it.
shodan-lookup is the reference implementation of family B (lookup, second line; nlink-jp/mcp's server-migration §1).
The re-measurement of the real peers (2026-11-27, ADR-030 §7) is recorded in asn-lookup's ADR-0001: Claude Code
2.1.311, gem-agent and lagent are all dual-era.

## Decision

Follow the common policy (nlink-jp/mcp's `docs/en/server-migration.md`, v0.3.0), with these items for this
repository:

1. **The shape seen from outside stays (policy §2).** `Server{Cfg, Cache, Eng, Version}.Serve(ctx, stdin, stdout)`
   stays (refusing a nil stdin as before). Inside it is a `server.ToolServer` built per `Serve`, the tools registered
   in `toolDefinitions()` order. Each handler calls `callTool(ctx, name, args)`, which holds everything from the
   dispatch to the wrapping — `get_usage`'s Markdown, `capStrings`, the 128 KB ceiling. The hand-written read/write
   loop, handshake, `request`, `response` and `rpcError` go.
2. **Options (policy §2)**: `Workers` 1 (the engine's pacing and the search credit guard assume serial calls),
   `QueueDepth` 256, a `slog` to stderr (Warn and above).
3. **Tool failures (policy §3)**: the `{code,message}` isError, `decodeArgs`, the 128 KB ceiling and `capStrings` stay.
4. **Behaviour that changes (policy §4)**:
   - An unknown tool is -32602 instead of an isError `unknown_tool`, so `CodeUnknownTool` and its usage.md row go.
   - `tools/*` before initialize is -32602, and so are `arguments` that is not an object.
   - A request with `"id":null` gets -32600 (before, `initialize`, `ping` and `tools/list` were answered with a null
     id); so does a request without `"jsonrpc"`.
   - An unknown method before initialize is -32602 (it was -32601); a batch is -32600 (it was a parse error).
   - A panic in a tool is answered -32603 and the server goes on (it crashed); up to 256 calls wait behind a running
     one, more get -32603 "server busy".
   - The version moves from a fixed 2024-11-05 to legacy negotiation and the modern era.
   - Cache writes go to a temporary file and are renamed, outside any cancellation path, so a cancellation leaves no
     partial file.
8. **Signals (policy §2)**: the `mcp` subcommand passes `Serve` a ctx cancelled by SIGINT and SIGTERM.
5. **Cancellation (policy §5, §8)**: `notifications/cancelled` now cancels the call's ctx. The credit read after a
   search (`engine/search.go`) failing under a cancelled ctx enters `halt` and stops every later search, so that read
   runs under `context.WithoutCancel`: whether the search was charged is checked even when the call was cancelled.
6. **Dependency**: `github.com/nlink-jp/mcp` is added; "standard library only" in CLAUDE.md and AGENTS.md changes.
7. **Version**: minor (v0.2.0).

## Defects found (each fixed in its own fix commit)

- The credit read after a search failing under a cancellation stopped every later search (§5).
- Argument names were matched case-insensitively (`{"IP":...}` passed as `ip`); they are now matched exactly.
- `mcp` served on `context.Background()`, so SIGINT and SIGTERM killed the process and no cleanup ran.

## Consequences

- Modern-only clients reach it too; legacy clients are answered as before.
- The credit guard stays right after a cancelled search.
- Tests run through the module's `client`. Tests of protocol details (parse errors, unknown methods, notifications,
  blank lines) went; a test against the three probe clients was added.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Keep ignoring cancellation (detach the handlers' ctx) | A client could no longer stop a long call; only the read after a charge needs fixing |
| Keep returning an unknown tool as an isError | The module answers -32602 first; reproducing the old answer would keep a copy of the protocol layer |

## References

- Organization ADR-030, ADR-025
- nlink-jp/mcp v0.3.0: `docs/en/server-migration.md`
- asn-lookup ADR-0001 (family A's reference and the re-measured peers)
- Issue nlink-jp/shodan-lookup#1
