# ADR-0002: The tool conventions come from nlink-jp/mcptool

| Field | Value |
|-------|-------|
| Status | **Accepted** (2026-11-28) |
| Date | 2026-11-28 |
| Binds | shodan-lookup |
| Decision makers | nlink-jp maintainers |
| Triggered by | Organization ADR-031 (the MCP tool conventions live in one module; the servers stop copying them). Issue nlink-jp/shodan-lookup#2 |

The Japanese version (`docs/ja/adr/0002-tool-conventions-through-mcptool.ja.md`) is the source.

## Context

ADR-0001 moved the protocol layer onto nlink-jp/mcp. The conventions on top of it stayed copied here:
- `internal/mcp/server.go`'s shell (`Serve`, `toolServer`, `handle`, `callTool`, `toolText`, `toolRawText`, `toolError`);
- `tools.go`'s dispatch, and `decodeArgs`, `argNames`, `argError` and `structuredError`;
- the startup seam (`internal/app`'s `notifyContext`);
- the probe-matrix and pipe-client tests.

shodan-lookup is family B's reference migration (mcptool's migration policy §7).

## Decision

This follows mcptool's migration policy (`docs/en/migration.md`, v0.1.3). What applies here:

1. **Registering tools (policy §2.1)**:
   - the six tools that take arguments (`lookup_host`, `get_service`, `count_services`, `get_history`, `parse_query`, `search_services`) are registered with their argument structs through `mcptool.Add`;
   - `get_quota`, `cache_status` and `get_usage` through `AddNoArgs`; today's schemas carry an empty `properties: {}`, which stays;
   - each tool's schema and struct name the same set (registration checks it).
2. **Handlers and errors (policy §2.2)**:
   - an argument error is `invalid_arguments`, whether it is refused at decoding or inside a handler or the engine, with the argument's name in `details.argument`:
     - an empty string or a port of `0`, a value out of range, a combination refused (`ports` with `ports_only`; `transport`, `offset` or `limit` without `port`);
     - the engine's refusals (an internal address, an unknown filter or facet name, an unbalanced quote, an `offset` past the end, a port that needs `transport`). The engine's `Error` carries which argument it is about (`Argument`), and the MCP layer copies it into `details.argument`;
   - a required argument absent or `null` is refused by mcptool as `missing_argument` (`details.argument`);
   - the other codes (`not_indexed`, `not_observed`, `plan_restricted`, `credit_floor`, `credit_mismatch`, the Shodan client's codes, `response_too_large`) stay; `internal_error` is mcptool's constant;
   - **the CLI does not change.** The engine's code `invalid_argument` stays in the CLI's exit status, `--json` and stderr; only the MCP layer reads it as `invalid_arguments`. The manual's test (every `Code*` constant has a row in the manual's table) holds that translation in one table.
3. **Response budgets (policy §1, "what stays")**: the 128 KB ceiling, the 1000-character backstop and each tool's thinning stay here.
   - They measure the result as mcptool writes it: on one line, HTML characters not escaped (`<`, `>` and `&` are one byte each). Today they measure the indented form.
   - A result under the ceiling is returned as the bytes measured, through `mcptool.Text`, so what is measured is what is sent.
   - Banner clipping (`clipEscaped`) counts `<`, `>` and `&` as one byte too.
4. **Serving (policy §2.3)**: `runMCP` builds the server with `Server.Build` and runs it with `serve.Run`, the streams passed through `serve.Options`. `notifyContext` goes; the signal test uses `serve.NotifyContext`. `instructions` go into `mcptool.Info` at creation, as today.
5. **Tests (policy §5)**:
   - tool tests are rewritten on `tooltest` (the cancellation test opens with `OpenWith`);
   - one `tooltest.ProbeMatrix` and one `tooltest.SchemaContract` (no tool returns a path);
   - the protocol behaviour tests (an unknown tool, a nil input) go: nlink-jp/mcp tests them;
   - before and after are compared with `mcpsnap`. The before record is v0.2.1 (the installed version); all nine tools refused before starting any work;
   - `make e2e-credits` does not run (it spends a query credit). `make e2e` uses the key but spends no credit; the number of calls is told before it runs.
6. **Dependency**: `github.com/nlink-jp/mcptool` v0.1.3 (the floor is v0.1.1, ADR-031 §3).
7. **Version**: a minor bump (v0.3.0).

## Changes clients will see (from mcptool's design §5.1)

- A value's JSON is one line (no indentation); the value is the same.
- `<`, `>` and `&` arrive unescaped — a banner's or a page's `&` arrives as `&`, not `\u0026`.
- An argument error's code becomes `invalid_arguments` instead of `invalid_argument`, with the name in `details.argument`. An unknown name or a wrong type is worded `unknown argument "…"` / `argument "…" must be …` instead of `arguments: json: unknown field "…"`.
- A missing required argument is `missing_argument`. An empty string or a `0` is an argument error (`invalid_arguments`), as today.
- With several problems in one call, the first one reported may change (unknown → missing → type).
- The budgets measure what is sent, so more fits: by the indentation and escaping saved, fewer rows are thinned and fewer banners shortened, and a result the ceiling withheld may now be returned.
- The manual's (`usage.md`) recovery table turns the `invalid_argument` row into two, `invalid_arguments` and `missing_argument`.

These changes share one commit: each follows from swapping the shell for mcptool, and none can be had without the others. Adding `Argument` to the engine is invisible, so it goes first in a commit of its own.

## Defects found (closed by the migration)

- No test that the schemas are closed (policy §4): mcptool's registration checks it.
- `argNames` accepted a field without a json name in any case (latent: every argument field today has a name). mcptool refuses an unnamed field at registration.

## Consequences

- `internal/mcp` keeps only the tools, their schemas, the list of codes and the response budget.
- A defect in a convention is fixed once in mcptool and reaches this server by a floor raise.

## Alternatives considered

| Alternative | Why not |
|---|---|
| Return the engine's `invalid_argument` over MCP as it is | Against policy §2.2 (the owner's decision, 2026-11-28): a caller could not handle argument errors by one code |
| Change the engine's code to `invalid_arguments` | The CLI's `--json` and stderr would change. The migration is about the MCP conventions; it does not draw the CLI in |
| Measure the ceiling after mcptool has written the result | mcptool reports no size and holds no budget (ADR-031 §1). A handler that writes and measures the result itself and returns it through `Text` sends what it measured |

## References

- Organization ADR-031, ADR-030, ADR-021 §4
- nlink-jp/mcptool v0.1.3: `docs/en/migration.md`, `docs/en/design.md` §5.1
- ADR-0001
- Issue nlink-jp/shodan-lookup#2
