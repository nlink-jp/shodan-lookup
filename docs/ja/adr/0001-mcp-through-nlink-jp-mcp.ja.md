# ADR-0001: MCP のプロトコル層を nlink-jp/mcp にする — 新旧両方の時代を話す

| 項目 | 値 |
|-------|-----|
| Status | **Accepted**（2026-11-27） |
| Date | 2026-11-27 |
| Binds | shodan-lookup |
| Decision makers | nlink-jp maintainers |
| Triggered by | 組織 ADR-030（MCP の実装は新旧両方の時代を話し、プロトコル層は nlink-jp/mcp だけから取る）。issue nlink-jp/shodan-lookup#1 |

## Context

`internal/mcp/server.go` は手書きの stdio MCP サーバだった。版は固定の 2024-11-05 で、旧方式（`initialize` の
握手）だけを話す。そのため、2026-07-28 版の新方式専用のクライアントからはつながらない。shodan-lookup は、家系 B
（lookup 2 系統）の参照実装にあたる（nlink-jp/mcp の文書 server-migration §1）。実際の相手の測り直し
（2026-11-27、ADR-030 §7）は asn-lookup の ADR-0001 にある。Claude Code 2.1.311・gem-agent・lagent は、どれも両対応だった。

## Decision

共通の方針（nlink-jp/mcp の `docs/ja/server-migration.ja.md`、v0.3.0）に従う。このリポに当てはまる項目は次のとおり。

1. **外から見える形は変えない（方針 §2）。** `Server{Cfg, Cache, Eng, Version}.Serve(ctx, stdin, stdout)` を残す
   （nil の stdin を拒むのも、いまのまま）。中身は、`Serve` のたびに作る `server.ToolServer` で、`toolDefinitions()`
   の順に登録する。各ツールのハンドラは `callTool(ctx, name, args)` を呼ぶ。`callTool` は、振り分け（`dispatch`）から
   `get_usage` の Markdown・`capStrings`・128 KB の上限による包みまでを持つ。手書きの読み書きのループ・握手・
   `request`・`response`・`rpcError` は消す。
2. **選択肢（方針 §2）**: `Workers` は 1（エンジンのペース配分と、検索のクレジットのガードが直列を前提にしているため）、
   `QueueDepth` は 256、ログは stderr への slog（Warn 以上）。
3. **ツールの失敗（方針 §3）**: `{code,message}` の isError、`decodeArgs`、128 KB の上限、`capStrings` はいまのまま。
4. **変わる振る舞い（方針 §4）**:
   - 未知のツールは、isError の `unknown_tool` ではなく -32602 になる。そこで `CodeUnknownTool` と usage.md の表の行を消す。
   - initialize の前の `tools/*` は -32602 になる。オブジェクトでない `arguments` も -32602 になる。
   - `"id":null` の要求は -32600 になる（これまでは `initialize`・`ping`・`tools/list` に id null で答えていた）。
   - 版は 2024-11-05 固定から、旧方式の交渉と新方式に変わる。
5. **取り消し（方針 §5・§8）**: `notifications/cancelled` で呼び出しの ctx が取り消されるようになる。検索の後のクレジットの
   読み取り（`engine/search.go`）が取り消された ctx で失敗すると、`halt` に入って以後の検索がすべて止まる。そこで
   この読み取りは `context.WithoutCancel` で行う。検索が課金されたかどうかは、取り消されても確かめる。
6. **依存**: `github.com/nlink-jp/mcp` を足す。CLAUDE.md・AGENTS.md の「標準ライブラリのみ」を改める。
7. **版**: minor を上げる（v0.2.0）。

## Consequences

- 新方式専用のクライアントからもつながる。旧方式のクライアントには、これまでどおり答える。
- 取り消された検索の後も、クレジットのガードは正しく働く。
- 試験はモジュールの `client` で動かす。プロトコルの細かな振る舞いの試験（parse error・未知メソッド・通知・空行）は外し、探りのクライアント 3 種の組み合わせを足した。

## Alternatives considered

| 案 | 採らない理由 |
|---|---|
| 取り消しを無視し続ける（ハンドラの ctx を切り離す） | 長い呼び出しを、クライアントが止められなくなる。直すべきは、課金の後の読み取りだけである |
| 未知のツールを isError で返し続ける | モジュールが先に -32602 で答える。それを各リポで再現すると、プロトコル層の写しが残る |

## References

- 組織 ADR-030、ADR-025
- nlink-jp/mcp v0.3.0: `docs/ja/server-migration.ja.md`
- asn-lookup ADR-0001（家系 A の参照実装と、実際の相手の測り直し）
- issue nlink-jp/shodan-lookup#1
