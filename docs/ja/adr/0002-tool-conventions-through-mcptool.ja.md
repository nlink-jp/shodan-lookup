# ADR-0002: ツールの作法を nlink-jp/mcptool にする

| 項目 | 値 |
|-------|-----|
| Status | **Accepted**（2026-11-28） |
| Date | 2026-11-28 |
| Binds | shodan-lookup |
| Decision makers | nlink-jp maintainers |
| Triggered by | 組織 ADR-031（MCP のツールの作法を 1 つのモジュールに置き、サーバは写すのをやめる）。issue nlink-jp/shodan-lookup#2 |

## Context

ADR-0001 で、プロトコル層を nlink-jp/mcp に移した。その上の作法は、このリポに写したままだった。
- `internal/mcp/server.go` の殻（`Serve`・`toolServer`・`handle`・`callTool`・`toolText`・`toolRawText`・`toolError`）
- `tools.go` のディスパッチと、`decodeArgs`・`argNames`・`argError`・`structuredError`
- 起動の差し替え口（`internal/app` の `notifyContext`）
- 探り 3 種と管の上のクライアントの試験

shodan-lookup は家系 B の参照実装である（mcptool の移行の方針 §7）。

## Decision

mcptool の移行の方針（`docs/ja/migration.ja.md`、v0.1.3）に従う。このリポに当てはまる項目は次のとおり。

1. **ツールの登録（方針 §2.1）**:
   - 引数を取る 6 本（`lookup_host`・`get_service`・`count_services`・`get_history`・`parse_query`・`search_services`）は、引数の構造体を `mcptool.Add` で登録する。
   - `get_quota`・`cache_status`・`get_usage` は `AddNoArgs` で登録する。いまのスキーマは空の `properties: {}` を持つので、そのまま残す。
   - スキーマと構造体の名前の集合は、どのツールでも一致していた（登録が確かめる）。
2. **ハンドラとエラー（方針 §2.2）**:
   - 引数の誤りは、デコードで断るものも、ハンドラとエンジンの中で断るものも、`invalid_arguments` にする。`details.argument` に引数の名前を入れる。
     - 空の文字列・`0` のポート、範囲の外の値、組み合わせの誤り（`ports` と `ports_only`、`port` 無しの `transport`・`offset`・`limit`）
     - エンジンの断り（内部のアドレス、未知のフィルタやファセットの名前、閉じない引用符、終わりを越えた `offset`、`transport` を要るポート）。エンジンの `Error` に、その誤りがどの引数のものかを持たせ（`Argument`）、MCP の層が `details.argument` に写す。
   - 必須の引数が無い・`null` のときは、mcptool が `missing_argument` で断る（`details.argument`）。
   - ほかのコード（`not_indexed`・`not_observed`・`plan_restricted`・`credit_floor`・`credit_mismatch`、Shodan のクライアントのコード、`response_too_large`）は、いまのまま。`internal_error` は mcptool の定数を使う。
   - **CLI は変えない。** エンジンのコード `invalid_argument` は、CLI の終了コードと `--json`・標準エラーの表示に残る。MCP の層だけが `invalid_arguments` に読み替える。説明書の試験（`Code*` の定数はどれも説明書の表にある）は、この読み替えを 1 か所の表で持つ。
3. **応答の上限（方針 §1「残すもの」）**: 128 KB の天井・1000 文字の打ち切り・ツールごとの間引きは、このリポに残す。
   - 測り方を、mcptool が書く形にそろえる。1 行、HTML の文字を逃がさない（`<`・`>`・`&` は 1 バイト）。いまは字下げした形で測っていた。
   - 天井を越えない結果は、測ったバイト列をそのまま `mcptool.Text` で返す。測ったものと送るものが同じになる。
   - バナーの切り詰め（`clipEscaped`）も、`<`・`>`・`&` を 1 バイトと数える。
4. **起動（方針 §2.3）**: `runMCP` は、サーバを `Server.Build` で作り、`serve.Run` で動かす。標準入出力は `serve.Options` で渡す。`notifyContext` は消し、信号の試験は `serve.NotifyContext` の差し替え口で行う。`instructions` は、いまと同じく作るときに `mcptool.Info` に入れる。
5. **試験（方針 §5）**:
   - ツールの試験は `tooltest` の上に書き直す（`OpenWith` で取り消しの試験を開く）。
   - `tooltest.ProbeMatrix` を 1 本と `tooltest.SchemaContract` を 1 本置く（パスを返すツールは無い）。
   - プロトコルの振る舞いの試験（知らないツール、nil の入力）は消す。nlink-jp/mcp が試験している。
   - 移行の前後は `mcpsnap` で突き合わせる。前の記録は v0.2.1（いま入っている版）で取り、9 本すべてが仕事を始める前に断った。
   - `make e2e-credits` は走らせない（クエリのクレジットを 1 つ使う）。`make e2e` は鍵を使うが、クレジットを使わない。走らせる前に、使う回数を伝える。
6. **依存**: `github.com/nlink-jp/mcptool` v0.1.3 を足す（下限は v0.1.1。ADR-031 §3）。
7. **版**: minor を上げる（v0.3.0）。

## 外から見える変化（mcptool の詳細設計 §5.1 から）

- 値の JSON が 1 行になる（字下げをやめる）。値は同じ。
- `<`・`>`・`&` が逃がされずに届く。たとえばバナーや HTML の `&` が `\u0026` ではなく `&` で届く。
- 引数の誤りのコードが `invalid_argument` から `invalid_arguments` になり、`details.argument` に名前が入る。未知の名前と型の誤りの文言は、`arguments: json: unknown field "…"` から `unknown argument "…"`・`argument "…" must be …` になる。
- 必須の引数が無いときのコードが `missing_argument` になる。空の文字列や `0` は、いまと同じく引数の誤り（`invalid_arguments`）である。
- 誤りが重なった呼び出しで、最初に返す誤りが変わりうる（未知 → 必須 → 型の順）。
- 上限の測り方が送る形と同じになるので、これまでより多く収まる。字下げと逃がしの分だけ、間引かれる行・切り詰められるバナーが減り、天井で返せなかった結果が返ることがある。
- 説明書（`usage.md`）の回復の表は、`invalid_argument` の行を `invalid_arguments` と `missing_argument` の 2 行にする。

これらの変化は 1 つのコミットにまとめる。どれも殻を mcptool に替えたことから生じ、ほかと切り離しては得られない。エンジンに `Argument` を足すのは、外から見えないので先に別のコミットにする。

## 見つけた不具合（移行で閉じる）

- スキーマが閉じていることを確かめる試験が無かった（方針 §4）。mcptool の登録が確かめる。
- `argNames` は、json の名前を持たない欄を大文字小文字を問わず受け入れていた（潜在。いまの引数の型はどれも名前を持つ）。mcptool は名前の無い欄を登録で断る。

## Consequences

- `internal/mcp` には、ツール・スキーマ・コードの一覧・応答の上限だけが残る。
- 作法の不具合は mcptool の 1 回の修正で直り、下限を上げれば届く。

## Alternatives considered

| 案 | 採らない理由 |
|---|---|
| エンジンの `invalid_argument` を MCP でもそのまま返す | 方針 §2.2（利用者の判断、2026-11-28）に反する。呼び出す側が引数の誤りを 1 つのコードで扱えない |
| エンジンのコードを `invalid_arguments` に改める | CLI の `--json` と標準エラーの表示が変わる。移行は MCP の作法の話で、CLI を巻き込まない |
| 天井を mcptool が書いた後で測る | mcptool は結果の大きさを返さず、応答の上限は持たない（ADR-031 §1）。ハンドラが自分で書いて測り、`Text` で返せば、測ったものと送るものが一致する |

## References

- 組織 ADR-031、ADR-030、ADR-021 §4
- nlink-jp/mcptool v0.1.3: `docs/ja/migration.ja.md`、`docs/ja/design.ja.md` §5.1
- ADR-0001
- issue nlink-jp/shodan-lookup#2
