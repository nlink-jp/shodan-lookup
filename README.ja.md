# shodan-lookup

IP アドレスがインターネットから見て何を晒しているか — 開いているポート、
そこで動く製品と版、TLS 証明書、Shodan がバナーから推定した脆弱性、それぞれを
いつ観測したか — を返す CLI 兼ローカル MCP サーバーです。

**shodan-lookup は Shodan®, LLC とは無関係であり、承認も受けていません。**
利用者自身の API キーで [Shodan](https://www.shodan.io) REST API を読みます。

兄弟の lookup ツールのうち、`asn-lookup` と `whois-lookup` は IP の持ち主を、
`abuse-lookup`・`tor-exit-lookup`・`icloud-relay-lookup` はその IP がどう
使われてきたかを答えます。このツールは何を晒しているかを答えます。推定 CVE の
詳細は `cve-lookup` に引き継ぎます。

- **読み取り専用です。** Shodan のオンデマンドスキャン（Shodan に対象を走査
  させる機能）と、書き込みを伴う機能（アラート・通知先・アカウント設定）は
  恒久的に対象外です。
- **否定的な答えを作りません。** Shodan が観測していない IP は「Shodan の索引に
  無い」と返し、「何も開いていない」とは返しません。推定 CVE の一覧が空でも
  「脆弱性が無い」ではありません。
- **クレジットはツール側で守ります。** クエリクレジットを使うのは検索だけで、
  設定した下限を割る呼び出しはしません。

第三者の索引を読むだけなので、**調査対象のホストにはパケットが届きません**。
ただし照会はすべて利用者の Shodan アカウントに帰属し、どの IP を・どの検索語で
調べたかを Shodan は知ります。内部アドレスは送る前に拒否します。

## 状況

これはプロジェクトの骨組みです。照会コマンド `count`・`host`・`quota`・
`service` はこのビルドではプレースホルダで、「not implemented yet」と
表示して終了コード 2 で止まります。

今動くのは `cache status`・`cache clear`・`mcp`・`version` です。

MCP 側では `cache_status` と `get_usage` が応答します。
照会ツールはエンジンと共に入ります（[RFP](docs/ja/shodan-lookup-rfp.ja.md) の Phase 1）。

## 必要なもの

- Shodan の API キー（Membership 以上）。Membership のキーで実測した範囲では、
  ホスト照会と件数集計はクレジットを消費しません。検索に使えるクエリクレジットは
  Membership で月 100 です。
- `api.shodan.io` へのネットワーク到達。

## インストール

未リリースです。ソースからビルドします:

```bash
make build        # → dist/shodan-lookup
```

## 設定

[config.example.toml](config.example.toml) を
`~/.config/shodan-lookup/config.toml` に複製し（権限は 0600）、`[api]` の下に
キーを書きます:

```toml
[api]
key = "YOUR-SHODAN-API-KEY"
```

セクションの外に 1 行で書いたキー（`api_key = "..."`。ほかの Shodan 向け
ツールが使う形）は、`[api]` へ移すよう案内して拒否します。ファイルは
`$XDG_CONFIG_HOME/shodan-lookup/`、`~/.config/shodan-lookup/`、（macOS では）
`~/Library/Application Support/shodan-lookup/` の順に探します。
`shodan-lookup cache status` は、どのファイルを読んだかと、キーが設定されて
いるかどうかを表示します。キーそのものは表示しません。知らないセクションや
キー、存在しない `--config` のパス、`""` を入れたキー、範囲外の数値はいずれも
エラーです。キーはすべてのリクエストのクエリ文字列に載るので、`base_url` は
https に限ります。

環境変数はファイルより優先します: `SHODAN_LOOKUP_API_KEY`（または
`SHODAN_API_KEY`）、`SHODAN_LOOKUP_BASE_URL`、`SHODAN_LOOKUP_CACHE_DIR`、
`SHODAN_LOOKUP_DEFAULT_SERVICES`、`SHODAN_LOOKUP_DEFAULT_VULNS`、
`SHODAN_LOOKUP_BANNER_BYTES`、`SHODAN_LOOKUP_CREDIT_FLOOR`、
`SHODAN_LOOKUP_HOST_TTL_HOURS`、`SHODAN_LOOKUP_COUNT_TTL_HOURS`、
`SHODAN_LOOKUP_SEARCH_TTL_HOURS`、`SHODAN_LOOKUP_TIMEOUT_SECONDS`、
`SHODAN_LOOKUP_MIN_INTERVAL_MS`。各設定の説明は例のファイルにあります。
TTL を 0 にすると、その種類の答えはキャッシュしません。

## コマンド

```
shodan-lookup host <IP>...             ホストの開放ポート・製品・証明書・推定 CVE
shodan-lookup service <IP> <PORT>      ホストの 1 サービスを区画ごとに全量まで
shodan-lookup count <QUERY>            Shodan のクエリに一致するサービスの数と内訳
shodan-lookup quota                    プランと残りのクエリクレジット（常に最新）
shodan-lookup cache status|clear       結果キャッシュの確認・削除
shodan-lookup mcp                      ローカル MCP サーバーとして起動（stdio）
shodan-lookup version                  版数を表示
```

件数の単位は**ホストではなくサービス（バナー）**です。一致するサービスを
2 つ持つ IP は 2 と数えます。

終了コード: 0 — すべての照会に答えた（「Shodan の索引に無い」も件数 0 も答え
です）。1 — 上流に問い合わせられなかった、または一部しか答えられなかった。
2 — 使い方・入力・設定の誤り、または未実装のコマンド。

## MCP サーバー

```json
{
  "mcpServers": {
    "shodan-lookup": { "command": "/path/to/shodan-lookup", "args": ["mcp"] }
  }
}
```

最初に `get_usage` を呼んでください。全体のリファレンスと、エラーからの
回復手順の表を返します。

## データソースと利用条件

結果は Shodan のデータで、Shodan の
[利用規約](https://static.shodan.io/legal/terms.html)の下で読みます。規約
§6.7 は、Shodan の情報を自分の資料（たとえばインシデントの報告書）に含める
ときに Shodan に帰属させ、Shodan の所有権と著作権を明示することを求めて
います。このツールがすべての結果に出所を付けるのはそのためです。キャッシュした
応答は手元の機械から出ません。

規約についてのプロジェクトの読みは RFP（§7）に記録しています。これは法的な
助言ではありません。利用者の Shodan プランでの使い方が規約に合うかどうかは、
利用者自身が確かめてください。

## ドキュメント

- [RFP（設計の正典）](docs/ja/shodan-lookup-rfp.ja.md) — 英訳:
  [docs/en/shodan-lookup-rfp.md](docs/en/shodan-lookup-rfp.md)

## ライセンス

MIT — [LICENSE](LICENSE) を参照。Shodan® は Shodan, LLC の商標です。
