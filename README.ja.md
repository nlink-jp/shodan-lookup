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
- **クレジットはツール側で守ります。** クエリクレジットを使うのは `search`
  だけです（条件つき、または 2 ページ目以降で 1 ページ 1 クレジット。実測）。
  どの検索も 1 とみなして、設定した下限を割る検索は送りません。予測と違う
  消費が起きたら、それ以降の検索を止めます。ホスト照会・履歴・件数集計・
  残量照会はクレジットを消費しません（実測）。

第三者の索引を読むだけなので、**調査対象のホストにはパケットが届きません**。
ただし照会はすべて利用者の Shodan アカウントに帰属し、どの IP を・どの検索語で
調べたかを Shodan は知ります。公開されていない IP アドレス（プライベート・
ループバック・リンクローカル・文書用の帯、およびそれらを埋め込んだ IPv6）は、
引数やクエリのどこに書かれていても、送る前に拒否します。名前
（`hostname:intranet.example` など）は綴りからは判定できないので、そのまま送ります。

## 状況

[RFP](docs/ja/shodan-lookup-rfp.ja.md) の Phase 1・2 に履歴を加えて実装済みです:
`host`・`service`・`count`・`history`・`tokens`・`search`・`quota` と、MCP
ツール `lookup_host`・`get_service`・`count_services`・`get_history`・
`parse_query`・`search_services`・`get_quota`。未リリースです。

## 必要なもの

- Shodan の API キー（Membership 以上）。Membership のキーで実測した範囲では、
  ホスト照会と件数集計はクレジットを消費しません。検索に使えるクエリクレジットは
  Membership で月 100 です。
- `api.shodan.io` へのネットワーク到達。

## インストール

未リリースです。ソースからビルドします:

```bash
make build        # → dist/shodan-lookup
make test         # オフライン
make e2e          # 利用者のキーで実機の Shodan に対して実行。クレジットは使わず、動いたら失敗する
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
shodan-lookup history <IP>             時間を通じて何を晒していたか（ポートごとに、各変化がいつ見えたか）
shodan-lookup tokens <QUERY>           Shodan がクエリをどう読むかと、検索の消費（無料）
shodan-lookup search <QUERY>           一致するサービスを 1 ページ — クエリクレジットを消費する
shodan-lookup quota                    プランと残りのクエリクレジット（常に最新）
shodan-lookup cache status|clear       結果キャッシュの確認・削除
shodan-lookup mcp                      ローカル MCP サーバーとして起動（stdio）
shodan-lookup version                  版数を表示
```

Shodan を読むコマンドはすべて `--json`（完全な JSON）を、`quota` 以外は
`--refresh`（キャッシュを使わず取り直す）を受け付けます。

```bash
shodan-lookup host 1.2.3.4                                # 何を晒しているか
shodan-lookup host 1.2.3.4 --port 443 --json              # 1 ポートだけ、完全な JSON
shodan-lookup host 1.2.3.4 --raw                          # Shodan の文書そのもの
shodan-lookup service 1.2.3.4 443 --section ssl_cert      # 証明書の全体
shodan-lookup service 1.2.3.4 53 --transport udp --section banner
shodan-lookup count 'port:3389 country:JP' --facet org:5 --facet ip:20
shodan-lookup history 1.2.3.4                             # ポート・製品・タイトル・証明書がいつ変わったか
shodan-lookup history 1.2.3.4 --port 443 --limit 20       # そのポートの観測を新しい順に
shodan-lookup tokens 'product:nginx country:JP'           # 無料: 検索すると 1 クレジットかかるか
shodan-lookup search 'product:nginx country:JP' --facet org:5   # 1 クレジット。消費を stderr に出す
shodan-lookup quota
```

答えの読み方:

- **Shodan の索引に無い**（`not_indexed`）は、Shodan がその IP を観測して
  いないという意味です。件数 0 で裏を取ってから答えます。Shodan の 404 だけ
  では判断しません（Shodan は、持っている記録を返せなかったときにも同じ
  404 を返すためです）。何も開いていないことの証拠ではありません。
- **そのポートのバナーが無い**（`not_observed`）は、ポートが閉じている
  ことの証拠ではありません。
- **推定 CVE** はバナーの版から推定したものです。`verified: false` は推定で、
  一覧が空でも「脆弱でない」ではありません。
- **件数の単位はホストではなくサービス（バナー）**です。一致するサービスを
  2 つ持つ IP は 2 と数えます。内訳は上位の値だけです。
- **絞り込み条件と内訳の名前は、Shodan 自身の一覧と照合してから送ります**。
  Shodan は知らない条件を文字列として扱って 0 件にし、知らない内訳は黙って
  捨てるからです。`vuln` と `tag` は Membership では拒否します。制限がエラーでは
  なく、不自然に少ない件数として返ってくるためです。
- **履歴は Shodan が返す最新の 1,000 バナー**です。上限に達していれば、
  それより前は読めません。ポートの最初の観測は、その窓の中での最初であって、
  開いた時点ではありません。騒がしい 1 つのポートが窓を埋めることがあり、
  答えはそのポートを名指しします。履歴の 404 もホスト照会と同じく裏を取ります
  （Shodan は、サービスを持つ大きなホストの履歴を返さないことがあります）。
- **`search` はクエリクレジットを消費します**。条件を使うか 2 ページ目以降なら
  1 ページ 1 クレジット、それ以外は 0 です（実測。1 回で 1 を超えません）。
  送る前に残量を読み、どの検索も 1 とみなして `[search] credit_floor`（既定 20）を
  割るなら送らずに拒否します（終了コード 2、`credit_floor`）。送った後に残量を
  読み直し、消費を stderr に出します。予測と違う消費が起きたら、そのプロセスでは
  検索を止めます（`credit_mismatch`）。ページは 24 時間キャッシュするので、同じ
  検索は消費しません。`--refresh` は再び消費します。「何件・どれが多いか」は
  多くの場合、無料の `count` で答えられます。
- **時刻は UTC** です。証明書の `expired` は、照会した時点で計算します。
- **ホスト照会は API キーを検査しません**（実測）。誤ったキーでもホストの記録は
  返ります。キーの誤りは `quota` と `count` で分かります。

終了コード: 0 — すべての照会に答えた（「Shodan の索引に無い」「そのポートの
バナーが無い」「件数 0」も答えです）。1 — 上流に問い合わせられなかった、
または一部しか答えられなかった。2 — 入力の誤り、内部アドレス、設定の誤り、
API キーが無いか拒否された、プランで制限された条件（`plan_restricted`）、
クレジットの守りが拒否した検索（`credit_floor`・`credit_mismatch`）。

## MCP サーバー

```json
{
  "mcpServers": {
    "shodan-lookup": { "command": "/path/to/shodan-lookup", "args": ["mcp"] }
  }
}
```

ツール: `lookup_host`・`get_service`・`count_services`・`get_history`・
`parse_query`・`search_services`（クレジットを使う唯一のツール）・`get_quota`・
`cache_status`・`get_usage`。最初に `get_usage` を呼んでください。全体の
リファレンスと、エラーからの回復手順の表を返します。`lookup_host` は応答の
予算内で答えます。既定を超えたサービス・バナー・CVE は `omitted` に件数として
出し、`get_service` で各部分の全量をページ送りで読めます。

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
